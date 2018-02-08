#include "ohash.h"
#include <float.h> // FLT_EPSILON, DBL_EPSILON, LDBL_EPSILON
#include <inttypes.h> // int*_t, uint*_t
#include <math.h> // fabs(), fabsf(), fabsl()
#include <stdio.h> // snprintf()
#include <stdlib.h> // size_t, malloc(), free()
#include <string.h> // strcmp()
#include <sodium.h> // crypto_shorthash_BYTES, crypto_shorthash(), randombytes_buf(), sodium_init()

// used to silence compiler warnings about intentionally unused function arguments
#define UNUSED(x) (void)(x)

// clang supports more flexible static variable declarations
#if __clang__
#define FLEX_STATIC static
#else
#define FLEX_STATIC
#endif

// multiplies a * b, returning max if result would overflow it
// implementation targeted for a and b between 0 and max
#define CAPPED_MULTIPLY(max, a, b) ( (a == 0 || b == 0) ? 0 : ((max) / (a) >= (b) ? (a) * (b) : (max)) )

// adds a + b, returning max if result would overflow it
// implementation targeted for a and b between 0 and max
#define CAPPED_ADD(max, a, b) ( (max) - (a) >= (b) ? (a) + (b) : (max) )

/**
 * Singly linked list node, for memory allocations internal to hash instance.
 */
typedef struct OHashAllocation {
    void *allocation;
    void *next;
} OHashAllocation;

/**
 * Doubly linked list node, for pair.
 */
typedef struct OHashPair {
    void *key;
    void *value;
    struct OHashPair *prev;
    struct OHashPair *next;
} OHashPair;

/**
 * Singly linked list node, for referencing OHashPair instance.
 */
typedef struct OHashPairRef {
    OHashPair *pair;
    struct OHashPairRef *next;
} OHashPairRef;

/**
 * Primary struct, representing a single hash instance.
 */
struct OHash {
    /**
     * Number of pairs allocated, whether or not currently in use.
     */
    size_t num_pairs_allocated;

    /**
     * Number of pairs currently stored in hash.
     */
    size_t num_pairs_used;

    /**
     * Head of doubly linked list of pairs currently in use.
     */
    OHashPair *pairs_used_head;

    /**
     * Tail of pairs_used_head list; used to append pairs in insertion order.
     */
    OHashPair *pairs_used_tail;

    /**
     * Head of singly linked list of pairs allocated but not currently in use.
     *
     * While struct is doubly linked, prev is always NULL when pairs are in this list.
     */
    OHashPair *pairs_unused_head;

    /**
     * Number of pair refs allocated, whether or not currently in use.
     */
    size_t num_pair_refs_allocated;

    /**
     * Head of singly linked list of pair refs allocated but not currently in use.
     */
    OHashPairRef *pair_refs_unused_head;

    /**
     * Singly linked list of pair refs tracking pairs currently in zombie state.
     *
     * Each zombie is a pair ref to a pair still present in pairs_used_head list.
     * Zombies are only created when pairs are deleted while any iterators
     * exist, allowing all operations to be used safely during iteration.
     */
    OHashPairRef *pair_refs_zombie_head;

    /**
     * Number of allocated hash table buckets, whether or not occupied.
     */
    size_t num_buckets_allocated;

    /**
     * Number of hash table buckets currently occupied by one or more pair refs.
     */
    size_t num_buckets_occupied;

    /**
     * Allocated hash table buckets.
     *
     * Each bucket is head of singly linked list of pair refs, operating as
     * separate chaining mechanism for handling hash key bucket collisions.
     */
    OHashPairRef **buckets;

    /**
     * Options used to configure hash behavior, as passed to ohash_new().
     */
    OHashOptions options;

    /**
     * Doubly linked list of allocated iterators.
     */
    OHashIter *iterators;

    /**
     * Long-term memory allocations internal to hash, freed upon ohash_free().
     */
    OHashAllocation *allocations;
};

/**
 * Doubly linked list node, for iterators.
 */
struct OHashIter {
    int first;       ///< whether we are at start of iteration (0/1)
    OHash *hash;     ///< hash instance the iterator instance belongs to
    OHashPair *pair; ///< current pair iterator is pointing at
    OHashIter *prev; ///< prev iterator
    OHashIter *next; ///< next iterator
};

static void *ohash_alloc_new(OHash *hash, const size_t size);
static void ohash_alloc_free_all(OHash *hash);
static _Bool ohash_prepare_options(OHashOptions *options);
inline static size_t ohash_key_bucket(const OHash *hash, const void *key);
static _Bool ohash_allocate_buckets(OHash *hash, size_t num_new_buckets);
static void ohash_release_pair(OHash *hash, OHashPair *pair);
static OHashPairRef *ohash_obtain_pair_ref(OHash *hash);
static void ohash_release_pair_ref(OHash *hash, OHashPairRef *pair_ref);
static void ohash_release_used_pair_ref(OHash *hash, OHashPairRef *pair_ref);
static void ohash_release_used_pair_ref_as_zombie(OHash *hash, OHashPairRef *pair_ref);

_Bool ohash_init(OHash *hash, OHashOptions options)
{
    if (!hash || !ohash_prepare_options(&options))
        return 0;

    hash->options = options;

    hash->num_pairs_allocated = 0;
    hash->num_pairs_used = 0;
    hash->num_pair_refs_allocated = 0;
    hash->num_buckets_allocated = 0;
    hash->num_buckets_occupied = 0;

    hash->pairs_used_head = NULL;
    hash->pairs_used_tail = NULL;
    hash->pairs_unused_head = NULL;
    hash->pair_refs_unused_head = NULL;
    hash->pair_refs_zombie_head = NULL;
    hash->buckets = NULL;
    hash->iterators = NULL;
    hash->allocations = NULL;

    if (!ohash_allocate_buckets(hash, options.num_items))
        return 0;

    return 1;
}

OHash *ohash_new(OHashOptions options)
{
    OHash *hash = malloc(sizeof *hash);

    if (hash && !ohash_init(hash, options)) {
        free(hash);
        hash = NULL;
    }

    return hash;
}

size_t ohash_count(const OHash *hash)
{
    return hash->num_pairs_used;
}

void *ohash_get(const OHash *hash, const void *key)
{
    // search pair refs of key's bucket for matching key
    const OHashPairRef *pair_ref = hash->buckets[ohash_key_bucket(hash, key)];

    while (pair_ref && !hash->options.key_compare_fn(pair_ref->pair->key, key))
        pair_ref = pair_ref->next;

    return pair_ref ? pair_ref->pair->value : NULL;
}

_Bool ohash_exists(const OHash *hash, const void *key)
{
    return ohash_get(hash, key) ? 1 : 0;
}

_Bool ohash_insert(OHash *hash, void *key, void *value)
{
    // search pair refs of key's bucket for matching (duplicate) key
    size_t bucket = ohash_key_bucket(hash, key);
    OHashPairRef *pair_ref = hash->buckets[bucket];

    while (pair_ref && !hash->options.key_compare_fn(pair_ref->pair->key, key))
        pair_ref = pair_ref->next;

    // duplicate key - replace key/value
    if (pair_ref) {
        if (hash->options.key_free_fn && pair_ref->pair->key != key)
            hash->options.key_free_fn(pair_ref->pair->key);

        if (pair_ref->pair->value && hash->options.value_free_fn && pair_ref->pair->value != value)
            hash->options.value_free_fn(pair_ref->pair->value);

        pair_ref->pair->key = key;
        pair_ref->pair->value = value;

        return 1;
    }

    // new insert

    // bucket capacity exceeds configuration
    if ((double)hash->num_buckets_occupied / (double)hash->num_buckets_allocated * 100 >=
        hash->options.resize_capacity_percent
    ) {
        // double number of buckets (and rebuild the contents), then get key's new hash
        if (ohash_allocate_buckets(hash, CAPPED_MULTIPLY(SIZE_MAX, hash->num_buckets_allocated, 2)))
            bucket = ohash_key_bucket(hash, key);
    }

    // obtain a pair ref with an attached pair
    if (!(pair_ref = ohash_obtain_pair_ref(hash)))
        return 0;

    // append as tail of used pairs, maintaining insertion order
    pair_ref->pair->key = key;
    pair_ref->pair->value = value;
    pair_ref->pair->prev = hash->pairs_used_tail;
    pair_ref->pair->next = NULL;

    if (hash->pairs_used_tail)
        hash->pairs_used_tail->next = pair_ref->pair;

    hash->pairs_used_tail = pair_ref->pair;

    if (!hash->pairs_used_head)
        hash->pairs_used_head = pair_ref->pair;

    // increment counts, prepend pair ref to bucket
    ++hash->num_pairs_used;

    if (!hash->buckets[bucket])
        ++hash->num_buckets_occupied;

    pair_ref->next = hash->buckets[bucket];
    hash->buckets[bucket] = pair_ref;

    return 1;
}

_Bool ohash_delete(OHash *hash, void *key)
{
    // search pair refs of key's bucket for matching key
    const size_t bucket = ohash_key_bucket(hash, key);
    OHashPairRef *pair_ref = hash->buckets[bucket], *prev_pair_ref = NULL;

    while (pair_ref && !hash->options.key_compare_fn(pair_ref->pair->key, key)) {
        prev_pair_ref = pair_ref;
        pair_ref = pair_ref->next;
    }

    // key not found
    if (!pair_ref)
        return 0;

    if (hash->options.key_free_fn)
        hash->options.key_free_fn(pair_ref->pair->key);

    if (pair_ref->pair->value && hash->options.value_free_fn)
        hash->options.value_free_fn(pair_ref->pair->value);

    --hash->num_pairs_used;

    // remove pair ref from bucket
    if (prev_pair_ref)
        prev_pair_ref->next = pair_ref->next;
    else if (!(hash->buckets[bucket] = pair_ref->next))
        --hash->num_buckets_occupied;

    // iterators are in play - mark pair ref as zombie within used list;
    // otherwise, zombie not required - release pair ref to unused list
    if (hash->iterators)
        ohash_release_used_pair_ref_as_zombie(hash, pair_ref);
    else
        ohash_release_used_pair_ref(hash, pair_ref);

    return 1;
}

_Bool ohash_delete_all(OHash *hash)
{
    _Bool success = 1;

    for (OHashPair *pair = hash->pairs_used_head, *next_pair; pair; pair = next_pair) {
        next_pair = pair->next;

        // skip zombies
        if (pair->key && !ohash_delete(hash, pair->key))
            success = 0;
    }

    return success;
}

void ohash_destroy(OHash *hash)
{
    // free iterators - desirable side effect of converting zombies to unused
    for (OHashIter *iterator = hash->iterators, *next; iterator; iterator = next) {
        next = iterator->next;
        ohash_iter_free(iterator);
    }

    // delete all pairs
    ohash_delete_all(hash);

    // free all internal allocations
    ohash_alloc_free_all(hash);

    // free hash buckets
    free(hash->buckets);
}

void ohash_free(OHash *hash)
{
    if (hash) {
        // free internals
        ohash_destroy(hash);

        // free hash instance itself
        free(hash);
        hash = NULL;
    }
}

void ohash_iter_init(OHashIter *iterator, OHash *hash)
{
    iterator->first = 1;
    iterator->hash = hash;
    iterator->pair = NULL;
    iterator->prev = NULL;

    // prepend to iterators list
    if (hash->iterators)
        hash->iterators->prev = iterator;

    iterator->next = hash->iterators;
    hash->iterators = iterator;
}

OHashIter *ohash_iter_new(OHash *hash)
{
    OHashIter *iterator = malloc(sizeof *iterator);

    if (iterator)
        ohash_iter_init(iterator, hash);

    return iterator;
}

void ohash_iter_rewind(OHashIter *iterator)
{
    iterator->first = 1;
    iterator->pair = NULL;
}

_Bool ohash_iter_each(OHashIter *iterator)
{
    // first iteration uses first non-zombie from used head
    if (iterator->first) {
        iterator->first = 0;

        for (
            iterator->pair = iterator->hash->pairs_used_head;
            iterator->pair && !iterator->pair->key;
            iterator->pair = iterator->pair->next
        );
    }
    // advance to the next non-zombie pair
    else if (iterator->pair)
        do {
            iterator->pair = iterator->pair->next;
        } while (iterator->pair && !iterator->pair->key);

    return iterator->pair ? 1 : 0;
}

void *ohash_iter_key(const OHashIter *iterator)
{
    return iterator->pair ? iterator->pair->key : NULL;
}

void *ohash_iter_value(const OHashIter *iterator)
{
    return iterator->pair ? iterator->pair->value : NULL;
}

void ohash_iter_destroy(OHashIter *iterator)
{
    // remove iterator from linked list
    if (iterator->prev)
        iterator->prev->next = iterator->next;
    else
        iterator->hash->iterators = iterator->next;

    if (iterator->next)
        iterator->next->prev = iterator->prev;

    // upon freeing last iterator, release used zombies to unused
    if (!iterator->hash->iterators) {
        OHashPairRef *pair_ref;
        while ((pair_ref = iterator->hash->pair_refs_zombie_head)) {
            iterator->hash->pair_refs_zombie_head = pair_ref->next;
            ohash_release_used_pair_ref(iterator->hash, pair_ref);
        }
    }
}

void ohash_iter_free(OHashIter *iterator)
{
    if (iterator) {
        ohash_iter_destroy(iterator);
        free(iterator);
        iterator = NULL;
    }
}

/**
 * Allocates space, internal to given hash instance.
 *
 * Allocations made through this function are automatically
 * freed when hash instance itself is freed with ohash_free().
 *
 * @param[in] hash An existing hash instance.
 * @param[in] size Bytes to allocate.
 * @retval void* Pointer to allocated memory, if successful.
 * @retval NULL If memory could not be allocated.
 */
static void *ohash_alloc_new(OHash *hash, const size_t size)
{
    OHashAllocation *alloc = malloc(sizeof *alloc);

    if (!alloc)
        return NULL;

    if (!(alloc->allocation = malloc(size))) {
        free(alloc);
        return NULL;
    }

    // prepend to allocations list
    alloc->next = hash->allocations;
    hash->allocations = alloc;

    return alloc->allocation;
}

/**
 * Frees all internal allocations for given hash instance.
 *
 * @param[in] hash An existing hash instance.
 */
static void ohash_alloc_free_all(OHash *hash)
{
    for (OHashAllocation *alloc = hash->allocations, *next_alloc; alloc; alloc = next_alloc) {
        next_alloc = alloc->next;
        free(alloc->allocation);
        free(alloc);
    }

    hash->allocations = NULL;
}

/**
 * Determines which bucket given key belongs in within given hash instance.
 *
 * @param[in] hash An existing hash instance.
 * @param[in] key A key, as a null pointer which configured hash function can handle.
 * @return Number between 0 and hash->num_buckets_allocated, as calculated by configured hash function.
 */
inline static size_t ohash_key_bucket(const OHash *hash, const void *key)
{
    return hash->options.key_hash_fn(hash->options, key) % hash->num_buckets_allocated;
}

/**
 * Prepares options for new hash instance.
 *
 * Validates passed options, and assigns reasonable defaults where possible.
 *
 * @param[in,out] options Desired options.
 * @retval 1 If options are valid and usable.
 * @retval 0 If any option is invalid - cannot continue with hash initialization.
 */
static _Bool ohash_prepare_options(OHashOptions *options)
{
    // safe to call multiple times in one process run
    if (sodium_init() == -1)
        return 0;

    if (!options->key_hash_fn || !options->key_compare_fn)
        return 0;

    if (!options->resize_capacity_percent)
        options->resize_capacity_percent = 75;
    else if (options->resize_capacity_percent < 0 || options->resize_capacity_percent > 100)
        return 0;

    int empty_secret = 1;
    for (unsigned i = 0; i < crypto_shorthash_KEYBYTES; ++i) {
        if (options->hash_string_secret[i]) {
            empty_secret = 0;
            break;
        }
    }

    if (empty_secret)
        randombytes_buf(options->hash_string_secret, crypto_shorthash_KEYBYTES);

    // round up to next even number, capped at SIZE_MAX, default of 2
    if (!(options->num_items = (CAPPED_ADD(SIZE_MAX, options->num_items, 1) & ~1)))
        options->num_items = 2;

    return 1;
}

/**
 * Allocates additional buckets for storage of pairs in hash table.
 *
 * @param[in] hash An existing hash instance.
 * @param[in] Number of additional buckets to allocate.
 * @retval 0 If additional buckets could not be allocated.
 * @retval 1 If additional buckets were successfully allocated.
 */
static _Bool ohash_allocate_buckets(OHash *hash, size_t num_new_buckets)
{
    // calculations for buckets, in units and allocated bytes
    FLEX_STATIC const size_t UNIT_ALLOCATION_BYTES = sizeof *hash->buckets;
    FLEX_STATIC const size_t MAX_ALLOCATION_BYTES = (SIZE_MAX & ~(UNIT_ALLOCATION_BYTES - 1));
    FLEX_STATIC const size_t MAX_ALLOCATION_UNITS = MAX_ALLOCATION_BYTES / UNIT_ALLOCATION_BYTES;

    const size_t num_old_buckets = hash->num_buckets_allocated;

    if (num_old_buckets >= MAX_ALLOCATION_UNITS)
        return 0;

    const size_t bytes_new_buckets = CAPPED_MULTIPLY(MAX_ALLOCATION_BYTES, UNIT_ALLOCATION_BYTES, num_new_buckets);

    if ((num_new_buckets = bytes_new_buckets / UNIT_ALLOCATION_BYTES) <= num_old_buckets)
        return 0;

    // allocate/initialize new buckets
    OHashPairRef **new_buckets = malloc(bytes_new_buckets);

    if (!new_buckets)
        return 0;

    for (size_t i = 0; i < num_new_buckets; ++i)
        new_buckets[i] = NULL;

    hash->num_buckets_allocated = num_new_buckets;
    hash->num_buckets_occupied = 0;

    // migrate pair refs from old buckets to new
    size_t old_bucket, new_bucket;
    OHashPairRef *pair_ref, *next_pair_ref;

    // iterate each used pair; when nested loop has already migrated a pair's bucket in
    // advance, its (superfluous) nested loop will find an empty bucket and do no extra work
    for (OHashPair *pair = hash->pairs_used_head; pair; pair = pair->next) {
        old_bucket = hash->options.key_hash_fn(hash->options, pair->key) % num_old_buckets;

        // instead of searching for current pair only, migrate all bucket's pairs in advance
        for (pair_ref = hash->buckets[old_bucket]; pair_ref; pair_ref = next_pair_ref) {
            next_pair_ref = pair_ref->next;

            // first pair in new bucket
            if (!new_buckets[new_bucket = ohash_key_bucket(hash, pair_ref->pair->key)])
                ++hash->num_buckets_occupied;

            // prepend pair as head of new bucket
            pair_ref->next = new_buckets[new_bucket];
            new_buckets[new_bucket] = pair_ref;
        }

        // bucket's pairs have all been migrated
        hash->buckets[old_bucket] = NULL;
    }

    free(hash->buckets);
    hash->buckets = new_buckets;

    return 1;
}

/**
 * Obtains a pair ref with an attached pair.
 *
 * A previously allocated - but currently unused - pair ref and pair will
 * be used if possible; otherwise additional objects are allocated.
 *
 * @param[in] hash An existing hash instance.
 * @retval OHashPairRef If both a pair ref (and attached pair) were successfully obtained.
 * @retval NULL If a pair ref (or attached pair) could not be obtained.
 */
static OHashPairRef *ohash_obtain_pair_ref(OHash *hash)
{
    // allocate more pairs
    if (!hash->pairs_unused_head) {
        // calculations for pairs, in units and allocated bytes
        FLEX_STATIC const size_t UNIT_ALLOCATION_BYTES = sizeof (OHashPair);
        FLEX_STATIC const size_t MAX_ALLOCATION_BYTES = (SIZE_MAX & ~(UNIT_ALLOCATION_BYTES - 1));
        FLEX_STATIC const size_t MAX_ALLOCATION_UNITS = MAX_ALLOCATION_BYTES / UNIT_ALLOCATION_BYTES;

        // allocate to match recent increase in bucket count; otherwise double existing allocation
        size_t num_new_pairs = CAPPED_ADD(
            MAX_ALLOCATION_UNITS,
            hash->num_pairs_allocated,
            hash->num_pairs_allocated < hash->num_buckets_allocated ?
                hash->num_buckets_allocated - hash->num_pairs_allocated :
                hash->num_pairs_allocated
        ) - hash->num_pairs_allocated;

        const size_t bytes_new_pairs = CAPPED_MULTIPLY(
            MAX_ALLOCATION_BYTES,
            UNIT_ALLOCATION_BYTES,
            num_new_pairs
        );

        if ((num_new_pairs = bytes_new_pairs / UNIT_ALLOCATION_BYTES) <= 0)
            return NULL;

        OHashPair *pairs = ohash_alloc_new(hash, bytes_new_pairs);

        if (!pairs)
            return NULL;

        hash->num_pairs_allocated += num_new_pairs;

        for (size_t i = 0; i < num_new_pairs; ++i)
            ohash_release_pair(hash, &pairs[i]);
    }

    // allocate more pair refs
    if (!hash->pair_refs_unused_head) {
        // calculations for pair refs, in units and allocated bytes
        FLEX_STATIC const size_t UNIT_ALLOCATION_BYTES = sizeof (OHashPairRef);
        FLEX_STATIC const size_t MAX_ALLOCATION_BYTES = (SIZE_MAX & ~(UNIT_ALLOCATION_BYTES - 1));
        FLEX_STATIC const size_t MAX_ALLOCATION_UNITS = MAX_ALLOCATION_BYTES / UNIT_ALLOCATION_BYTES;

        // allocate to match recent increase in bucket count; otherwise double existing allocation
        size_t num_new_pair_refs = CAPPED_ADD(
            MAX_ALLOCATION_UNITS,
            hash->num_pair_refs_allocated,
            hash->num_pair_refs_allocated < hash->num_buckets_allocated ?
                hash->num_buckets_allocated - hash->num_pair_refs_allocated :
                hash->num_pair_refs_allocated
        ) - hash->num_pair_refs_allocated;

        const size_t bytes_new_pair_refs = CAPPED_MULTIPLY(
            MAX_ALLOCATION_BYTES,
            UNIT_ALLOCATION_BYTES,
            num_new_pair_refs
        );

        if ((num_new_pair_refs = bytes_new_pair_refs / UNIT_ALLOCATION_BYTES) <= 0)
            return NULL;

        OHashPairRef *pair_refs = ohash_alloc_new(hash, bytes_new_pair_refs);

        if (!pair_refs)
            return NULL;

        hash->num_pair_refs_allocated += num_new_pair_refs;

        for (size_t i = 0; i < num_new_pair_refs; ++i)
            ohash_release_pair_ref(hash, &pair_refs[i]);
    }

    // pop a pair and pair ref from their respective unused lists
    OHashPair *pair = hash->pairs_unused_head;
    hash->pairs_unused_head = pair->next;

    OHashPairRef *pair_ref = hash->pair_refs_unused_head;
    hash->pair_refs_unused_head = pair_ref->next;

    pair_ref->pair = pair;

    return pair_ref;
}

static void ohash_release_pair(OHash *hash, OHashPair *pair)
{
    pair->key = NULL;
    pair->value = NULL;
    pair->prev = NULL; // pairs_unused_head is only accessed as a singly linked list
    pair->next = hash->pairs_unused_head;
    hash->pairs_unused_head = pair;
}

static void ohash_release_pair_ref(OHash *hash, OHashPairRef *pair_ref)
{
    pair_ref->pair = NULL;
    pair_ref->next = hash->pair_refs_unused_head;
    hash->pair_refs_unused_head = pair_ref;
}

/**
 * Release a used pair ref and its attached pair to the unused list.
 *
 * @param[in] hash An existing hash instance.
 * @param[in] pair_ref The used (possibly zombie) pair ref to release to unused list.
 */
static void ohash_release_used_pair_ref(OHash *hash, OHashPairRef *pair_ref)
{
    // remove pair from used linked list
    if (pair_ref->pair->prev)
        pair_ref->pair->prev->next = pair_ref->pair->next;

    if (pair_ref->pair->next)
        pair_ref->pair->next->prev = pair_ref->pair->prev;

    if (hash->pairs_used_head == pair_ref->pair)
        hash->pairs_used_head = pair_ref->pair->next;

    if (hash->pairs_used_tail == pair_ref->pair)
        hash->pairs_used_tail = pair_ref->pair->prev;

    // push pair and its pair ref to their respective unused lists
    ohash_release_pair(hash, pair_ref->pair);
    ohash_release_pair_ref(hash, pair_ref);
}

static void ohash_release_used_pair_ref_as_zombie(OHash *hash, OHashPairRef *pair_ref)
{
    pair_ref->pair->key = NULL;
    pair_ref->pair->value = NULL;

    pair_ref->next = hash->pair_refs_zombie_head;
    hash->pair_refs_zombie_head = pair_ref;
}

/* bundled key comparison functions */

_Bool ohash_compare_key_pointer(const void *a, const void *b)
{
    return a == b;
}

_Bool ohash_compare_key_string(const void *a, const void *b)
{
    return strcmp((char *)a, (char *)b) == 0;
}

_Bool ohash_compare_key_int(const void *a, const void *b)
{
    return *(int*)a == *(int*)b;
}

_Bool ohash_compare_key_intmax(const void *a, const void *b)
{
    return *(intmax_t*)a == *(intmax_t*)b;
}

_Bool ohash_compare_key_int8(const void *a, const void *b)
{
    return *(int8_t*)a == *(int8_t*)b;
}

_Bool ohash_compare_key_int16(const void *a, const void *b)
{
    return *(int16_t*)a == *(int16_t*)b;
}

_Bool ohash_compare_key_int32(const void *a, const void *b)
{
    return *(int32_t*)a == *(int32_t*)b;
}

_Bool ohash_compare_key_int64(const void *a, const void *b)
{
    return *(int64_t*)a == *(int64_t*)b;
}

_Bool ohash_compare_key_uint(const void *a, const void *b)
{
    return *(unsigned*)a == *(unsigned*)b;
}

_Bool ohash_compare_key_uintmax(const void *a, const void *b)
{
    return *(uintmax_t*)a == *(uintmax_t*)b;
}

_Bool ohash_compare_key_uint8(const void *a, const void *b)
{
    return *(uint8_t*)a == *(uint8_t*)b;
}

_Bool ohash_compare_key_uint16(const void *a, const void *b)
{
    return *(uint16_t*)a == *(uint16_t*)b;
}

_Bool ohash_compare_key_uint32(const void *a, const void *b)
{
    return *(uint32_t*)a == *(uint32_t*)b;
}

_Bool ohash_compare_key_uint64(const void *a, const void *b)
{
    return *(uint64_t*)a == *(uint64_t*)b;
}

_Bool ohash_compare_key_float(const void *a, const void *b)
{
    return fabsf(*(float*)a - *(float*)b) < FLT_EPSILON;
}

_Bool ohash_compare_key_double(const void *a, const void *b)
{
    return fabs(*(double*)a - *(double*)b) < DBL_EPSILON;
}

_Bool ohash_compare_key_long_double(const void *a, const void *b)
{
    return fabsl(*(long double*)a - *(long double*)b) < LDBL_EPSILON;
}

/* bundled key hashing functions */

uintmax_t ohash_key_pointer(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%p", key) + 1];
    snprintf(key_str, sizeof key_str, "%p", key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_string(const OHashOptions options, const void *key)
{ UNUSED(options);
    char *key_str = (char*)key;
    unsigned long long key_len = strlen(key_str);

    unsigned char key_hash[crypto_shorthash_BYTES];
    crypto_shorthash(key_hash, (const unsigned char*)key_str, key_len, options.hash_string_secret);

    // convert char[8] to uint64_t
    return (uint64_t)key_hash[0] | (uint64_t)key_hash[1] << 8 |
        (uint64_t)key_hash[2] << 16 | (uint64_t)key_hash[3] << 24 |
        (uint64_t)key_hash[4] << 32 | (uint64_t)key_hash[5] << 40 |
        (uint64_t)key_hash[6] << 48 | (uint64_t)key_hash[7] << 56;
}

uintmax_t ohash_key_int(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%d", *(int*)key) + 1];
    snprintf(key_str, sizeof key_str, "%d", *(int*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_intmax(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNdMAX, *(intmax_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNdMAX, *(intmax_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_int8(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNd8, *(int8_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNd8, *(int8_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_int16(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNd16, *(int16_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNd16, *(int16_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_int32(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNd32, *(int32_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNd32, *(int32_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_int64(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNd64, *(int64_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNd64, *(int64_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_uint(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%u", *(unsigned*)key) + 1];
    snprintf(key_str, sizeof key_str, "%u", *(unsigned*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_uintmax(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNuMAX, *(uintmax_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNuMAX, *(uintmax_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_uint8(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNu8, *(uint8_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNu8, *(uint8_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_uint16(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNu16, *(uint16_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNu16, *(uint16_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_uint32(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNu32, *(uint32_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNu32, *(uint32_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_uint64(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%" SCNu64, *(uint64_t*)key) + 1];
    snprintf(key_str, sizeof key_str, "%" SCNu64, *(uint64_t*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_float(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%f", *(float*)key) + 1];
    snprintf(key_str, sizeof key_str, "%f", *(float*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_double(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%f", *(double*)key) + 1];
    snprintf(key_str, sizeof key_str, "%f", *(double*)key);

    return ohash_key_string(options, key_str);
}

uintmax_t ohash_key_long_double(const OHashOptions options, const void *key)
{ UNUSED(options);
    char key_str[snprintf(NULL, 0, "%Lf", *(long double*)key) + 1];
    snprintf(key_str, sizeof key_str, "%Lf", *(long double*)key);

    return ohash_key_string(options, key_str);
}
