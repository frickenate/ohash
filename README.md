# OrderedHash - Insertion Ordered Hash Map Table For C

## Description / Features

C implementation of an ordered hash map table.

Features include:

- Items are maintained in insertion order, allowing iteration over stored items in a defined order.
- Built-in support for string and integer keys. Custom functions can be used to hash other types (structs, etc.).
- Built-in hash functions use [SipHash](https://131002.net/siphash/) to prevent hash collision attacks.
- Optionally make hash responsible for freeing memory for keys and values when they are deleted.

The most important detail to understand about this implementation: all
keys and values are passed around as `void *` pointers. `ohash_insert()`
will not accept integers for example, but rather pointers to integers. This
is most important when retrieving your keys and values back using any of
`ohash_get()`, `ohash_iter_key()` or `ohash_iter_value()`. You must always
cast the return values of these functions back to the data types you stored.

## Dependencies

* libsodium-dev (required) - provides [SipHash](https://131002.net/siphash/)
* cmake (optional) - to compile shared and static libs

## Installation / Build Options

### Option #1 - Compile shared and static libs

```bash
# build shared and static libs in build directory with cmake.
# make command creates liborderedhash.a and liborderedhash.so
git clone https://github.com/frickenate/C-OrderedHash &&
    cd C-OrderedHash && mkdir build && cd build &&
    cmake .. && make

# install system-wide, typically under /usr/local
sudo make install

# build your project against liborderedhash and libsodium
clang -O2 example.c -lorderedhash -lsodium -o example
```

### Option #2 - Compile your project against orderedhash.c directly

```bash
git clone https://github.com/frickenate/C-OrderedHash

clang -O2 example.c C-OrderedHash/orderedhash.c -lsodium -o example
```

## Basic Usage

```c
// example.c
#include <stdio.h>
#include <orderedhash.h>

int main()
{
    // options for our hash instance; this example uses strings as
    // keys, so we use ohash_key_string and ohash_compare_key_string
    OHashOptions hash_opts = {
        .key_hash_fn = ohash_key_string,
        .key_compare_fn = ohash_compare_key_string,
    };

    OHash *activities = ohash_new(hash_opts);

    if (!activities) {
        printf("Failed to create hash\n");
        return 1;
    }

    // track activities of some people
    ohash_insert(activities, "Jack", "eating dinner");
    ohash_insert(activities, "Frank", "sleeping");
    ohash_insert(activities, "Amy", "reading a book");

    // current count
    printf(
        "Tracking the activity of %zu people.\n",
        ohash_count(activities)
    );

    // test key existence
    printf(
        "Frank is %s in hash, and Judy is %s.\n",
        ohash_exists(activities, "Frank") ? "found" : "not found",
        ohash_exists(activities, "Judy") ? "found" : "not found"
    );

    // get value by key
    printf (
        "Amy is currently %s.\n",
        (char*)ohash_get(activities, "Amy")
    );

    // iterate items in original insertion order
    OHashIter *iter = ohash_iter_new(activities);

    while (ohash_iter_each(iter)) {
        printf(
            "%s is busy %s right now.\n",
            (char*)ohash_iter_key(iter),
            (char*)ohash_iter_value(iter)
        );

        // safe to delete items while iterating
        ohash_delete(activities, ohash_iter_key(iter));
    }

    ohash_iter_free(iter);

    // release all memory for the hash instance
    ohash_free(activities);
    return 0;
}
```

## Advanced Usage

`OHashOptions` accepts additional options to tailor the behavior of hash
instances. Perhaps the most useful is the ability to define `key_free_fn`
and/or `value_free_fn` as a pointer to a function which should be used
to free the memory of pointers stored in the hash.

```c
// example.c
#include <stdio.h>
#include <string.h>
#include <orderedhash.h>

int main()
{
    // hash can be tasked with freeing memory of keys and/or values
    // when items are deleted. for this example, we configure both
    OHashOptions hash_opts = {
        .key_hash_fn = ohash_key_string,
        .key_compare_fn = ohash_compare_key_string,
        .key_free_fn = free,
        .value_free_fn = free
    };

    OHash *activities = ohash_new(hash_opts);

    if (!activities) {
        printf("Failed to create hash\n");
        return 1;
    }

    // use heap-allocated strings
    char *name = malloc(5);
    strcpy(name, "John");

    char *activity = malloc(9);
    strcpy(activity, "swimming");

    ohash_insert(activities, name, activity);

    // what is John doing?
    printf("%s is %s.\n", name, (char*)ohash_get(activities, name));

    // remove John from hash; since we defined options for key_free_fn
    // and value_free_fn, the name and activity pointers are freed
    ohash_delete(activities, name);

    // ohash_free() also frees all keys/values when freeing functions
    // are defined; in this case we already removed the only item, so
    // there are no more keys or values remaining that need to be freed
    ohash_free(activities);
    return 0;
}
```

## FAQ

### Q: Multi-threaded support?

> A: Unfortunately, multi-threaded support is not baked in. Each hash
instance is fully self-contained, so threads should be able to safely
operate on separate instances returned by `ohash_new()`, but operating
on the same hash instance from multiple threads is not safe. In theory
one safe scenario would be for the main process/thread to create a hash
and populate it fully before spawning threads that only ever use the
functions `ohash_count()`, `ohash_exists()` and `ohash_get()`. Even
`ohash_iter_new()`, used to iterate over a hash, is not thread-safe.
