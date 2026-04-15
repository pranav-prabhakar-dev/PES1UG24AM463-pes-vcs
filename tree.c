// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Forward declaration — object_write is implemented in object.c.
// We declare it here so tree.c can call it without including a separate header,
// which keeps test_tree (which does NOT link index.o) compilable.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// Minimal per-entry struct for reading the index file directly.
// We avoid including index.h so that test_tree links cleanly (index.c is
// not part of the test_tree link target).
typedef struct {
    uint32_t mode;
    ObjectID hash;
    char path[512];
} RawEntry;

// Sort helper: entries must be in lexicographic path order so that directory
// grouping in write_tree_level works correctly.
static int compare_raw_entries(const void *a, const void *b) {
    return strcmp(((const RawEntry *)a)->path, ((const RawEntry *)b)->path);
}

// Recursive helper: builds one level of the tree hierarchy and writes it.
static int write_tree_level(RawEntry *entries, int count,
                             int prefix_len, ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        const char *rel = entries[i].path + prefix_len;
        char *slash = strchr(rel, '/');

        if (!slash) {
            // No slash → plain file at this level
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = entries[i].mode;
            te->hash = entries[i].hash;
            strncpy(te->name, rel, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            i++;
        } else {
            // Has slash → belongs to a subdirectory; collect all siblings
            int dir_len = (int)(slash - rel);
            char dir_name[256];
            strncpy(dir_name, rel, dir_len);
            dir_name[dir_len] = '\0';

            // Find the end of this directory's run
            int j = i;
            while (j < count) {
                const char *r = entries[j].path + prefix_len;
                char *s = strchr(r, '/');
                if (!s) break;
                if ((int)(s - r) != dir_len) break;
                if (strncmp(r, dir_name, dir_len) != 0) break;
                j++;
            }

            // Recurse: build the subtree for entries[i..j-1]
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i,
                                 prefix_len + dir_len + 1, &sub_id) != 0)
                return -1;

            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            te->hash = sub_id;
            strncpy(te->name, dir_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';

            i = j;
        }
    }

    void *data;
    size_t len;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;
    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
//
// Reads .pes/index directly (format: "<mode-octal> <hex> <mtime> <size> <path>")
// so that this translation unit stays independent of index.c — which is
// important because test_tree does not link index.o.
//
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    // Heap-allocate the entry array: 10000 * ~548 bytes ≈ 5 MB, too large for stack
    RawEntry *entries = malloc(10000 * sizeof(RawEntry));
    if (!entries) return -1;
    int count = 0;

    FILE *f = fopen(INDEX_FILE, "r");
    if (f) {
        uint32_t mode;
        char hex[HASH_HEX_SIZE + 1];
        unsigned long long mtime;
        unsigned int size;
        char path[512];

        while (count < 10000 &&
               fscanf(f, "%o %64s %llu %u %511s",
                      &mode, hex, &mtime, &size, path) == 5) {
            entries[count].mode = mode;
            hex_to_hash(hex, &entries[count].hash);
            strncpy(entries[count].path, path, sizeof(entries[count].path) - 1);
            entries[count].path[sizeof(entries[count].path) - 1] = '\0';
            count++;
        }
        fclose(f);
    }

    qsort(entries, count, sizeof(RawEntry), compare_raw_entries);

    int rc = write_tree_level(entries, count, 0, id_out);
    free(entries);
    return rc;
}