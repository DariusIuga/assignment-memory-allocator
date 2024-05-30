// SPDX-License-Identifier: BSD-3-Clause

#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../tests/snippets/test-utils.h"
#include "../utils/block_meta.h"

// 8 byte alignment on Linux
#define ALIGNMENT 8
// First multiple of 8 bytes
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

// The head of the linked list of all memory zones
// Am I allocating memory for calloc or not?
// bool from_calloc = false;
struct block_meta *head = NULL;
struct block_meta *tail = NULL;
bool heap_inited = false;

void init_heap(struct block_meta *block)
{
    // Preallocation
    block = sbrk(0);
    struct block_meta *end = sbrk(MMAP_THRESHOLD);
    DIE(end == (void *)-1, "sbrk failed!");

    block->size = MMAP_THRESHOLD - METADATA_SIZE;
    block->prev = tail;
    block->next = NULL;
    block->status = STATUS_ALLOC;
    head = block;
    tail = block;
}

struct block_meta *request_space(struct block_meta *block, size_t size,
                                 size_t threshold)
{
    if (block != NULL) {
        if (block->status == STATUS_FREE) {
            // The block was previously freed
            if (size + 32 < threshold) {
                block->status = STATUS_ALLOC;
            } else {
                block->status = STATUS_MAPPED;
            }
            return block;
        }
    }

    size_t full_size = size + METADATA_SIZE;

    if (full_size < threshold) {
        block = sbrk(0);
        void *request = sbrk(full_size);
        DIE(request == (void *)-1, "sbrk failed!");
        block->status = STATUS_ALLOC;
    } else {
        // Big zones of memory are allocated with mmap
        block = mmap(NULL, full_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
        block->status = STATUS_MAPPED;
    }

    if (head == NULL) {
        head = block;
    }

    block->size = size;
    block->prev = tail;
    block->next = NULL;
    if (tail != NULL) {
        tail->next = block;
    }
    tail = block;

    return block;
}

void *find_fit(size_t size)
{
    // Finds the first free block bigger than the requested size
    if (head == tail) {
        // Could access members of a unmapped non-NULL pointer, which would
        // result in a segfault. This should avoitd that+
        return NULL;
    }
    struct block_meta *header = head;
    while (header != NULL) {
        if (header->status == STATUS_FREE && header->size >= size) {
            header->size = size;
            return header;
        }
        header = header->next;
    }
    return NULL;
}

struct block_meta *get_block_ptr(void *ptr)
{
    return (struct block_meta *)ptr - 1;
}

void *os_malloc(size_t size)
{
    if (size <= 0) {
        return NULL;
    }

    size = ALIGN(size);
    struct block_meta *block;

    if (heap_inited == false && size + METADATA_SIZE < MMAP_THRESHOLD) {
        heap_inited = true;
        init_heap(block);
        block = head;
        return (block + 1);
    }

    block = find_fit(size);

    block = request_space(block, size, MMAP_THRESHOLD);
    DIE(block == NULL, "Failed to allocate space!");

    return (block + 1);
}

void os_free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }

    // TODO: consider merging blocks once splitting blocks is implemented.
    struct block_meta *block_ptr = get_block_ptr(ptr);
    if (block_ptr == NULL) {
        return;
    }
    if (block_ptr->status == STATUS_MAPPED) {
        munmap(block_ptr, block_ptr->size + METADATA_SIZE);
    } else if (block_ptr->status == STATUS_ALLOC) {
        block_ptr->status = STATUS_FREE;
    }
}

void *os_calloc(size_t nmemb, size_t size)
{
    size_t total_size = nmemb * size;
    if (total_size <= 0) {
        return NULL;
    }

    total_size = ALIGN(total_size);
    struct block_meta *block;

    if (heap_inited == false && total_size + METADATA_SIZE < EXEC_PAGESIZE) {
        heap_inited = true;
        init_heap(block);
        block = head;
        return (block + 1);
    }

    block = find_fit(total_size);

    block = request_space(block, total_size, EXEC_PAGESIZE);
    DIE(block == NULL, "Failed to allocate space!");
    memset(block + 1, 0, block->size);

    return (block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
    if (ptr == NULL) {
        // For a  NULL pointer realloc should act like malloc.
        return os_malloc(size);
    }
    if (size == 0) {
        os_free(ptr);
        return NULL;
    }

    struct block_meta *block_ptr = get_block_ptr(ptr);
    size_t old_size = block_ptr->size;
    size_t new_size = ALIGN(size);
    size_t minimum_size = MIN(old_size, new_size);

    if (block_ptr->status == STATUS_FREE) {
        return NULL;
    } else if (block_ptr->status == STATUS_MAPPED) {
        void *new_ptr = os_malloc(new_size);
        if (new_ptr == NULL) {
            return NULL;  // TODO: set errno on failure.
        }
        // Copy the memory content to the new zone
        memcpy(new_ptr, ptr, new_size);
        // Free the old zone
        munmap((void *)block_ptr, block_ptr->size + METADATA_SIZE);

        return new_ptr;
    } else if (block_ptr->status == STATUS_ALLOC) {
        memcpy(ptr, ptr, minimum_size);
    } else {
        memcpy(ptr, ptr, minimum_size);
    }
}

// TESTING realloc-arrays
int main(void)
{
    void *prealloc_ptr, *ptr_free, *ptrs[NUM_SZ_SM];

    prealloc_ptr = mock_preallocate();

    /* Test small allocations */
    for (int i = 0; i < NUM_SZ_SM; i++) {
        ptrs[i] = os_realloc_checked(NULL, inc_sz_sm[i]);
        taint(ptrs[i], inc_sz_sm[i]);
    }

    /* Test block truncating on small allocations */
    for (int i = 1; i < NUM_SZ_SM; i++)
        ptrs[i] = os_realloc_checked(ptrs[i], inc_sz_sm[i - 1]);

    /* Test block expansion on small allocations */
    for (int i = 0; i < NUM_SZ_SM; i++)
        ptrs[i] = os_realloc_checked(ptrs[i], inc_sz_sm[i]);

    /* Test mapped reallocations */
    for (int i = 0; i < NUM_SZ_LG; i++)
        ptrs[i] = os_realloc_checked(ptrs[i], inc_sz_lg[i]);

    /* Test mixed reallocations */
    for (int i = 0; i < NUM_SZ_MD; i++)
        ptrs[i] = os_realloc_checked(ptrs[i], inc_sz_md[i]);

    /* Test realloc on free block */
    ptr_free = os_realloc_checked(NULL, 100);
    os_free(ptr_free);
    os_realloc_checked(ptr_free, 200);

    /* Cleanup using realloc */
    os_realloc_checked(prealloc_ptr, 0);
    for (int i = 0; i < NUM_SZ_SM; i++) os_realloc_checked(ptrs[i], 0);

    return 0;
}