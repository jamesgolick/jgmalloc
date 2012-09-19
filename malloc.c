#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "errno.h"
#include "unistd.h"
#include "assert.h"
#include "string.h"
#include "pthread.h"

#define DEBUG 1

struct malloc_chunk;
typedef struct malloc_chunk* mchunkptr;
struct malloc_chunk {
  size_t size;
  bool free;
  struct malloc_chunk *next;
  struct malloc_chunk *prev;
};

#define ALLOCATE 409600
#define ALIGN_TO 16
#define OVERHEAD (size_t) (sizeof(struct malloc_chunk) + sizeof(size_t))
#define MIN_CHUNK_SIZE (size_t) OVERHEAD + ALIGN_TO

void print_malloc_stats();
mchunkptr free_list_head();
void allocate();
size_t aligned_size(size_t size);

void set_size(mchunkptr chunk, size_t size);
void assert_sane_chunk(mchunkptr chunk);

int allocations = 0;
int frees = 0;
int totalBytesAllocated = 0;

mchunkptr freeListHead;
mchunkptr freeListTail;

void* heapStart;
void* heapEnd;

void* jgmalloc(size_t block_size);
void* after_chunk(mchunkptr chunk);

void* malloc(size_t size) {
  void *ptr = jgmalloc(size);
  mchunkptr chunk = ((mchunkptr)ptr) - 1;
  assert(chunk->size >= size);
  fprintf(stderr, "[malloc] issuing %p chunk @ %p size %u to satisfy %u\n", ptr, chunk, chunk->size, size);
  return ptr;
}

void* jgmalloc(size_t block_size) {
  if (freeListHead == NULL) {
    allocate();
    return malloc(block_size);
  } else {
    mchunkptr cur = freeListHead;

    do {
      if (cur->size > block_size) {
	size_t alignedSize = aligned_size(block_size);
	size_t totalSize = alignedSize + OVERHEAD;
	size_t remainingSize = cur->size - totalSize;

	// split this block if there's enough space left to actually allocate
	// for anything else.
	if (remainingSize > MIN_CHUNK_SIZE && remainingSize < cur->size) {
	  mchunkptr split = ((void*)cur) + totalSize;

	  set_size(split, cur->size - totalSize - OVERHEAD);
	  assert_sane_chunk(split);
	  assert(after_chunk(split) <= heapEnd);
	  assert((void*) split - (void*) cur == totalSize);
	  set_size(cur, alignedSize);
	  assert_sane_chunk(cur);

	  if (cur == freeListHead) {
	    freeListHead = split;
	    split->next = cur->next;
	  } else {
	    split->next = cur->next;
	    split->prev = cur->prev;
	  }

	  cur->next = NULL;
	  cur->prev = NULL;
	  
	  return cur + 1;
	} else {
	  if (cur == freeListHead)
	    freeListHead = cur->next;

	  if (cur->next)
	    cur->next->prev = cur->prev;

	  if (cur->prev)
	    cur->prev->next = cur->next;

	  cur->next = NULL;
	  cur->prev = NULL;

	  return cur + 1;
	}
      }
    } while((cur = cur->next) != NULL);
  }

  allocate();
  return jgmalloc(block_size);
}

void free(void* ptr) {
  if (ptr == NULL) return;

  fprintf(stderr, "[free] freeing @ %p\n", ptr);
  mchunkptr chunk = ((mchunkptr) ptr) - 1;

  if (freeListHead) {
    freeListTail->prev = chunk;
    chunk->next = freeListTail;
    freeListTail = chunk;
  } else {
    freeListHead = chunk;
    freeListTail = chunk;
  }
}

void print_malloc_stats() {
  fprintf(stderr, "[malloc_stats] allocations: %d bytes allocated: %d frees: %d\n",
	  allocations, totalBytesAllocated, frees);
}

void *realloc(void *ptr, size_t size) {
  void *newPtr = malloc(size);

  if (ptr != NULL) {
    if (newPtr != NULL)
      memcpy(newPtr, ptr, sizeof(ptr));
    free(ptr);
  }

  fprintf(stderr, "[realloc] issuing pointer %p\n", newPtr);

  return newPtr;
}

void *calloc(size_t count, size_t size) {
  fprintf(stderr, "entering calloc.\n");
  void *ptr = malloc(count * size);
  if (ptr != NULL)
    memset(ptr, 0, count * size);
  fprintf(stderr, "calloc returning pointer %p\n", ptr);
  return ptr;
}

void allocate(size_t size) {
  mchunkptr ptr = mmap(NULL, ALLOCATE, PROT_WRITE | PROT_READ, MAP_ANON | MAP_SHARED, -1, 0);

  if (!heapStart) heapStart = ptr;
  heapEnd = ((void*)ptr) + ALLOCATE;

  set_size(ptr, ALLOCATE - OVERHEAD);
  assert_sane_chunk(ptr);

  freeListHead = ptr;
  freeListTail = ptr;
}

size_t aligned_size(size_t size) {
  if (size % ALIGN_TO > 0)
    return size + (ALIGN_TO - (size % ALIGN_TO));
  else
    return size;
}

void *after_chunk(mchunkptr chunk) {
  return ((void*)chunk) + chunk->size + OVERHEAD;
}

size_t *size_region(mchunkptr chunk) {
  size_t *region = (void *)chunk + chunk->size + sizeof(struct malloc_chunk);
  assert((void*)region <= heapEnd - sizeof(size_t));
  return region;
}

void set_size(mchunkptr chunk, size_t size) {
  chunk->size = size;
  size_t *sizeRegion = size_region(chunk);
  *sizeRegion = chunk->size;
}

void assert_sane_chunk(mchunkptr chunk) {
  assert(chunk->size == *size_region(chunk));
}
