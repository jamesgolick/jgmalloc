#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "errno.h"
#include "unistd.h"
#include "assert.h"
#include "string.h"
#include "pthread.h"
#include "jgmalloc.h"

#define DEBUG 1
#define ALLOCATE 409600
#define ALIGN_TO 16
#define OVERHEAD (size_t) (sizeof(struct malloc_chunk) + sizeof(size_t))
#define MIN_CHUNK_SIZE (size_t) OVERHEAD + ALIGN_TO

int allocations = 0;
int frees = 0;
int totalBytesAllocated = 0;

mchunkptr freeListHead = NULL;
mchunkptr freeListTail = NULL;

void* jgmalloc(size_t block_size);

void* malloc(size_t size) {
  void *ptr = jgmalloc(size);
  mchunkptr chunk = ((mchunkptr)ptr) - 1;
  assert(chunk->size >= size);
  assert(!chunk->free);

  return ptr;
}

void *jgmalloc(size_t size) {
  if (free_list_is_empty()) {
    allocate();
  }
}

void free(void* ptr) {
}


void *realloc(void *ptr, size_t size) {
  void *newPtr = malloc(size);

  if (ptr != NULL) {
    if (newPtr != NULL)
      memcpy(newPtr, ptr, sizeof(ptr));
    free(ptr);
  }

  return newPtr;
}

void *calloc(size_t count, size_t size) {
  void *ptr = malloc(count * size);

  if (ptr != NULL)
    memset(ptr, 0, count * size);

  return ptr;
}

void *reallocf(void *ptr, size_t size) {
  //fprintf(stderr, "VALLOC\n");
}

void allocate(size_t size) {
  mchunkptr ptr = mmap(NULL, ALLOCATE, PROT_WRITE | PROT_READ, MAP_ANON | MAP_SHARED, -1, 0);

  if (freeListHead == NULL) {
    freeListHead = ptr;
  } else {
    freeListTail->next = ptr;
  }

  freeListTail = ptr;
}

size_t aligned_size(size_t size) {
  if (size % ALIGN_TO > 0)
    return size + (ALIGN_TO - (size % ALIGN_TO));
  else
    return size;
}

void*
mchunk_chunk_start(mchunkptr chunk) {
 return chunk + 1;
}

size_t*
mchunk_footer(mchunkptr chunk) {
  size_t *region = mchunk_chunk_start(chunk) + chunk->size;
  return region;
}

void 
mchunk_set_footer(mchunkptr chunk, size_t size) {
  chunk->size = size;
  size_t *sizeRegion = mchunk_footer(chunk);
  *sizeRegion = chunk->size;
}

void 
assert_sane_chunk(mchunkptr chunk) {
  assert(chunk->size == *mchunk_footer(chunk));
}
