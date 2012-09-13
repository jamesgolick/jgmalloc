#include <stdio.h>
#include "unistd.h"
#include "assert.h"
#include "string.h"

#define DEBUG 1

struct malloc_chunk;
struct malloc_chunk {
  size_t size;
  struct malloc_chunk *next;
  struct malloc_chunk *prev;
};

#define ALIGN_TO 16

void print_malloc_stats();

int allocations = 0;
int frees = 0;
int totalBytesAllocated = 0;

struct malloc_chunk *freeListStart;

void* malloc(size_t block_size) {
  fprintf(stderr, "enter malloc\n");

  if (freeListStart != NULL) {
    struct malloc_chunk *chunk = freeListStart;

    do {
      if (chunk->size >= block_size) {

#ifdef DEBUG
	print_malloc_stats();
#endif

	if (chunk->prev != NULL)
	  chunk->prev->next = chunk->next;

	if (chunk->next != NULL)
	  chunk->next->prev = chunk->prev;

	if (chunk == freeListStart)
	  freeListStart = chunk->next;

	chunk->prev = NULL;
	chunk->next = NULL;

	fprintf(stderr, "reissuing %p chunk %p\n", chunk + 1, chunk);

	return chunk + 1;
      }
    } while((chunk = chunk->next) != NULL);
  }

  allocations++;

  size_t size = block_size + sizeof(struct malloc_chunk);
  if (size % ALIGN_TO > 0)
    size += ALIGN_TO - (size % ALIGN_TO);

  assert(size % ALIGN_TO == 0);

  totalBytesAllocated += size;

  struct malloc_chunk *ptr = sbrk(size);
  ptr->size = block_size;

#ifdef DEBUG
  print_malloc_stats();
#endif
  fprintf(stderr, "issuing pointer %p chunk %p\n", ptr + 1, ptr);

  return ptr + 1;
}

void free(void* ptr) {
  if (ptr == NULL) return;

  struct malloc_chunk *chunk = ((struct malloc_chunk *)ptr) - 1;
  fprintf(stderr, "enter free with %p chunk %p\n", ptr, chunk);

  if (freeListStart == NULL) {
    freeListStart = chunk;
    frees++;
  } else {
    struct malloc_chunk *last = freeListStart;

    while(last->next != NULL) {
      last = last->next;
    }

    last->next = chunk;
    chunk->prev = last;

    frees++;
  }

  print_malloc_stats();
}

void print_malloc_stats() {
  fprintf(stderr, "[malloc_stats] allocations: %d bytes allocated: %d frees: %d\n",
	  allocations, totalBytesAllocated, frees);
}

void *realloc(void *ptr, size_t size) {
  fprintf(stderr, "entering realloc.\n");
  void *newPtr = malloc(size);

  if (ptr != NULL) {
    memcpy(newPtr, ptr, sizeof(ptr));
    free(ptr);
  }

  fprintf(stderr, "realloc returning pointer %p\n", newPtr);

  return newPtr;
}

void *calloc(size_t count, size_t size) {
  fprintf(stderr, "entering calloc.\n");
  void *ptr = malloc(count * size);
  memset(ptr, 0, count * size);
  fprintf(stderr, "calloc returning pointer %p\n", ptr);
  return ptr;
}

