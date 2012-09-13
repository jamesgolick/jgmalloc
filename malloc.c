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
    struct malloc_chunk *last = freeListStart;

    do {
      if (last->size <= block_size) {

#ifdef DEBUG
	print_malloc_stats();
#endif

	if (last->prev)
	  last->prev->next = last->next;

	if (last->next)
	  last->next->prev = last->prev;

	if (freeListStart == last) {
	  if (last->next)
	    freeListStart = last->next;
	  else
	    freeListStart = NULL;
	}

	last->next = NULL;
	last->prev = NULL;

	fprintf(stderr, "reissuing pointer %p / chunk %p\n", last + 1, last);
	return last + 1;
      }
    } while((last=last->next) != NULL);
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

  return newPtr;
}

void *calloc(size_t count, size_t size) {
  fprintf(stderr, "entering calloc.\n");
  void *ptr = malloc(count * size);
  //memset(ptr, 0, count * size);
  return ptr;
}

