#include <stdio.h>
#include "unistd.h"
#include "assert.h"


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

	return last + 1;
      }
    } while(last->next != NULL);
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

  return ptr + 1;
}

void free(void* ptr) {
  struct malloc_chunk *chunk = ((struct malloc_chunk *)ptr) - 1;

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
