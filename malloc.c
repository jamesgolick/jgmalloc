#include <stdio.h>
#include "unistd.h"
#include "assert.h"
#include "string.h"
#include "pthread.h"

#define DEBUG 1

struct malloc_chunk;
struct malloc_chunk {
  size_t size;
  int magic;
  struct malloc_chunk *next;
  struct malloc_chunk *prev;
};

#define ALIGN_TO 16

void print_malloc_stats();

int allocations = 0;
int frees = 0;
int totalBytesAllocated = 0;

void* malloc(size_t block_size) {
  fprintf(stderr, "enter malloc\n");

  return NULL;
}

void free(void* ptr) {
  if (ptr == NULL) return;
}

void print_malloc_stats() {
  fprintf(stderr, "[malloc_stats] allocations: %d bytes allocated: %d frees: %d\n",
	  allocations, totalBytesAllocated, frees);
}

void *realloc(void *ptr, size_t size) {
  fprintf(stderr, "entering realloc.\n");
  void *newPtr = malloc(size);

  if (ptr != NULL) {
    if (newPtr != NULL)
      memcpy(newPtr, ptr, sizeof(ptr));
    free(ptr);
  }

  fprintf(stderr, "realloc returning pointer %p\n", newPtr);

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
