#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdlib.h>
#include "errno.h"
#include "unistd.h"
#include "assert.h"
#include "string.h"
#include "pthread.h"
#include "malloc.h"
#include "jgmalloc.h"

#define DEBUG 1
#define ALLOCATE 2000000
#define ALIGN_TO 16
#define OVERHEAD (size_t) (sizeof(struct malloc_chunk) + sizeof(size_t))
#define MIN_CHUNK_SIZE (size_t) OVERHEAD + ALIGN_TO

int allocations = 0;
int frees = 0;
int totalBytesAllocated = 0;

mchunkptr freeListHead = NULL;
mchunkptr freeListTail = NULL;

heapptr heapListStart = NULL;

bool heap_any_contains_ptr(const void *ptr);

mchunkptr jgmalloc(size_t);
size_t mchunk_total_space(size_t);
size_t mchunk_aligned_size(size_t);
bool mchunk_should_split(mchunkptr, size_t);
mchunkptr mchunk_split(mchunkptr, size_t);
mchunkptr mchunk_chunk_right(mchunkptr);
void mchunk_set_size(mchunkptr, size_t);

heapptr heap_make(struct malloc_chunk **chunk) {
  heapptr heap = (void*)*chunk;
  *chunk = (void*)(heap + 1);
  memcpy(*chunk, heap, sizeof(struct malloc_chunk));
  mchunk_set_size(*chunk, (*chunk)->size - sizeof(struct heap));

  heap->start = *chunk;
  heap->end = (void*)*chunk + OVERHEAD + (*chunk)->size;

  return heap;
}

void
heap_list_append(struct malloc_chunk **chunk) {
  if (heapListStart) {
    heapptr cur = heapListStart;
    do {
      if (cur->end + 1 == (void*)*chunk) {
	cur->end = (void*)*chunk + OVERHEAD + (*chunk)->size;
	return;
      }
    } while((cur = cur->next) != NULL);

    heapptr heap = heap_make(chunk);
    cur = heapListStart;
    while(cur->next != NULL) { cur = cur->next; }
    cur->next = heap;
    heap->prev = cur;
  } else {
    heapListStart = heap_make(chunk);
  }
}

bool
free_list_is_empty() {
  return freeListHead == NULL;
}

void*
malloc(size_t size) {
  mchunkptr chunk = jgmalloc(size);

  assert(chunk->size >= size);
  assert(!chunk->free);

  return chunk + 1;
}

void
free_list_remove(mchunkptr ptr) {
  if (ptr->prev)
    ptr->prev->next = ptr->next;

  if (ptr->next)
    ptr->next->prev = ptr->prev;

  if (ptr == freeListHead)
    freeListHead = ptr->next;

  if (ptr == freeListTail)
    freeListTail = ptr->prev;

  ptr->prev = ptr->next = NULL;
  ptr->free = false;
}

void free_list_append(mchunkptr ptr) {
  ptr->free = true;

  if (freeListHead == NULL) {
    assert(freeListTail == NULL);
    freeListHead = ptr;
  } else {
    freeListTail->next = ptr;
    ptr->prev = freeListTail;
  }

  freeListTail = ptr;
}

mchunkptr
jgmalloc(size_t size) {
  if (free_list_is_empty()) {
    allocate();
    // if we still don't have any memory we're fucked.
    if (free_list_is_empty()) { return NULL; }
  }

  mchunkptr cur = freeListHead;
  do {
    if (cur->size >= mchunk_aligned_size(size)) {
      free_list_remove(cur);

      if (mchunk_should_split(cur, size)) {
	mchunkptr nxt = mchunk_split(cur, size);
	assert(mchunk_chunk_right(cur) == nxt);
	free_list_append(nxt);

	return cur;
      } else {
	return cur;
      }
    }
  } while((cur = cur->next) != NULL);

  allocate();
  return jgmalloc(size);
}

void
free(void* ptr) {
  if (ptr == NULL) { return; }

  if (heap_any_contains_ptr(ptr)) {
    mchunkptr chunk = (mchunkptr)ptr-1;
    free_list_append(chunk);
  }
}


void*
realloc(void *oldptr, size_t size) {
  void *newptr = malloc(size);

  if (oldptr != NULL) {
    if (newptr != NULL)
      memcpy(newptr, oldptr, sizeof(oldptr));
  }

  return newptr;
}

void*
calloc(size_t count, size_t size) {
  void *ptr = malloc(count * size);

  if (ptr != NULL)
    memset(ptr, 0, count * size);

  return ptr;
}

void *reallocf(void *ptr, size_t size) {
  return NULL;
}

void allocate() {
  mchunkptr ptr = mmap(NULL, ALLOCATE, PROT_WRITE | PROT_READ, MAP_ANON | MAP_SHARED, -1, 0);
  memset(ptr, 0, sizeof(struct malloc_chunk));

  mchunk_set_size(ptr, ALLOCATE - OVERHEAD);

  heap_list_append(&ptr);

  free_list_append(ptr);
}

size_t
mchunk_aligned_size(size_t size) {
  if (size % ALIGN_TO > 0)
    return size + (ALIGN_TO - (size % ALIGN_TO));
  else
    return size;
}

size_t
mchunk_total_space(size_t size) {
  return mchunk_aligned_size(size) + OVERHEAD;
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
mchunk_set_size(mchunkptr chunk, size_t size) {
  chunk->size = size;
  size_t *sizeRegion = mchunk_footer(chunk);
  *sizeRegion = chunk->size;
}

bool
mchunk_should_split(mchunkptr ptr, size_t size) {
  size_t remaining_size = ptr->size - mchunk_total_space(size);
  // make sure remaining_size is < ptr->size because of unsigned int div
  return remaining_size < ptr->size && remaining_size >= MIN_CHUNK_SIZE;
}

mchunkptr
mchunk_split(mchunkptr ptr, size_t size) {
  size_t remaining_size = ptr->size - mchunk_total_space(size);
  assert(remaining_size < ptr->size);

  mchunkptr split = (void*)ptr + OVERHEAD + mchunk_aligned_size(size);
  memset(split, 0, sizeof(struct malloc_chunk));

  mchunk_set_size(split, ptr->size - mchunk_aligned_size(size) - OVERHEAD);
  mchunk_set_size(ptr, mchunk_aligned_size(size));

  assert(ptr->size >= size);

  return split;
}

void 
assert_sane_chunk(mchunkptr chunk) {
  assert(chunk->size == *mchunk_footer(chunk));
}

mchunkptr
mchunk_chunk_right(mchunkptr ptr) {
  return (void*)ptr + OVERHEAD + ptr->size;
}

bool
heap_any_contains_ptr(const void *ptr) {
  heapptr cur = heapListStart;
  do {
    if (ptr > cur->start && ptr < cur->end)
      return true;
  } while((cur = cur->next) != NULL);

  return false;
}

void *
valloc(size_t size) {
  return NULL;
}
