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

struct heap {
  void *start;
  void *end;
  struct heap *next;
  struct heap *prev;
};
typedef struct heap * heapptr;

int allocations = 0;
int frees = 0;
int totalBytesAllocated = 0;

mchunkptr freeListHead;
mchunkptr freeListTail;

heapptr heapListHead;
heapptr heapListTail;

void* jgmalloc(size_t block_size);
void* after_chunk(mchunkptr chunk);

void* malloc(size_t size) {
  void *ptr = jgmalloc(size);
  mchunkptr chunk = ((mchunkptr)ptr) - 1;
  assert(chunk->size >= size);
  assert(!chunk->free);
  //fprintf(stderr, "[malloc] issuing %p chunk @ %p size %u to satisfy %u\n", ptr, chunk, chunk->size, size);
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
	cur->free = false;
	size_t alignedSize = aligned_size(block_size);
	size_t totalSize = alignedSize + OVERHEAD;
	size_t remainingSize = cur->size - totalSize;

	// split this block if there's enough space left to actually allocate
	// for anything else.
	if (remainingSize > MIN_CHUNK_SIZE && remainingSize < cur->size) {
	  mchunkptr split = ((void*)cur) + totalSize;

	  set_size(split, cur->size - totalSize - OVERHEAD);
	  assert_sane_chunk(split);
	  assert(!beyond_right_edge_of_heap(split));
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
  if (!is_in_heap(ptr)) return;

  mchunkptr chunk = ((mchunkptr) ptr) - 1;
  assert_sane_chunk(chunk);
  chunk->free = true;

  if (freeListHead) {
    mchunkptr left  = chunk_left(chunk);
    mchunkptr right = chunk_right(chunk);
    bool append = true;

    if (left && left->free) {
      append = false;
      chunk->prev = left;

      if (left->next) {
	chunk->next = left->next;
	left->next->prev = chunk;
      }

      if (left == freeListTail)
	freeListTail = chunk;
    }

    if (right && right->free) {
      append = false;
      chunk->next = right;

      if (right->prev) {
	chunk->prev = right->prev;
	right->prev->next = chunk;
      }

      if (right == freeListHead)
	freeListHead = chunk;
    }

    if (append) {
      freeListTail->prev = chunk;
      chunk->next = freeListTail;
      freeListTail = chunk;
    }
  } else {
    freeListHead = chunk;
    freeListTail = chunk;
  }
}

void print_malloc_stats() {
  ///fprintf(stderr, "[malloc_stats] allocations: %d bytes allocated: %d frees: %d\n",
	  //allocations, totalBytesAllocated, frees);
}

void *realloc(void *ptr, size_t size) {
  void *newPtr = malloc(size);

  if (ptr != NULL) {
    //fprintf(stderr, "[realloc] attempting to realloc %p of size %u to %u\n", ptr, ((mchunkptr)ptr - 1)->size, size);

    if (newPtr != NULL)
      memcpy(newPtr, ptr, sizeof(ptr));
    free(ptr);
  }

  //fprintf(stderr, "[realloc] issuing pointer %p\n", newPtr);

  return newPtr;
}

void *calloc(size_t count, size_t size) {
  //fprintf(stderr, "entering calloc.\n");
  void *ptr = malloc(count * size);
  if (ptr != NULL)
    memset(ptr, 0, count * size);
  //fprintf(stderr, "calloc returning pointer %p\n", ptr);
  return ptr;
}

/*void *valloc(size_t size) {*/
/*  fprintf(stderr, "VALLOC\n");*/
/*}*/

void *reallocf(void *ptr, size_t size) {
  //fprintf(stderr, "VALLOC\n");
}

heapptr make_heap(void *allocation) {
  heapptr heap = (heapptr)allocation;
  //memset(heap, 0, sizeof(struct heap));
  mchunkptr chunk = allocation + sizeof(struct heap);
  chunk->size = ALLOCATE - OVERHEAD - sizeof(struct heap);
  heap->start = (void*)chunk;
  heap->end = (void*)chunk + chunk->size;

  return heap;
}

void allocate(size_t size) {
  mchunkptr ptr = mmap(NULL, ALLOCATE, PROT_WRITE | PROT_READ, MAP_ANON | MAP_SHARED, -1, 0);
  ptr->size = ALLOCATE - OVERHEAD;

  if (heapListHead) {
    heapptr cur = heapListHead;
    bool appended = false;

    do {
      if (cur->end == (void*)ptr - 1) {
	cur->end = (void*)ptr + ALLOCATE;
	appended = true;
      }
    } while((cur = heapListHead->next) != NULL);

    if (!appended) {
      heapptr heap = make_heap(ptr);
      ptr = heap->start + 1;
      heapListTail->next = heap;
      heap->prev = heapListTail;
      heapListTail = heap;
    }
  } else {
    heapListHead = make_heap(ptr);
    heapListTail = heapListHead;
    ptr = heapListHead->start + 1;
  }

  set_size(ptr, ptr->size);
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
  assert(has_space_right(region, sizeof(size_t)));
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

mchunkptr chunk_left(mchunkptr chunk) {
  if (is_left_edge_of_heap(chunk)) {
    return NULL;
  } else {
    size_t *leftSize = (void*)chunk - sizeof(size_t);
    return (void*)chunk - *leftSize - OVERHEAD;
  }
}

mchunkptr chunk_right(mchunkptr chunk) {
  void *right = (void*)chunk + chunk->size + OVERHEAD;
  if (beyond_right_edge_of_heap(right)) {
    return NULL;
  } else {
    return right;
  }
}

void record_new_heap_bounds(void *start, void *end) {
}

bool beyond_right_edge_of_heap(void *ptr) {
  heapptr cur = heapListHead;
  do {
    if (ptr > cur->start && ptr < cur->end)
      return false;
  } while((cur = cur->next) != NULL);

  return true;
}

bool is_in_heap(void *ptr) {
  return true;
}

bool has_space_right(void* ptr, size_t space) {
  return true;
}

bool is_left_edge_of_heap(mchunkptr chunk) {
  return false;
}
