#include <stdio.h>
#include <sys/mman.h>
#include <stdbool.h>
#include "errno.h"
#include "unistd.h"
#include "assert.h"
#include "string.h"
#include "pthread.h"
#include "jgmalloc.h"
#include <malloc/malloc.h>

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

mchunkptr jgmalloc(size_t);
size_t mchunk_total_space(size_t);
size_t mchunk_aligned_size(size_t);
bool mchunk_should_split(mchunkptr, size_t);
mchunkptr mchunk_split(mchunkptr, size_t);
mchunkptr mchunk_chunk_right(mchunkptr);
void mchunk_set_size(mchunkptr, size_t);

bool
free_list_is_empty() {
  return freeListHead == NULL;
}

void*
jg_malloc(struct _malloc_zone_t *zone, size_t size) {
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
jg_free(struct _malloc_zone_t *zone, void* ptr) {
  mchunkptr chunk = (mchunkptr)ptr-1;
  free_list_append(chunk);
}


void*
jg_realloc(struct _malloc_zone_t *zone, void *ptr, size_t size) {
  void *newPtr = jg_malloc(zone, size);

  if (ptr != NULL) {
    if (newPtr != NULL)
      memcpy(newPtr, ptr, sizeof(ptr));
    jg_free(zone, ptr);
  }

  return newPtr;
}

void*
jg_calloc(struct _malloc_zone_t *zone, size_t count, size_t size) {
  void *ptr = jg_malloc(zone, count * size);

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

size_t
jg_size() {
  return 0;
}

boolean_t
jg_zone_locked() {
  return false;
}

void *
jg_valloc(size_t size) {
  return NULL;
}

// This is all snatched from tcmalloc
static void __attribute__((constructor))
jgmalloc_init(void) {
  static malloc_zone_t jgmalloc_zone;
  memset(&jgmalloc_zone, 0, sizeof(malloc_zone_t));

  jgmalloc_zone.version = 6;
  jgmalloc_zone.zone_name = "jgmalloc";
  jgmalloc_zone.size = jg_size;
  jgmalloc_zone.malloc = jg_malloc;
  jgmalloc_zone.calloc = jg_calloc;
  jgmalloc_zone.free = jg_free;
  jgmalloc_zone.realloc = jg_realloc;
  jgmalloc_zone.batch_malloc = NULL;
  jgmalloc_zone.batch_free = NULL;

  jgmalloc_zone.free_definite_size = NULL;
  jgmalloc_zone.memalign = NULL;

  malloc_default_purgeable_zone();

  // Register the jgmalloc zone. At this point, it will not be the
  // default zone.
  malloc_zone_register(&jgmalloc_zone);

  // Unregister and reregister the default zone.  Unregistering swaps
  // the specified zone with the last one registered which for the
  // default zone makes the more recently registered zone the default
  // zone.  The default zone is then re-registered to ensure that
  // allocations made from it earlier will be handled correctly.
  // Things are not guaranteed to work that way, but it's how they work now.
  malloc_zone_t *default_zone = malloc_default_zone();
  malloc_zone_unregister(default_zone);
  malloc_zone_register(default_zone);
}
