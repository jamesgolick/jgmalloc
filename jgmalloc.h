#include <string.h>
#include <stdbool.h>

struct malloc_chunk {
  size_t size;
  bool free;
  struct malloc_chunk *next;
  struct malloc_chunk *prev;
};
typedef struct malloc_chunk* mchunkptr;

void print_malloc_stats();
mchunkptr free_list_head();
void allocate();
size_t aligned_size(size_t size);

void set_size(mchunkptr chunk, size_t size);
void assert_sane_chunk(mchunkptr chunk);

mchunkptr chunk_left(mchunkptr);
mchunkptr chunk_right(mchunkptr);

bool beyond_right_edge_of_heap(void*);
bool is_in_heap(void*);
void record_new_heap_bounds(void*, void*);
bool has_space_right(void*, size_t);
bool is_left_edge_of_heap(mchunkptr);
