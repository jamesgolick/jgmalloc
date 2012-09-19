#include <string.h>

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
