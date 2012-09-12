#include <stdio.h>

void* malloc(size_t size) {
  printf("asdf");
  char *block = (char*)sbrk(size);

  return ((char*)block);
}

void free(void* ptr) {
}
