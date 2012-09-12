#include <stdlib.h>
#include <stdio.h>

int main() {
  printf("asdf");
  char *p = malloc(100 * sizeof(char));
  printf("%p\n", p);

  exit(0);
}
