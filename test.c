#include <stdlib.h>
#include <stdio.h>

int main() {
  char *a = malloc(100 * sizeof(char));
  char *b = malloc(100 * sizeof(char));

  printf("%p\n", a);
  printf("%p\n", b);

  free(a);
  free(b);

  char *c = malloc(100 * sizeof(char));
  char *d = malloc(100 * sizeof(char));
  printf("%p\n", c);
  printf("%p\n", d);

  exit(0);
}
