#include <stdio.h>
#include <stdlib.h>

// .data
int g = 1;

// .bss
int g2 = 0;
int g3 = 0;

// link from another object file
long asdf(long);

int main(int argc, const char **argv) {
  long y = asdf(1);
  printf("y %d\n", y);
  puts("XXX1");
  printf("XXX2\n");
  fprintf(stdout, "XXX3\n");
  fprintf(stdout, "%p\n", fprintf);
  g = &fprintf;
  g2 = &fprintf;
  g3 = &fprintf;
  fprintf(stdout, "%p\n", g);
  fprintf(stderr, "%p\n", g2);
  fprintf(stderr, "%p\n", g3);
  fflush(stdout);
  fflush(stderr);
  for (int i = 0; i < argc; i++) {
    printf("arg %d: %s\n", i, argv[i]);
  }
  return 0;
}
