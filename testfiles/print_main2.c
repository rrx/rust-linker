#include <stdio.h>
#include <stdlib.h>

char *g4 = "X";
long g = 1;

int main(int argc, const char **argv) {
  int x = &fprintf;
  fprintf(stdout, "%p, %p, %x\n", x, g4, *g4);
  return 0;
}
