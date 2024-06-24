#include <stdio.h>
#include <stdlib.h>

int call_fprintf() {
  int x = &fprintf;
  fprintf(stdout, "%p\n", x);
  return 0;
}

int main(int argc, const char **argv) { return call_fprintf(); }
