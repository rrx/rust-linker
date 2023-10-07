#include <sigsegv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

extern long simple_function();

void *g_ptr;
int g_size;

int handler(void *fault_address, int serious) {
  /*printf("segfault: %x, %d\n", g_ptr, g_size);*/
  /*fflush(stdout);*/
  return 0;
}

void segfault_me() {
  void (*ptr)() = 0;
  ptr();
}

void handlers_init(void *ptr, int size) {
  g_ptr = ptr;
  g_size = size;
  /*puts("asdf\n");*/
  /*puts("asdf\n");*/
  /*simple_function();*/
  /*printf("install: %x, %d\n", g_ptr, g_size);*/
  /*fflush(stdout);*/
  /* Install the global SIGSEGV handler.  */
  /*sigsegv_install_handler (&handler);*/
  /*segfault_me();*/
}


