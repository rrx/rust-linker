/*int __libc_argc = 0;*/

int _DYNAMIC = 0;

char *argv = "";

#include <stdio.h>

int initialize(void *d, void *main, void *init) {
	_DYNAMIC = d;

	/*exit(1);*/
	asm(
			"mov %0,%%rdi;"    // main
			/*"xor %%rdi,%%rdi;"    // main*/
			"mov %2,%%rcx;"    // _init
			"xor %%rsi,%%rsi;" // argc = 0
			"mov %1,%%rdx;"    // argv
			"xor %%r8,%%r8;"   // _fini = 0
			"xor %%r9,%%r9;"   // atexit fn = 0
			"call __libc_start_main;"
			:
			:"r" (main), "r" (argv), "r" (init)
			:"%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"
			);
	/*_start(0,0);*/
	return 0;
}

int main() {
	/*printf("asdf");*/
	/*fflush(stdin);*/
	return 0;
}

