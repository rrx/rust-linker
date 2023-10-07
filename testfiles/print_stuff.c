#include <stdio.h>

const char *g_str1 = "0xx\n";
const char *g_str2 = "13334x\n";
int g_v = 10;

int print_stuff1() {
	return 1;
}

int print_stuff2(char *str, int val) {
	return g_v+1+val;
}

int print_stuff3(int val) {
	return g_v+strlen(g_str1);
}

int print_stuff4(char *str, int val) {
	fputs("fffff", stdout);
	fflush(stdout);
	return 0;
	printf("yyyy: %s xxxx\n", g_str1);
	printf("zzzz: %s xxxx\n", g_str2);
	printf(g_str1);
	printf(g_str2);
	int ret0 = printf(str, val);
	return g_v+1;
	/*int ret1 = fprintf(stdout, "printing stuff\n");*/
	char *s = "1111\n";
	int ret1 = printf(s);
	int ret2 = printf("2222\n");
	putc(0x31, stdout);
	fflush(stdout);
	int len = strlen("asdf");
	int ret3 = putc(0x30, stderr);
	fflush(stderr);

	return ret1 + ret2 + len;

}

void *get_v() {
	return &g_v;
}

void *get_str1() {
	return &g_str1;
}

void *get_str2() {
	return &g_str2;
}

