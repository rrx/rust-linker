// load globals from an external
char x = 0x34;
char *ptr = &x;

// not in shared library
extern long g2;

// in shared library
extern long global_int2;
extern void callme(void);

long load_from_extern() {
	callme();
	return 1 + x + global_int2 + g2;
}

