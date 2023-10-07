#include <stdio.h>

void *print_string() {
	char *s = "fffff\n";
	fputs(s, stdout);
	printf("amazing\n");
	fflush(stdout);
	return s;
}

