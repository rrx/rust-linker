#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

void invoke_method()
{
	void *dl_handle;
	int (*func)(int, FILE*);
	char *error;
    	
	char *lib = "/usr/lib/x86_64-linux-musl/libc.so";

	/* Open the shared object */
	dl_handle = dlopen(lib, RTLD_LAZY );
	if (!dl_handle) {
		printf( "!!! %s\n", dlerror() );
		return;
	}
	/* Resolve stdout */
	FILE **stdout_sym = (FILE *) dlsym( dl_handle, "stdout" );
	printf("stdout: 0x%08x\n", *stdout_sym);
	/*printf("stdout: 0x%08x\n", *stdout_sym);*/

	long long **s1 = stdout;
	printf("stdout: 0x%16x\n", stdout);
	printf("stdout: 0x%08x\n", *s1);

	/* Resolve the symbol (method) from the object */
	func = dlsym( dl_handle, "fputc" );
	error = dlerror();
	if (error != NULL) {
		printf( "!!! %s\n", error );
		return;
	}

	/* Call the resolved method and print the result */
	printf("%x\n", (*func)(0x30, *stdout_sym));

	/* Close the object */
	dlclose( dl_handle );

	return;
}


int main( int argc, char *argv[] )
{
	invoke_method();
	return 0;
}
