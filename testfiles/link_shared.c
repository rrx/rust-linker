#include <zlib.h>

void *call_z() {
	return gzopen("asdf", "r");
}
