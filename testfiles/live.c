long global_int = 0;
long global_int2 = 1;
int global_int3 = 0;

long simple_function() {
	return 1;
}

long func2(long x) {
	/*return 10+x+global_int;*/
	return x+1;
}

long call_live(long x) {
	global_int3 = 3;
	//return (long)&global_int;// + func2(x+2);
	return global_int2+global_int3+10+x;
	/*return 1;*/
}

