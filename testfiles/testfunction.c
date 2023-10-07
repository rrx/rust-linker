extern long asdf(long);

long testinternal() {
	return 10001;
}

long call_external() {
	return 1 + asdf(2);
}

long testfunction() {
	return 1 + 10 + testinternal();
}
