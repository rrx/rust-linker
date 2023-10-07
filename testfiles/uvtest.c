#include <stdio.h>
#include <stdlib.h>
#include <uv.h>

uv_loop_t *loop;

int init() {
    loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
}

int step() {
    return uv_run(loop, UV_RUN_ONCE);
}

int cleanup() {
    uv_loop_close(loop);
    free(loop);
}

int uvtest() {
    init();
    printf("Now quitting.\n");
    uv_run(loop, UV_RUN_DEFAULT);
    cleanup();
    return 0;
}
