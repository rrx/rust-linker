extern long g1;
extern void callme(void);

// Tell the compiler incoming stack alignment is not RSP%16==8 or ESP%16==12
__attribute__((force_align_arg_pointer))
void _start() {

    /* main body of program: call main(), etc */
    /*long x = g1;*/
    /*callme();*/

    /* exit system call */
    asm("movl $1,%eax;"
        "xorl %ebx,%ebx;"
        "int  $0x80"
    );
    __builtin_unreachable();  // tell the compiler to make sure side effects are done before the asm statement
}

