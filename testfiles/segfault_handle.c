// See: https://feepingcreature.github.io/handling.html
//
#define __USE_GNU
#include <ucontext.h>
#include <signal.h>
#include <stdio.h>

void seghandle_userspace() {
  // note: because we set up a proper stackframe,
  // unwinding is safe from here.
  // also, by the time this function runs, the
  // operating system is "done" with the signal.

  // choose language-appropriate throw instruction
  // raise new MemoryAccessError "Segmentation Fault";
  // throw new MemoryAccessException;
  // longjmp(erroneous_exit);
  // asm { int 3; }
  /**(int*) NULL = 0;*/
  fprintf(stderr, "handled\n");
}

enum X86Registers {
  GS = 0, FS, ES, DS, EDI, ESI, EBP, ESP, EBX, EDX, ECX, EAX,
  TRAPNO, ERR, EIP, CS, EFL, UESP, SS
};

void seghandle(int sig, void* si, void* unused) {
  ucontext_t* uc = (ucontext_t*) unused;
  // No. I refuse to use triple-pointers.
  // Just pretend ref a = v; is V* ap = &v;
  // and then substitute a with (*ap).
  gregset_t *gregs = &uc->uc_mcontext.gregs;
  long *eip = (void*) gregs[EIP];
  long **esp = (void**) gregs[ESP];

  // imitate the effects of "call seghandle_userspace"
  esp --; // decrement stackpointer.
          // remember: stack grows down!
  *esp = eip;

  // set up OS for call via return, like in the attack
  eip = (void*) &seghandle_userspace;
}

void setup_segfault_handler() {
  struct sigaction sa;

  sigemptyset (&sa.sa_mask);
  sa.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
  sa.sa_sigaction = &seghandle;
  if (sigaction(SIGSEGV, &sa, 0x0) == -1) {
    fprintf(stderr, "failed to setup SIGSEGV handler\n");
    exit(1);
  }
}

int main() {
  setup_segfault_handler();
  *(int*) NULL = 0;
}
