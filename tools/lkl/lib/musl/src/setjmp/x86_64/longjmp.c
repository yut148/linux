/* Copyright 2011-2012 Nicholas J. Kain, licensed under standard MIT license */
#include <setjmp.h>

void logjmp(jmp_buf env, int val)
{
	__asm__ __volatile__ (
        "movl %%rsi,%%rax\n\t"           /* val will be longjmp return */
	"test %%rax,%%rax\n\t"
	"jnz 1f\n\t"
	"inc %%rax\n\t"                /* if val==0, val=1 per longjmp semantics */
        "1:\n\t"
	"movl (%%rdi),%%rbx\n\t"         /* rdi is the jmp_buf, restore regs from it */
	"movl 8(%%rdi),%%rbp\n\t"
	"movl 16(%%rdi),%%r12\n\t"
	"movl 24(%%rdi),%%r13\n\t"
	"movl 32(%%rdi),%%r14\n\t"
	"movl 40(%%rdi),%%r15\n\t"
	"movl 48(%%rdi),%%rdx\n\t"       /* this ends up being the stack pointer */
	"movl %%rdx,%%rsp\n\t"
	"movl 56(%%rdi),%%rdx\n\t"       /* this is the instruction pointer */
	"jmp *%%rdx\n\t"               /* goto saved address without altering rsp */
        );
}
