/* Copyright 2011-2012 Nicholas J. Kain, licensed under standard MIT license */
#include <setjmp.h>
int setjmp(jmp_buf env)
{
        __asm__ __volatile (
	"movl %%rbx,(%%rdi)\n\t"         /* rdi is jmp_buf, move registers onto it */
	"movl %%rbp,8(%%rdi)\n\t"
	"movl %%r12,16(%%rdi)\n\t"
	"movl %%r13,24(%%rdi)\n\t"
	"movl %%r14,32(%%rdi)\n\t"
	"movl %%r15,40(%%rdi)\n\t"
	"lea 8(%%rsp),%%rdx\n\t"        /* this is our rsp WITHOUT current ret addr */
	"movl %%rdx,48(%%rdi)\n\t"
	"movl (%%rsp),%%rdx\n\t"         /* save return addr ptr for new rip */
	"movl %%rdx,56(%%rdi)\n\t"
	"xor %%rax,%%rax\n\t"           /* always return 0 */
	"ret\n\t"
        );
}
