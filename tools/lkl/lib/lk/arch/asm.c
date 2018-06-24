/*
 * Copyright (c) 2015 Travis Geiselbrecht
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <lk/arch/x86.h>

/* void x86_64_context_switch(uint64_t *oldsp, uint64_t newsp) */
void x86_64_context_switch(uint64_t *oldsp, uint64_t newsp)
{
    /* save the old context and restore the new */
    __asm__ __volatile__ (
    "pushf\n\t"
    "pushq %%rbx\n\t"
    "pushq %%rbp\n\t"
    "pushq %%r12\n\t"
    "pushq %%r13\n\t"
    "pushq %%r14\n\t"
    "pushq %%r15\n\t"

    "movq %%rsp,(%%rdi)\n\t"
    "movq %%rsi,%%rsp\n\t"

    "popq %%r15\n\t"
    "popq %%r14\n\t"
    "popq %%r13\n\t"
    "popq %%r12\n\t"
    "popq %%rbp\n\t"
    "popq %%rbx\n\t"
    "popf\n\t"

    "retq\n\t"
    );
}
