#include <lk/kernel/thread.h>
#include <lk/kernel/timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef __EMSCRIPTEN__
#include <stdlib.h>
#include <emscripten.h>
#include <lk/arch/emscripten.h>
#endif

struct thread *_current_thread = NULL;
int ints_enabled = 0;
int fiqs_enabled = 0;

static void initial_thread_func(void)
{
    int ret;

    /* release the thread lock that was implicitly held across the reschedule */
    spin_unlock(&thread_lock);

    thread_t *ct = get_current_thread();
    ret = ct->entry(ct->arg);

    thread_exit(ret);
}

void arch_thread_initialize(struct thread* t) {
#ifdef __EMSCRIPTEN__
    // create a default stack frame on the stack
    addr_t stack_top = (addr_t)t->stack + t->stack_size;

    struct emscripten_context_switch_frame *frame = (struct emscripten_context_switch_frame *)(stack_top);

    // move down a frame size and zero it out
    frame--;
    memset(frame, 0, sizeof(*frame));

    frame->sp = (addr_t) &initial_thread_func;

    // set the stack pointer
    t->arch.sp = (addr_t)frame;
#else
    // init context
    getcontext(&t->arch.context);

    // set stack
    t->arch.context.uc_stack.ss_sp = t->stack;
    t->arch.context.uc_stack.ss_size = t->stack_size;
    t->arch.context.uc_stack.ss_flags = 0;

    // disable return
    t->arch.context.uc_link = NULL;

    // set entrypoint
    makecontext(&t->arch.context, initial_thread_func, 0);
#endif /* __EMSCRIPTEN__ */
}

void arch_context_switch(struct thread *oldthread, struct thread *newthread) {
#ifdef __EMSCRIPTEN__
    // swap context
    EM_ASM_({
        var $vararg_buffer = 0;
        var sp = 0;
        sp = STACKTOP;
        STACKTOP = STACKTOP + 4|0; if ((STACKTOP|0) >= (STACK_MAX|0)) abortStackOverflow(4|0);
        vararg_buffer = sp + 4|0;
        // push old sp
        HEAP32[$vararg_buffer>>2] = $0;
        // load new sp
        STACKTOP = $1;
    }, oldthread->arch.sp, newthread->arch.sp);

#else
    swapcontext(&oldthread->arch.context, &newthread->arch.context);
#endif
}

void arch_idle(void) {
    thread_preempt();
}

void arch_dump_thread(thread_t *t) {

}

#if 0
void timer_initialize(lk_timer_t *timer) {
    assert(0);
}
void timer_set_oneshot(lk_timer_t *timer, lk_time_t delay, timer_callback callback, void *arg) {
    assert(0);
}
void timer_cancel(lk_timer_t *timer) {
    assert(0);
}
void timer_set_periodic(lk_timer_t *timer, lk_time_t period, timer_callback callback, void *arg) {
    assert(0);
}
#endif
