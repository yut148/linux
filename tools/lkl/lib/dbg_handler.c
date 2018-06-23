#include <core/printf.h>
#include <lkl_host.h>

extern void dbg_entrance();
static int dbg_running = 0;

static void dbg_thread(void* arg) {
	lkl_host_ops.thread_detach();
	printf("======Enter Debug======\n");
	dbg_entrance();
	printf("======Exit Debug======\n");
	dbg_running = 0;
}

void dbg_handler(int signum) {
	/* We don't care about the possible race on dbg_running. */
	if (dbg_running) {
		printf("A debug lib is running\n");
		return;
	}
	dbg_running = 1;
	lkl_host_ops.thread_create(&dbg_thread, NULL);
}

void lkl_register_dbg_handler() {
	printf("lkl_register_dbg_handler is not implemented.\n");
}
