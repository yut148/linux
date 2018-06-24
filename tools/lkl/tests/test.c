#include <lib_printf.h>

#include "test.h"

#define CLOCKS_PER_SEC 1000

/* circular log buffer */

static char log_buf[0x10000];
static char *head = log_buf, *tail = log_buf;

static inline void advance(char **ptr)
{
	if ((unsigned int)(*ptr - log_buf) >= sizeof(log_buf))
		*ptr = log_buf;
	else
		*ptr = *ptr + 1;
}

static void log_char(char c)
{
	*tail = c;
	advance(&tail);
	if (tail == head)
		advance(&head);
}

static void print_log(void)
{
	char last;

	printf(" log: |\n");
	last = '\n';
	while (head != tail) {
		if (last == '\n')
			printf("  ");
		last = *head;
                printf("%c", last);
		advance(&head);
	}
	if (last != '\n')
		printf("\n");
}

int lkl_test_run(const struct lkl_test *tests, int nr, const char *fmt, ...)
{
	int i, ret, status = TEST_SUCCESS;
	u64 start, stop;
	char name[1024];
	va_list args;

	va_start(args, fmt);
	vsnprintf(name, sizeof(name), fmt, args);
	va_end(args);

	printf("1..%d # %s\n", nr, name);
	for (i = 1; i <= nr; i++) {
		const struct lkl_test *t = &tests[i-1];
		unsigned long delta_us;

		printf("* %d %s\n", i, t->name);

		start = 0;

		ret = t->fn(t->arg1, t->arg2, t->arg3);

		stop = 10;

		switch (ret) {
		case TEST_SUCCESS:
			printf("ok %d %s\n", i, t->name);
			break;
		case TEST_SKIP:
			printf("ok %d %s # SKIP\n", i, t->name);
			break;
		case TEST_BAILOUT:
			status = TEST_BAILOUT;
			/* fall through */
		case TEST_FAILURE:
		default:
			if (status != TEST_BAILOUT)
				status = TEST_FAILURE;
			printf("not ok %d %s\n", i, t->name);
		}

		printf(" ---\n");
		delta_us = (stop - start) * 1000000 / CLOCKS_PER_SEC;
		printf(" time_us: %ld\n", delta_us);
		print_log();
		printf(" ...\n");

		if (status == TEST_BAILOUT) {
			printf("Bail out!\n");
			return TEST_FAILURE;
		}

	}

	return status;
}


void lkl_test_log(const char *str, int len)
{
	while (len--)
		log_char(*(str++));
}

int lkl_test_logf(const char *fmt, ...)
{
	__builtin_va_start(args, fmt);
	printf(fmt, args);
	__builtin_va_end(args);

        return 0;
}
