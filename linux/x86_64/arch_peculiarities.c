#include "arch_regs.h"

static void
test_arch_peculiarities(void)
{
	is_x32_enabled = (getpid() == syscall(__NR_getpid | __X32_SYSCALL_BIT));
}
