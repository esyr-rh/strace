#include <asm/unistd.h>

#ifdef __NR_getcwd

# include <limits.h>
# include <stdio.h>
# include <unistd.h>

# ifndef CUR_PERSONALITY
#  define CUR_PERSONALITY 0
# endif

int
main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s personality", argv[0]);
		_exit(1);
	}

	syscall(__NR_getcwd, NULL, 0);
	if ((argv[1][0] - '0') & (1 << CUR_PERSONALITY)) {
		printf("getcwd(NULL, 0) = -1 ERANGE (%m)\n");
		fflush(stdout);
	}

#if CUR_PERSONALITY < 1
	execl("../getcwd_m32", "getcwd_m32", argv[1], NULL);
#endif

#if CUR_PERSONALITY < 2
	execl("../getcwd_mx32", "getcwd_mx32", argv[1], NULL);
#endif

	puts("+++ exited with 0 +++");

	return 0;
}

#else

SKIP_MAIN_UNDEFINED("__NR_getcwd");

#endif
