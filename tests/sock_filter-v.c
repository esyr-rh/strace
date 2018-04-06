/*
 * Check decoding of socket filters.
 *
 * Copyright (c) 2017 Dmitry V. Levin <ldv@altlinux.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tests.h"

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/filter.h>

#if defined __alpha__ || defined __hppa__ || defined __mips__ \
	|| defined __sparc__
# define SOL_SOCKET_EXPECTED 0xffff
#else
# define SOL_SOCKET_EXPECTED 0x1
#endif

#ifdef SOL_SOCKET
# if SOL_SOCKET != SOL_SOCKET_EXPECTED
#  error "Unexpected value of SOL_SOCKET"
# endif
# undef SOL_SOCKET
#endif /* SOL_SOCKET */
#define SOL_SOCKET SOL_SOCKET_EXPECTED

#if defined __hppa__
# define SO_ATTACH_FILTER_EXPECTED 0x401a
#else
# define SO_ATTACH_FILTER_EXPECTED 0x1a
#endif

#ifdef SO_ATTACH_FILTER
# if SO_ATTACH_FILTER != SO_ATTACH_FILTER_EXPECTED
#  error "Unexpected value of SO_ATTACH_FILTER"
# endif
# undef SO_ATTACH_FILTER
#endif /* SO_ATTACH_FILTER */
#define SO_ATTACH_FILTER SO_ATTACH_FILTER_EXPECTED

#if defined __hppa__
# define SO_ATTACH_REUSEPORT_CBPF_EXPECTED 0x402c
#elif defined __sparc__
# define SO_ATTACH_REUSEPORT_CBPF_EXPECTED 0x35
#else
# define SO_ATTACH_REUSEPORT_CBPF_EXPECTED 0x33
#endif

#ifdef SO_ATTACH_REUSEPORT_CBPF
# if SO_ATTACH_REUSEPORT_CBPF != SO_ATTACH_REUSEPORT_CBPF_EXPECTED
#  error "Unexpected value of SO_ATTACH_REUSEPORT_CBPF"
# endif
# undef SO_ATTACH_REUSEPORT_CBPF
# define SO_ATTACH_REUSEPORT_CBPF SO_ATTACH_REUSEPORT_CBPF_EXPECTED
#endif /* SO_ATTACH_REUSEPORT_CBPF */

#ifdef BPF_LD
# if BPF_LD != 0x00
#  error "Unexpected value of BPF_LD"
# endif
# undef BPF_LD
#endif /* BPF_LD */
#define BPF_LD 0

#ifdef BPF_K
# if BPF_K != 0x00
#  error "Unexpected value of BPF_K"
# endif
# undef BPF_K
#endif /* BPF_K */
#define BPF_K 0

#ifdef BPF_W
# if BPF_W != 0x00
#  error "Unexpected value of BPF_W"
# endif
# undef BPF_W
#endif /* BPF_W */
#define BPF_W 0

#ifdef BPF_JMP
# if BPF_JMP != 0x05
#  error "Unexpected value of BPF_JMP"
# endif
# undef BPF_JMP
#endif /* BPF_JMP */
#define BPF_JMP 0x5

#ifdef BPF_RET
# if BPF_RET != 0x06
#  error "Unexpected value of BPF_RET"
# endif
# undef BPF_RET
#endif /* BPF_RET */
#define BPF_RET 0x6

#ifdef SKF_LL_OFF
# if SKF_LL_OFF != -0x200000
#  error "Unexpected value of SKF_LL_OFF"
# endif
# undef SKF_LL_OFF
#endif /* SKF_LL_OFF */
#define SKF_LL_OFF 0xffe00000

#ifdef SKF_NET_OFF
# if SKF_NET_OFF != -0x100000
#  error "Unexpected value of SKF_NET_OFF"
# endif
# undef SKF_NET_OFF
#endif /* SKF_NET_OFF */
#define SKF_NET_OFF 0xfff00000

#ifdef SKF_AD_OFF
# if SKF_AD_OFF != -0x1000
#  error "Unexpected value of SKF_AD_OFF"
# endif
# undef SKF_AD_OFF
#endif /* SKF_AD_OFF */
#define SKF_AD_OFF 0xfffff000

#define STR(a_) #a_
#if XLAT_RAW
# define STR1(a_) STR(a_)
# define STR2(a_, b_) STR(a_) "|" STR(b_)
# define STR3(a_, b_, c_) STR(a_) "|" STR(b_) "|" STR(c_)
#elif XLAT_VERBOSE
# define STR1(a_) STR(a_) " /* " #a_ " */"
# define STR2(a_, b_) STR(a_) " /* " #a_ " */|" STR(b_) " /* " #b_ " */"
# define STR3(a_, b_, c_) \
	STR(a_) " /* " #a_ " */|" STR(b_) " /* " #b_ " */|" STR(c_) " /* " #c_ " */"
#else
# define STR1(a_) #a_
# define STR2(a_, b_) #a_ "|" #b_
# define STR3(a_, b_, c_) #a_ "|" #b_ "|" #c_
#endif

#define PRINT_STMT_SYM(pfx, code, k)	\
	printf("%sBPF_STMT(%s, %s)", pfx, code, k)
#define PRINT_STMT_VAL(pfx, code, k)	\
	printf("%sBPF_STMT(%s, %#x)", pfx, code, k)

#define PRINT_JUMP(pfx, code, k, jt, jf) \
	printf("%sBPF_JUMP(%s, %#x, %#x, %#x)", pfx, code, k, jt, jf)

static const struct sock_filter bpf_filter[] = {
	BPF_STMT(BPF_LD|BPF_B|BPF_ABS, SKF_LL_OFF+4),
	BPF_STMT(BPF_LD|BPF_B|BPF_ABS, SKF_NET_OFF+8),
	BPF_STMT(BPF_LD|BPF_B|BPF_ABS, SKF_AD_OFF+SKF_AD_PROTOCOL),
	BPF_JUMP(BPF_JMP|BPF_K|BPF_JEQ, IPPROTO_UDP, 0, 5),
	BPF_STMT(BPF_LD|BPF_W|BPF_LEN, 0),
	BPF_JUMP(BPF_JMP|BPF_K|BPF_JGE, 100, 0, 3),
	BPF_STMT(BPF_LD|BPF_B|BPF_ABS, 42),
	BPF_JUMP(BPF_JMP|BPF_K|BPF_JEQ, 'a', 0, 1),
	BPF_STMT(BPF_RET|BPF_K, -1U),
	BPF_STMT(BPF_RET|BPF_K, 0)
};

static void
print_filter(void)
{
	PRINT_STMT_SYM("[", STR3(BPF_LD, BPF_B, BPF_ABS),
		       STR1(SKF_LL_OFF) STR(+4));
	PRINT_STMT_SYM(", ", STR3(BPF_LD, BPF_B, BPF_ABS),
		       STR1(SKF_NET_OFF) STR(+8));
	PRINT_STMT_SYM(", ", STR3(BPF_LD, BPF_B, BPF_ABS),
		       STR1(SKF_AD_OFF) STR(+) STR1(SKF_AD_PROTOCOL));
	PRINT_JUMP(", ", STR3(BPF_JMP, BPF_K, BPF_JEQ), IPPROTO_UDP, 0, 5);
	PRINT_STMT_VAL(", ", STR3(BPF_LD, BPF_W, BPF_LEN), 0);
	PRINT_JUMP(", ", STR3(BPF_JMP, BPF_K, BPF_JGE), 100, 0, 3);
	PRINT_STMT_VAL(", ", STR3(BPF_LD, BPF_B, BPF_ABS), 42);
	PRINT_JUMP(", ", STR3(BPF_JMP, BPF_K, BPF_JEQ), 'a', 0, 1);
	PRINT_STMT_VAL(", ", STR2(BPF_RET, BPF_K), -1U);
	PRINT_STMT_VAL(", ", STR2(BPF_RET, BPF_K), 0);
	putchar(']');
}

static const char *errstr;

static int
get_filter(int fd, void *val, socklen_t *len)
{
	int rc = getsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, val, len);
	errstr = sprintrc(rc);
	return rc;
}

static int
set_filter(int fd, void *val, socklen_t len)
{
	int rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, val, len);
	errstr = sprintrc(rc);
	return rc;
}

int
main(void)
{
	int rc;
	struct sock_filter *const filter =
		tail_memdup(bpf_filter, sizeof(bpf_filter));
	void *const efault = filter + ARRAY_SIZE(bpf_filter);
	TAIL_ALLOC_OBJECT_CONST_PTR(struct sock_fprog, prog);
	TAIL_ALLOC_OBJECT_CONST_PTR(socklen_t, len);

	prog->len = ARRAY_SIZE(bpf_filter);
	prog->filter = filter;

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		perror_msg_and_skip("socket AF_INET SOCK_DGRAM");

	/* query sock_filter program length -> 0 */
	*len = BPF_MAXINSNS;
	rc = get_filter(fd, NULL, len);
	if (rc)
		perror_msg_and_skip("getsockopt SOL_SOCKET SO_ATTACH_FILTER");
	printf("getsockopt(%d, %s, %s, NULL, [%u->0]) = 0\n",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), BPF_MAXINSNS);

	/* getsockopt NULL optlen - EFAULT */
	rc = get_filter(fd, NULL, NULL);
	printf("getsockopt(%d, %s, %s, NULL, NULL) = %s\n",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), errstr);

	/* attach a filter */
	rc = set_filter(fd, prog, sizeof(*prog));
	if (rc)
		perror_msg_and_skip("setsockopt SOL_SOCKET SO_ATTACH_FILTER");
	printf("setsockopt(%d, %s, %s, {len=%u, filter=",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), prog->len);
	print_filter();
	printf("}, %u) = 0\n", (unsigned int) sizeof(*prog));

	/* setsockopt optlen is too small - EINVAL */
	rc = set_filter(fd, prog, sizeof(*prog) - 4);
	printf("setsockopt(%d, %s, %s, %p, %u) = %s\n",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), prog,
	       (unsigned int) sizeof(*prog) - 4, errstr);

#ifdef SO_ATTACH_REUSEPORT_CBPF
	rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF,
			prog, sizeof(*prog));
	errstr = sprintrc(rc);
	printf("setsockopt(%d, %s, %s, {len=%u, filter=",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_REUSEPORT_CBPF), prog->len);
	print_filter();
	printf("}, %u) = %s\n", (unsigned int) sizeof(*prog), errstr);
#endif

	/* query sock_filter program length -> ARRAY_SIZE(bpf_filter) */
	*len = 0;
	rc = get_filter(fd, efault, len);
	printf("getsockopt(%d, %s, %s, %p, [0->%u]) = %s\n",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), efault,
	       (unsigned int) ARRAY_SIZE(bpf_filter), errstr);

	/* getsockopt optlen is too small - EINVAL */
	*len = ARRAY_SIZE(bpf_filter) - 1;
	rc = get_filter(fd, efault, len);
	printf("getsockopt(%d, %s, %s, %p, [%u]) = %s\n",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), efault,
	       (unsigned int) ARRAY_SIZE(bpf_filter) - 1, errstr);

	/* getsockopt optval EFAULT */
	*len = ARRAY_SIZE(bpf_filter);
	rc = get_filter(fd, filter + 1, len);
	printf("getsockopt(%d, %s, %s, %p, [%u]) = %s\n",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER), filter + 1,
	       (unsigned int) ARRAY_SIZE(bpf_filter), errstr);

	/* getsockopt optlen is too large - truncated */
	*len = ARRAY_SIZE(bpf_filter) + 1;
	rc = get_filter(fd, filter, len);
	printf("getsockopt(%d, %s, %s, ",
	       fd, STR1(SOL_SOCKET), STR1(SO_ATTACH_FILTER));
	print_filter();
	printf(", [%u->%d]) = %s\n",
	       (unsigned int) ARRAY_SIZE(bpf_filter) + 1, *len, errstr);

	puts("+++ exited with 0 +++");
	return 0;
}
