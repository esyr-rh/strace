/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-2000 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 2005-2016 Dmitry V. Levin <ldv@altlinux.org>
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

#include "defs.h"
#include "msghdr.h"
#include <arpa/inet.h>
#include <netinet/in.h>

#include "xlat/msg_flags.h"
#include "xlat/scmvals.h"
#include "xlat/ip_cmsg_types.h"

#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
struct cmsghdr32 {
	uint32_t cmsg_len;
	int cmsg_level;
	int cmsg_type;
};
#endif

typedef union {
	char *ptr;
	struct cmsghdr *cmsg;
#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
	struct cmsghdr32 *cmsg32;
#endif
} union_cmsghdr;

static void
print_scm_rights(struct tcb *tcp, const void *cmsg_data,
		 const size_t data_len)
{
	const int *fds = cmsg_data;
	const char *end = (const char *) cmsg_data + data_len;
	bool seen = false;

	if (sizeof(*fds) > data_len)
		return;

	tprints(", cmsg_data=[");
	while ((const char *) fds < end) {
		if (seen)
			tprints(", ");
		else
			seen = true;
		printfd(tcp, *fds++);
	}
	tprints("]");
}

static void
print_scm_creds(struct tcb *tcp, const void *cmsg_data,
		const size_t data_len)
{
	const struct ucred *uc = cmsg_data;

	if (sizeof(*uc) > data_len)
		return;

	tprintf(", cmsg_data={pid=%u, uid=%u, gid=%u}",
		(unsigned) uc->pid, (unsigned) uc->uid, (unsigned) uc->gid);
}

static void
print_scm_security(struct tcb *tcp, const void *cmsg_data,
		   const size_t data_len)
{
	if (!data_len)
		return;

	tprints(", cmsg_data=");
	print_quoted_string(cmsg_data, data_len, 0);
}

static void
print_cmsg_ip_pktinfo(struct tcb *tcp, const void *cmsg_data,
		      const size_t data_len)
{
	const struct in_pktinfo *info = cmsg_data;

	if (sizeof(*info) > data_len)
		return;

	tprints(", cmsg_data={ipi_ifindex=");
	print_ifindex(info->ipi_ifindex);
	tprintf(", ipi_spec_dst=inet_addr(\"%s\"), ipi_addr=inet_addr(\"%s\")}",
		inet_ntoa(info->ipi_spec_dst), inet_ntoa(info->ipi_addr));
}

static void
print_cmsg_ip_ttl(struct tcb *tcp, const void *cmsg_data,
		  const size_t data_len)
{
	const unsigned int *ttl = cmsg_data;

	if (sizeof(*ttl) > data_len)
		return;

	tprintf(", cmsg_data=[%u]", *ttl);
}

static void
print_cmsg_ip_tos(struct tcb *tcp, const void *cmsg_data,
		  const size_t data_len)
{
	const uint8_t *tos = cmsg_data;

	if (sizeof(*tos) > data_len)
		return;

	tprintf(", cmsg_data=[%#x]", *tos);
}

static void
print_cmsg_ip_checksum(struct tcb *tcp, const void *cmsg_data,
		       const size_t data_len)
{
	const uint32_t *csum = cmsg_data;

	if (sizeof(*csum) > data_len)
		return;

	tprintf(", cmsg_data=[%u]", *csum);
}

static void
print_cmsg_ip_opts(struct tcb *tcp, const void *cmsg_data,
		   const size_t data_len)
{
	const unsigned char *opts = cmsg_data;
	size_t i;

	if (!data_len)
		return;

	tprints(", cmsg_data=[");
	for (i = 0; i < data_len; ++i) {
		if (i)
			tprints(", ");
		tprintf("0x%02x", opts[i]);
	}
	tprints("]");
}

static void
print_cmsg_ip_recverr(struct tcb *tcp, const void *cmsg_data,
		      const size_t data_len)
{
	const struct {
		uint32_t ee_errno;
		uint8_t  ee_origin;
		uint8_t  ee_type;
		uint8_t  ee_code;
		uint8_t  ee_pad;
		uint32_t ee_info;
		uint32_t ee_data;
		struct sockaddr_in offender;
	} *err = cmsg_data;

	if (sizeof(*err) > data_len)
		return;

	tprintf(", cmsg_data={ee_errno=%u, ee_origin=%u, ee_type=%u, ee_code=%u"
		", ee_info=%u, ee_data=%u, offender=",
		err->ee_errno, err->ee_origin, err->ee_type,
		err->ee_code, err->ee_info, err->ee_data);
	print_sockaddr(tcp, &err->offender, sizeof(err->offender));
	tprints("}");
}

static void
print_cmsg_ip_origdstaddr(struct tcb *tcp, const void *cmsg_data,
			  const size_t data_len)
{
	if (sizeof(struct sockaddr_in) > data_len)
		return;

	tprints(", cmsg_data=");
	print_sockaddr(tcp, cmsg_data, data_len);
}

static void
print_cmsg_type_data(struct tcb *tcp, const int cmsg_level, const int cmsg_type,
		     const void *cmsg_data, const size_t data_len)
{
	switch (cmsg_level) {
	case SOL_SOCKET:
		printxval(scmvals, cmsg_type, "SCM_???");
		switch (cmsg_type) {
		case SCM_RIGHTS:
			print_scm_rights(tcp, cmsg_data, data_len);
			break;
		case SCM_CREDENTIALS:
			print_scm_creds(tcp, cmsg_data, data_len);
			break;
		case SCM_SECURITY:
			print_scm_security(tcp, cmsg_data, data_len);
			break;
		}
		break;
	case SOL_IP:
		printxval(ip_cmsg_types, cmsg_type, "IP_???");
		switch (cmsg_type) {
		case IP_PKTINFO:
			print_cmsg_ip_pktinfo(tcp, cmsg_data, data_len);
			break;
		case IP_TTL:
			print_cmsg_ip_ttl(tcp, cmsg_data, data_len);
			break;
		case IP_TOS:
			print_cmsg_ip_tos(tcp, cmsg_data, data_len);
			break;
		case IP_RECVOPTS:
		case IP_RETOPTS:
			print_cmsg_ip_opts(tcp, cmsg_data, data_len);
			break;
		case IP_RECVERR:
			print_cmsg_ip_recverr(tcp, cmsg_data, data_len);
			break;
		case IP_ORIGDSTADDR:
			print_cmsg_ip_origdstaddr(tcp, cmsg_data, data_len);
			break;
		case IP_CHECKSUM:
			print_cmsg_ip_checksum(tcp, cmsg_data, data_len);
			break;
		case SCM_SECURITY:
			print_scm_security(tcp, cmsg_data, data_len);
			break;
		}
		break;
	default:
		tprintf("%u", cmsg_type);
	}
}

static void
decode_msg_control(struct tcb *tcp, unsigned long addr, size_t len)
{
	const size_t cmsg_size =
#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
		(current_wordsize < sizeof(long)) ? sizeof(struct cmsghdr32) :
#endif
			sizeof(struct cmsghdr);

	if (!len)
		return;
	tprints(", msg_control=");

	char *buf = len < cmsg_size ? NULL : malloc(len);
	if (!buf || umoven(tcp, addr, len, buf) < 0) {
		printaddr(addr);
		free(buf);
		return;
	}

	union_cmsghdr u = { .ptr = buf };

	tprints("[");
	while (len >= cmsg_size) {
		size_t cmsg_len =
#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
			(current_wordsize < sizeof(long)) ? u.cmsg32->cmsg_len :
#endif
				u.cmsg->cmsg_len;
		int cmsg_level =
#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
			(current_wordsize < sizeof(long)) ? u.cmsg32->cmsg_level :
#endif
				u.cmsg->cmsg_level;
		int cmsg_type =
#if SUPPORTED_PERSONALITIES > 1 && SIZEOF_LONG > 4
			(current_wordsize < sizeof(long)) ? u.cmsg32->cmsg_type :
#endif
				u.cmsg->cmsg_type;

		if (u.ptr != buf)
			tprints(", ");
		tprintf("{cmsg_len=%lu, cmsg_level=", (unsigned long) cmsg_len);
		printxval(socketlayers, cmsg_level, "SOL_???");
		tprints(", cmsg_type=");

		if (cmsg_len > len)
			cmsg_len = len;

		print_cmsg_type_data(tcp, cmsg_level, cmsg_type,
				     (const void *) (u.ptr + cmsg_size),
				     cmsg_len > cmsg_size ? cmsg_len - cmsg_size: 0);
		tprints("}");

		if (cmsg_len < cmsg_size) {
			len -= cmsg_size;
			break;
		}
		cmsg_len = (cmsg_len + current_wordsize - 1) &
			(size_t) ~(current_wordsize - 1);
		if (cmsg_len >= len) {
			len = 0;
			break;
		}
		u.ptr += cmsg_len;
		len -= cmsg_len;
	}
	if (len)
		tprints(", ...");
	tprints("]");
	free(buf);
}

static void
print_msghdr(struct tcb *tcp, struct msghdr *msg, unsigned long data_size)
{
	tprints("{msg_name=");
	decode_sockaddr(tcp, (long)msg->msg_name, msg->msg_namelen);
	tprintf(", msg_namelen=%d", msg->msg_namelen);

	tprints(", msg_iov=");
	tprint_iov_upto(tcp, (unsigned long) msg->msg_iovlen,
			(unsigned long) msg->msg_iov, IOV_DECODE_STR, data_size);
	tprintf(", msg_iovlen=%lu", (unsigned long) msg->msg_iovlen);

	decode_msg_control(tcp, (unsigned long) msg->msg_control,
			   msg->msg_controllen);
	tprintf(", msg_controllen=%lu", (unsigned long) msg->msg_controllen);

	tprints(", msg_flags=");
	printflags(msg_flags, msg->msg_flags, "MSG_???");
	tprints("}");
}

void
decode_msghdr(struct tcb *tcp, long addr, unsigned long data_size)
{
	struct msghdr msg;

	if (addr && verbose(tcp) && fetch_struct_msghdr(tcp, addr, &msg))
		print_msghdr(tcp, &msg, data_size);
	else
		printaddr(addr);
}

void
dumpiov_in_msghdr(struct tcb *tcp, long addr, unsigned long data_size)
{
	struct msghdr msg;

	if (fetch_struct_msghdr(tcp, addr, &msg))
		dumpiov_upto(tcp, msg.msg_iovlen, (long)msg.msg_iov, data_size);
}

static int
decode_mmsghdr(struct tcb *tcp, long addr, bool use_msg_len)
{
	struct mmsghdr mmsg;
	int fetched = fetch_struct_mmsghdr(tcp, addr, &mmsg);

	if (fetched) {
		tprints("{msg_hdr=");
		print_msghdr(tcp, &mmsg.msg_hdr, use_msg_len ? mmsg.msg_len : -1UL);
		tprintf(", msg_len=%u}", mmsg.msg_len);
	} else {
		printaddr(addr);
	}

	return fetched;
}

void
decode_mmsgvec(struct tcb *tcp, unsigned long addr, unsigned int len,
	       bool use_msg_len)
{
	if (syserror(tcp)) {
		printaddr(addr);
	} else {
		unsigned int i, fetched;

		tprints("[");
		for (i = 0; i < len; ++i, addr += fetched) {
			if (i)
				tprints(", ");
			fetched = decode_mmsghdr(tcp, addr, use_msg_len);
			if (!fetched)
				break;
		}
		tprints("]");
	}
}

void
dumpiov_in_mmsghdr(struct tcb *tcp, long addr)
{
	unsigned int len = tcp->u_rval;
	unsigned int i, fetched;
	struct mmsghdr mmsg;

	for (i = 0; i < len; ++i, addr += fetched) {
		fetched = fetch_struct_mmsghdr(tcp, addr, &mmsg);
		if (!fetched)
			break;
		tprintf(" = %lu buffers in vector %u\n",
			(unsigned long)mmsg.msg_hdr.msg_iovlen, i);
		dumpiov_upto(tcp, mmsg.msg_hdr.msg_iovlen,
			(long)mmsg.msg_hdr.msg_iov, mmsg.msg_len);
	}
}