/*
 * Copyright (c) 2015-2017 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2017 Quentin Monnet <quentin.monnet@6wind.com>
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
#include "print_fields.h"

#ifdef HAVE_LINUX_BPF_H
# include <linux/bpf.h>
#endif
#include <linux/filter.h>

#include "xlat/bpf_commands.h"
#include "xlat/bpf_file_mode_flags.h"
#include "xlat/bpf_map_types.h"
#include "xlat/bpf_map_flags.h"
#include "xlat/bpf_prog_types.h"
#include "xlat/bpf_prog_flags.h"
#include "xlat/bpf_map_update_elem_flags.h"
#include "xlat/bpf_attach_type.h"
#include "xlat/bpf_attach_flags.h"
#include "xlat/bpf_query_flags.h"
#include "xlat/ebpf_regs.h"
#include "xlat/numa_node.h"

/** Storage for all the data that is needed to be stored on entering. */
struct bpf_priv_data {
	bool     bpf_obj_info_printed;

	bool     bpf_prog_info_stored;
	uint32_t bpf_prog_info_jited_prog_len;
	uint32_t bpf_prog_info_xlated_prog_len;
	uint32_t bpf_prog_info_nr_map_ids;

	bool     bpf_prog_query_stored;
	uint32_t bpf_prog_query_prog_cnt;
};

#define DECL_BPF_CMD_DECODER(bpf_cmd_decoder)				\
int									\
bpf_cmd_decoder(struct tcb *const tcp,					\
		const kernel_ulong_t addr,				\
		const unsigned int size,				\
		void *const data,					\
		struct bpf_priv_data *priv)				\
/* End of DECL_BPF_CMD_DECODER definition. */

#define DEF_BPF_CMD_DECODER(bpf_cmd)					\
	static DECL_BPF_CMD_DECODER(decode_ ## bpf_cmd)

#define BPF_CMD_ENTRY(bpf_cmd)						\
	[bpf_cmd] = decode_ ## bpf_cmd

#ifndef BPF_OBJ_NAME_LEN
# define BPF_OBJ_NAME_LEN 16U
#else
# if BPF_OBJ_NAME_LEN != 16U
#  error "Unexpected value of BPF_OBJ_NAME_LEN"
# endif
#endif

#ifndef BPF_TAG_SIZE
# define BPF_TAG_SIZE 8
#else
# if BPF_OBJ_TAG_SIZE != 8
#  error "Unexpected value of BPF_TAG_SIZE"
# endif
#endif

typedef DECL_BPF_CMD_DECODER((*bpf_cmd_decoder_t));

/*
 * A note about bpf syscall decoder: it doesn't perform any size sanity checks,
 * so if even it leads to partial copying of one of the fields, the command
 * handler will still use the (partially-copied-from-userspace, partially
 * zeroed) field value.  So, we try to handle it by interrupting the decoding
 * after every version of the structure used by the specific command (as it
 * looks like the most sensible way to parse this insanity).
 */

static int
decode_attr_extra_data(struct tcb *const tcp,
		       const char *data,
		       unsigned int size,
		       const size_t attr_size)
{
	if (size <= attr_size)
		return 0;

	data += attr_size;
	size -= attr_size;

	unsigned int i;
	for (i = 0; i < size; ++i) {
		if (data[i]) {
			if (abbrev(tcp)) {
				tprints(", ...");
			} else {
				tprintf(", /* bytes %zu..%zu */ ",
					attr_size, attr_size + size - 1);
				print_quoted_string(data, size,
						    QUOTE_FORCE_HEX);
			}
			return RVAL_DECODED;
		}
	}

	return 0;
}

struct ebpf_insn {
	uint8_t code;
	uint8_t dst_reg:4;
	uint8_t src_reg:4;
	int16_t off;
	int32_t imm;
};

struct ebpf_insns_data {
	unsigned int count;
};

static bool
print_ebpf_insn(struct tcb * const tcp, void * const elem_buf,
		const size_t elem_size, void * const data)
{
	struct ebpf_insns_data *eid = data;
	struct ebpf_insn *insn = elem_buf;

	if (eid->count++ >= BPF_MAXINSNS) {
		tprints("...");
		return false;
	}

	tprints("{code=");
	print_bpf_filter_code(insn->code, true);

	/* We can't use PRINT_FIELD_XVAL on bit fields */
	tprints(", dst_reg=");
	printxval(ebpf_regs, insn->dst_reg, "BPF_REG_???");
	tprints(", src_reg=");
	printxval(ebpf_regs, insn->src_reg, "BPF_REG_???");

	PRINT_FIELD_D(", ", *insn, off);
	PRINT_FIELD_X(", ", *insn, imm);
	tprints("}");

	return true;
}

void
print_ebpf_prog(struct tcb *const tcp, const kernel_ulong_t addr,
		const uint32_t len)
{
	if (abbrev(tcp)) {
		printaddr(addr);
	} else {
		struct ebpf_insns_data eid = {};
		struct ebpf_insn insn;

		print_array(tcp, addr, len, &insn, sizeof(insn),
			    umoven_or_printaddr, print_ebpf_insn, &eid);
	}
}

DEF_BPF_CMD_DECODER(BPF_MAP_CREATE)
{
	struct bpf_map_desc {
		uint32_t map_type, key_size, value_size, max_entries,
			 map_flags, inner_map_fd, numa_node;
		char     map_name[BPF_OBJ_NAME_LEN];
		uint32_t map_ifindex;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_map_desc, map_ifindex);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_XVAL("{", attr, map_type, bpf_map_types,
			 "BPF_MAP_TYPE_???");
	PRINT_FIELD_U(", ", attr, key_size);
	PRINT_FIELD_U(", ", attr, value_size);
	PRINT_FIELD_U(", ", attr, max_entries);
	if (LE_CLAMP(len, offsetofend(struct bpf_map_desc, max_entries)))
		goto bpf_map_create_end;

	/* map_flags field was added in Linux commit v4.6-rc1~91^2~108^2~6. */
	PRINT_FIELD_FLAGS(", ", attr, map_flags, bpf_map_flags, "BPF_F_???");
	if (LE_CLAMP(len, offsetofend(struct bpf_map_desc, map_flags)))
		goto bpf_map_create_end;

	/*
	 * inner_map_fd field was added in Linux commit
	 * v4.12-rc1~64^3~373^2~2.
	 */
	PRINT_FIELD_FD(", ", attr, inner_map_fd, tcp);
	if (LE_CLAMP(len, offsetofend(struct bpf_map_desc, inner_map_fd)))
		goto bpf_map_create_end;

	/* numa_node field was added in Linux commit v4.14-rc1~130^2~196^2~1. */
	if (attr.map_flags & BPF_F_NUMA_NODE)
		PRINT_FIELD_XVAL(", ", attr, numa_node, numa_node, NULL);
	if (LE_CLAMP(len, offsetofend(struct bpf_map_desc, numa_node)))
		goto bpf_map_create_end;

	/* map_name field was added in Linux commit v4.15-rc1~84^2~605^2~3. */
	PRINT_FIELD_CSTRING(", ", attr, map_name);
	if (LE_CLAMP(len, offsetofend(struct bpf_map_desc, map_name)))
		goto bpf_map_create_end;

	/*
	 * map_ifindex field was added in Linux commit
	 * v4.16-rc1~123^2~145^2~5^2~8.
	 */
	PRINT_FIELD_IFINDEX(", ", attr, map_ifindex);

	decode_attr_extra_data(tcp, data, size, attr_size);

bpf_map_create_end:
	tprints("}");

	return RVAL_DECODED | RVAL_FD;
}

DEF_BPF_CMD_DECODER(BPF_MAP_LOOKUP_ELEM)
{
	struct bpf_io_elem_struct {
		uint32_t map_fd;
		uint64_t ATTRIBUTE_ALIGNED(8) key, value;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_io_elem_struct, value);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{", attr, map_fd, tcp);
	PRINT_FIELD_X(", ", attr, key);
	PRINT_FIELD_X(", ", attr, value);
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_MAP_UPDATE_ELEM)
{
	struct bpf_update_elem {
		uint32_t map_fd;
		uint64_t ATTRIBUTE_ALIGNED(8) key;
		uint64_t ATTRIBUTE_ALIGNED(8) value;
		uint64_t flags;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_update_elem, flags);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{", attr, map_fd, tcp);
	PRINT_FIELD_X(", ", attr, key);
	PRINT_FIELD_X(", ", attr, value);
	PRINT_FIELD_XVAL(", ", attr, flags, bpf_map_update_elem_flags,
			 "BPF_???");
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_MAP_DELETE_ELEM)
{
	struct bpf_delete_elem {
		uint32_t map_fd;
		uint64_t ATTRIBUTE_ALIGNED(8) key;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_delete_elem, key);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{", attr, map_fd, tcp);
	PRINT_FIELD_X(", ", attr, key);
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_MAP_GET_NEXT_KEY)
{
	struct bpf_io_elem_struct {
		uint32_t map_fd;
		uint64_t ATTRIBUTE_ALIGNED(8) key, next_key;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_io_elem_struct, next_key);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{", attr, map_fd, tcp);
	PRINT_FIELD_X(", ", attr, key);
	PRINT_FIELD_X(", ", attr, next_key);
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_PROG_LOAD)
{
	struct bpf_prog_load {
		uint32_t prog_type, insn_cnt;
		uint64_t ATTRIBUTE_ALIGNED(8) insns, license;
		uint32_t log_level, log_size;
		uint64_t ATTRIBUTE_ALIGNED(8) log_buf;
		uint32_t kern_version, prog_flags;
		char     prog_name[BPF_OBJ_NAME_LEN];
		uint32_t prog_ifindex;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_prog_load, prog_ifindex);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_XVAL("{", attr, prog_type, bpf_prog_types,
			 "BPF_PROG_TYPE_???");
	PRINT_FIELD_U(", ", attr, insn_cnt);
	tprints(", insns=");
	print_ebpf_prog(tcp, attr.insns, attr.insn_cnt);
	PRINT_FIELD_STR(", ", attr, license, tcp);
	if (LE_CLAMP(len, offsetofend(struct bpf_prog_load, license)))
		goto bpf_prog_load_end;

	/* log_* fields were added in Liunux commit v3.18-rc1~52^2~1^2~4. */
	PRINT_FIELD_U(", ", attr, log_level);
	PRINT_FIELD_U(", ", attr, log_size);
	PRINT_FIELD_X(", ", attr, log_buf);
	if (LE_CLAMP(len, offsetofend(struct bpf_prog_load, log_buf)))
		goto bpf_prog_load_end;

	/* kern_version field was added in Linux commit v4.1-rc1~84^2~50. */
	tprintf(", kern_version=KERNEL_VERSION(%u, %u, %u)",
		attr.kern_version >> 16,
		(attr.kern_version >> 8) & 0xFF,
		attr.kern_version & 0xFF);
	if (LE_CLAMP(len, offsetofend(struct bpf_prog_load, kern_version)))
		goto bpf_prog_load_end;

	/* prog_flags field was added in Linux commit v4.12-rc2~34^2~29^2~2. */
	PRINT_FIELD_FLAGS(", ", attr, prog_flags, bpf_prog_flags, "BPF_F_???");
	if (LE_CLAMP(len, offsetofend(struct bpf_prog_load, prog_flags)))
		goto bpf_prog_load_end;

	/* prog_name field was added in Linux commit v4.15-rc1~84^2~605^2~4. */
	PRINT_FIELD_CSTRING(", ", attr, prog_name);
	if (LE_CLAMP(len, offsetofend(struct bpf_prog_load, prog_name)))
		goto bpf_prog_load_end;

	/*
	 * prog_ifindex field was added as prog_target_ifindex in Linux commit
	 * v4.15-rc1~84^2~127^2~13 and renamed to its current name in
	 * v4.15-rc1~15^2~5^2~3^2~7.
	 */
	PRINT_FIELD_IFINDEX(", ", attr, prog_ifindex);

	decode_attr_extra_data(tcp, data, size, attr_size);

bpf_prog_load_end:
	tprints("}");

	return RVAL_DECODED | RVAL_FD;
}

DEF_BPF_CMD_DECODER(BPF_OBJ_PIN)
{
	struct bpf_obj {
		uint64_t ATTRIBUTE_ALIGNED(8) pathname;
		uint32_t bpf_fd;
		uint32_t file_flags;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_obj, file_flags);
	unsigned int len = size < attr_size ? size : attr_size;

	memcpy(&attr, data, len);

	PRINT_FIELD_PATH("{", attr, pathname, tcp);
	PRINT_FIELD_FD(", ", attr, bpf_fd, tcp);
	if (LE_CLAMP(len, offsetofend(struct bpf_obj, bpf_fd)))
		goto bpf_obj_pin_end;

	/* file_flags field was added in Linux v4.15-rc1~84^2~384^2~4 */
	PRINT_FIELD_FLAGS(", ", attr, file_flags, bpf_file_mode_flags,
			  "BPF_F_???");

	decode_attr_extra_data(tcp, data, size, attr_size);

bpf_obj_pin_end:
	tprints("}");

	return RVAL_DECODED | RVAL_FD;
}

#define decode_BPF_OBJ_GET decode_BPF_OBJ_PIN

DEF_BPF_CMD_DECODER(BPF_PROG_ATTACH)
{
	struct bpf_prog_attach {
		uint32_t target_fd, attach_bpf_fd, attach_type, attach_flags;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_prog_attach, attach_flags);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{", attr, target_fd, tcp);
	PRINT_FIELD_FD(", ", attr, attach_bpf_fd, tcp);
	PRINT_FIELD_XVAL(", ", attr, attach_type, bpf_attach_type, "BPF_???");
	PRINT_FIELD_FLAGS(", ", attr, attach_flags, bpf_attach_flags,
			  "BPF_F_???");
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_PROG_DETACH)
{
	struct bpf_prog_detach {
		uint32_t target_fd, dummy, attach_type;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_prog_detach, attach_type);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{", attr, target_fd, tcp);
	PRINT_FIELD_XVAL(", ", attr, attach_type, bpf_attach_type, "BPF_???");
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_PROG_TEST_RUN)
{
	struct bpf_prog_test {
		uint32_t prog_fd, retval, data_size_in, data_size_out;
		uint64_t ATTRIBUTE_ALIGNED(8) data_in, data_out;
		uint32_t repeat, duration;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_prog_test, duration);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_FD("{test={", attr, prog_fd, tcp);
	PRINT_FIELD_U(", ", attr, retval);
	PRINT_FIELD_U(", ", attr, data_size_in);
	PRINT_FIELD_U(", ", attr, data_size_out);
	PRINT_FIELD_X(", ", attr, data_in);
	PRINT_FIELD_X(", ", attr, data_out);
	PRINT_FIELD_U(", ", attr, repeat);
	PRINT_FIELD_U(", ", attr, duration);
	tprints("}");
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_PROG_GET_NEXT_ID)
{
	struct bpf_get_id {
		uint32_t start_id, next_id;
		uint32_t open_flags;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_get_id, open_flags);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_U("{", attr, start_id);
	PRINT_FIELD_U(", ", attr, next_id);
	if (LE_CLAMP(len, offsetofend(struct bpf_get_id, next_id)))
		goto bpf_prog_get_next_id_end;

	/* open_flags field has been added in Linux v4.15-rc1~84^2~384^2~4 */
	PRINT_FIELD_FLAGS(", ", attr, open_flags, bpf_file_mode_flags,
			  "BPF_F_???");

	decode_attr_extra_data(tcp, data, size, attr_size);

bpf_prog_get_next_id_end:
	tprints("}");

	return RVAL_DECODED;
}

#define decode_BPF_MAP_GET_NEXT_ID decode_BPF_PROG_GET_NEXT_ID

DEF_BPF_CMD_DECODER(BPF_PROG_GET_FD_BY_ID)
{
	struct bpf_get_id {
		uint32_t prog_id, next_id;
		uint32_t open_flags;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_get_id, open_flags);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_U("{", attr, prog_id);
	PRINT_FIELD_U(", ", attr, next_id);
	if (LE_CLAMP(len, offsetofend(struct bpf_get_id, next_id)))
		goto bpf_prog_get_fd_by_id_end;

	/* open_flags field has been added in Linux v4.15-rc1~84^2~384^2~4 */
	PRINT_FIELD_FLAGS(", ", attr, open_flags, bpf_file_mode_flags,
			  "BPF_F_???");

	decode_attr_extra_data(tcp, data, size, attr_size);

bpf_prog_get_fd_by_id_end:
	tprints("}");

	return RVAL_DECODED;
}

DEF_BPF_CMD_DECODER(BPF_MAP_GET_FD_BY_ID)
{
	struct bpf_get_id {
		uint32_t map_id, next_id;
		uint32_t open_flags;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_get_id, open_flags);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	PRINT_FIELD_U("{", attr, map_id);
	PRINT_FIELD_U(", ", attr, next_id);
	if (LE_CLAMP(len, offsetofend(struct bpf_get_id, next_id)))
		goto bpf_map_get_fd_by_id_end;

	/* open_flags field has been added in Linux v4.15-rc1~84^2~384^2~4 */
	PRINT_FIELD_FLAGS(", ", attr, open_flags, bpf_file_mode_flags,
			  "BPF_F_???");

	decode_attr_extra_data(tcp, data, size, attr_size);

bpf_map_get_fd_by_id_end:
	tprints("}");

	return RVAL_DECODED;
}

static void
print_bpf_map_info(struct tcb * const tcp, uint32_t bpf_fd,
		   const char *info_buf, uint32_t size,
		   struct bpf_priv_data *priv)
{
	struct bpf_map_info {
		uint32_t type;
		uint32_t id;
		uint32_t key_size;
		uint32_t value_size;
		uint32_t max_entries;
		uint32_t map_flags;
		char     name[BPF_OBJ_NAME_LEN];
		uint32_t ifindex;
		uint64_t netns_dev;
		uint64_t netns_ino;
	} ATTRIBUTE_ALIGNED(8) info = { 0 };
	const size_t info_size =
		offsetofend(struct bpf_map_info, netns_ino);
	unsigned int len = MIN(size, info_size);

	if (entering(tcp))
		return;

	memcpy(&info, info_buf, len);

	PRINT_FIELD_XVAL("{", info, type, bpf_map_types, "BPF_MAP_TYPE_???");
	PRINT_FIELD_U("{", info, id);
	PRINT_FIELD_U("{", info, key_size);
	PRINT_FIELD_U("{", info, value_size);
	PRINT_FIELD_U("{", info, max_entries);
	PRINT_FIELD_FLAGS(", ", info, map_flags, bpf_map_flags, "BPF_F_???");
	PRINT_FIELD_CSTRING(", ", info, name);
	PRINT_FIELD_IFINDEX(", ", info, ifindex);
	PRINT_FIELD_DEV(", ", info, netns_dev);
	PRINT_FIELD_U("{", info, netns_ino);

	decode_attr_extra_data(tcp, info_buf, size, info_size);
	tprints("}");
}

static void
print_bpf_prog_info(struct tcb * const tcp, uint32_t bpf_fd,
		    const char *info_buf, uint32_t size,
		    struct bpf_priv_data *priv)
{
	struct bpf_prog_info {
		uint32_t type;
		uint32_t id;
		uint8_t  tag[BPF_TAG_SIZE];
		uint32_t jited_prog_len;
		uint32_t xlated_prog_len;
		uint64_t ATTRIBUTE_ALIGNED(8) jited_prog_insns;
		uint64_t ATTRIBUTE_ALIGNED(8) xlated_prog_insns;
		uint64_t load_time;
		uint32_t created_by_uid;
		uint32_t nr_map_ids;
		uint64_t ATTRIBUTE_ALIGNED(8) map_ids;
		char     name[BPF_OBJ_NAME_LEN];
		uint32_t ifindex;
		uint64_t netns_dev;
		uint64_t netns_ino;
	}  ATTRIBUTE_ALIGNED(8) info = { 0 };
	const size_t info_size =
		offsetofend(struct bpf_prog_info, netns_ino);
	unsigned int len = MIN(size, info_size);
	uint64_t map_id_buf;

	memcpy(&info, info_buf, len);

	if (entering(tcp)) {
		if (!priv)
			priv = xcalloc(1, sizeof(*priv));

		priv->bpf_prog_info_stored = true;
		priv->bpf_prog_info_jited_prog_len = info.jited_prog_len;
		priv->bpf_prog_info_xlated_prog_len = info.xlated_prog_len;
		priv->bpf_prog_info_nr_map_ids = info.nr_map_ids;

		set_tcb_priv_data(tcp, priv, free);

		return;
	}

	PRINT_FIELD_XVAL("{", info, type, bpf_prog_types, "BPF_PROG_TYPE_???");
	PRINT_FIELD_U(", ", info, id);
	PRINT_FIELD_HEX_ARRAY(", ", info, tag);

	tprints(", jited_prog_len=");
	if (priv && priv->bpf_prog_info_stored
	    && priv->bpf_prog_info_jited_prog_len != info.jited_prog_len)
		tprintf("%" PRIu32 " => ", priv->bpf_prog_info_jited_prog_len);
	tprintf("%" PRIu32, info.jited_prog_len);

	tprints(", jited_prog_insns=");
	printstr_ex(tcp, info.jited_prog_insns, info.jited_prog_len,
		    QUOTE_FORCE_HEX);

	tprints(", xlated_prog_len=");
	if (priv && priv->bpf_prog_info_stored
	    && priv->bpf_prog_info_xlated_prog_len != info.xlated_prog_len)
		tprintf("%" PRIu32 " => ", priv->bpf_prog_info_xlated_prog_len);
	tprintf("%" PRIu32, info.xlated_prog_len);

	tprints(", xlated_prog_insns=");
	print_ebpf_prog(tcp, info.xlated_prog_insns, info.xlated_prog_len);

	PRINT_FIELD_U(", ", info, load_time);
	PRINT_FIELD_UID(", ", info, created_by_uid);

	tprints(", nr_map_ids=");
	if (priv && priv->bpf_prog_info_stored
	    && priv->bpf_prog_info_nr_map_ids != info.nr_map_ids)
		tprintf("%" PRIu32 " => ", priv->bpf_prog_info_nr_map_ids);
	tprintf("%" PRIu32, info.nr_map_ids);

	tprints(", map_ids=");
	print_array(tcp, info.map_ids, info.nr_map_ids,
		    &map_id_buf, sizeof(map_id_buf),
		    umoven, print_uint64_array_member, 0);

	PRINT_FIELD_IFINDEX(", ", info, ifindex);
	PRINT_FIELD_DEV(", ", info, netns_dev);
	PRINT_FIELD_U("{", info, netns_ino);

	decode_attr_extra_data(tcp, info_buf, size, info_size);
	tprints("}");
}

bool
fetch_bpf_obj_info(struct tcb * const tcp, uint64_t info, uint32_t size,
		   char **info_buf)
{
	if (!*info_buf)
		*info_buf = xmalloc(get_pagesize());

	if (size > 0 && size <= get_pagesize()
	    && !umoven(tcp, info, size, *info_buf))
		return true;

	return false;
}

static void
print_bpf_obj_info(struct tcb * const tcp, uint32_t bpf_fd, uint64_t info,
		   uint32_t size, struct bpf_priv_data *priv)
{
	static char *info_buf;

	char path[PATH_MAX + 1];
	int ret = getfdpath(tcp, bpf_fd, path, sizeof(path));

	if (ret >= 0 && !abbrev(tcp) && !(priv && priv->bpf_obj_info_printed)) {
		if (!strcmp(path, "anon_inode:bpf-map")) {
			if (fetch_bpf_obj_info(tcp, info, size, &info_buf)) {
				print_bpf_map_info(tcp, bpf_fd, info_buf, size,
						   priv);
				return;
			}
		} else if (!strcmp(path, "anon_inode:bpf-prog")) {
			if (fetch_bpf_obj_info(tcp, info, size, &info_buf)) {
				print_bpf_prog_info(tcp, bpf_fd, info_buf,
						    size, priv);
				return;
			}
		}
	}

	if (!priv) {
		priv = xcalloc(1, sizeof(*priv));
		priv->bpf_obj_info_printed = true;
		set_tcb_priv_data(tcp, priv, free);
	}

	printaddr64(info);
}

DEF_BPF_CMD_DECODER(BPF_OBJ_GET_INFO_BY_FD)
{
	struct bpf_obj_info {
		uint32_t bpf_fd, info_len;
		uint64_t ATTRIBUTE_ALIGNED(8) info;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_obj_info, info);
	unsigned int len = MIN(size, attr_size);

	memcpy(&attr, data, len);

	if (entering(tcp)) {
		PRINT_FIELD_FD("{info={", attr, bpf_fd, tcp);
		PRINT_FIELD_U(", ", attr, info_len);
		tprintf(", info=");

		return 0;
	}

	print_bpf_obj_info(tcp, attr.bpf_fd, attr.info, attr.info_len, priv);
	tprints("}");
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return RVAL_FD;
}

DEF_BPF_CMD_DECODER(BPF_PROG_QUERY)
{
	struct bpf_prog_query {
		uint32_t target_fd;
		uint32_t attach_type;
		uint32_t query_flags;
		uint32_t attach_flags;
		uint64_t ATTRIBUTE_ALIGNED(8) prog_ids;
		uint32_t prog_cnt;
	} attr = {};
	const size_t attr_size =
		offsetofend(struct bpf_prog_query, prog_cnt);
	unsigned int len = MIN(size, attr_size);
	uint64_t prog_id_buf;

	memcpy(&attr, data, len);

	if (entering(tcp)) {
		PRINT_FIELD_FD("{query={", attr, target_fd, tcp);
		PRINT_FIELD_XVAL(", ", attr, attach_type, bpf_attach_type,
				 "BPF_???");
		PRINT_FIELD_FLAGS(", ", attr, query_flags, bpf_query_flags,
				  "BPF_F_QUERY_???");
		PRINT_FIELD_FLAGS(", ", attr, attach_flags, bpf_attach_flags,
				  "BPF_F_???");

		tprints(", prog_ids=");

		if (!priv)
			priv = xcalloc(1, sizeof(*priv));

		priv->bpf_prog_query_stored = true;
		priv->bpf_prog_query_prog_cnt = attr.prog_cnt;

		set_tcb_priv_data(tcp, priv, free);

		return 0;
	}

	print_array(tcp, attr.prog_ids, attr.prog_cnt, &prog_id_buf,
		    sizeof(prog_id_buf), umoven, print_uint64_array_member, 0);

	tprints(", prog_cnt=");
	if (priv && priv->bpf_prog_query_stored
	    && priv->bpf_prog_query_prog_cnt != attr.prog_cnt)
		tprintf("%" PRIu32 " => ", priv->bpf_prog_query_prog_cnt);
	tprintf("%" PRIu32, attr.prog_cnt);
	tprints("}");
	decode_attr_extra_data(tcp, data, size, attr_size);
	tprints("}");

	return 0;
}

SYS_FUNC(bpf)
{
	static const bpf_cmd_decoder_t bpf_cmd_decoders[] = {
		BPF_CMD_ENTRY(BPF_MAP_CREATE),
		BPF_CMD_ENTRY(BPF_MAP_LOOKUP_ELEM),
		BPF_CMD_ENTRY(BPF_MAP_UPDATE_ELEM),
		BPF_CMD_ENTRY(BPF_MAP_DELETE_ELEM),
		BPF_CMD_ENTRY(BPF_MAP_GET_NEXT_KEY),
		BPF_CMD_ENTRY(BPF_PROG_LOAD),
		BPF_CMD_ENTRY(BPF_OBJ_PIN),
		BPF_CMD_ENTRY(BPF_OBJ_GET),
		BPF_CMD_ENTRY(BPF_PROG_ATTACH),
		BPF_CMD_ENTRY(BPF_PROG_DETACH),
		BPF_CMD_ENTRY(BPF_PROG_TEST_RUN),
		BPF_CMD_ENTRY(BPF_PROG_GET_NEXT_ID),
		BPF_CMD_ENTRY(BPF_MAP_GET_NEXT_ID),
		BPF_CMD_ENTRY(BPF_PROG_GET_FD_BY_ID),
		BPF_CMD_ENTRY(BPF_MAP_GET_FD_BY_ID),
		BPF_CMD_ENTRY(BPF_OBJ_GET_INFO_BY_FD),
		BPF_CMD_ENTRY(BPF_PROG_QUERY),
	};

	const unsigned int cmd = tcp->u_arg[0];
	const kernel_ulong_t addr = tcp->u_arg[1];
	const unsigned int size = tcp->u_arg[2];
	int rc;

	if (entering(tcp)) {
		static char *buf;

		if (!buf)
			buf = xmalloc(get_pagesize());

		printxval(bpf_commands, cmd, "BPF_???");
		tprints(", ");

		if (size > 0
		    && size <= get_pagesize()
		    && cmd < ARRAY_SIZE(bpf_cmd_decoders)
		    && bpf_cmd_decoders[cmd]) {
			rc = umoven_or_printaddr(tcp, addr, size, buf)
			     ? RVAL_DECODED
			     : bpf_cmd_decoders[cmd](tcp, addr, size, buf,
						     NULL);
		} else {
			printaddr(addr);
			rc = RVAL_DECODED;
		}
	} else {
		struct bpf_priv_data *priv = get_tcb_priv_data(tcp);

		rc = bpf_cmd_decoders[cmd](tcp, addr, size, NULL, priv)
			| RVAL_DECODED;
	}

	if (rc & RVAL_DECODED)
		tprintf(", %u", size);

	return rc;
}
