#if 0
#include "defs.h"


#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <asm/unistd.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

//#include "btree.h"
#include "nsfs.h"
#include "xmalloc.h"

/* key - NS ID, value - parent NS ID. */
// struct btree *ns_hierarchy;
/*
 * key - NS ID, value - struct btree * with PID tree;
 * PID tree has PID in NS as a key and PID in parent NS as a value.
 */
// struct btree *ns_pid_tree;

static const char tid_str[]  = "NSpid:\t";
static const char tgid_str[] = "NStgid:\t";
static const char pgid_str[] = "NSpgid:\t";
static const char sid_str[]  = "NSsid:\t";

static const struct {
	const char *str;
	size_t size;
} id_strs[PT_COUNT] = {
	[PT_TID] =  { tid_str,  sizeof(tid_str)  },
	[PT_TGID] = { tgid_str, sizeof(tgid_str) },
	[PT_PGID] = { pgid_str, sizeof(pgid_str) },
	[PT_SID] =  { sid_str,  sizeof(sid_str)  },
};


/**
 * Limit on PID NS hierarchy depth, imposed since Linux 3.7. NS traversal
 * is not possible before Linux 4.9, so we consider this limut pretty universal.
 */
#define MAX_NS_DEPTH 32

struct proc_data {
	int proc_pid;
	short ns_count;
	short refcount;
	uint64_t ns_hierarchy[MAX_NS_DEPTH];
	int id_count[PT_COUNT];
	int *id_hierarchy[PT_COUNT];
};

/**
 * Helper function, converts pid to string, or to "self" for pid == 0.
 * Uses static buffer for operation.
 */
static const char *
pid_to_str(pid_t pid)
{
	static char buf[sizeof("-2147483648")];
	ssize_t ret;

	if (!pid)
		return "self";

	ret = snprintf(buf, sizeof(buf), "%d", pid);

	if ((ret < 0) || ((size_t) ret >= sizeof(buf)))
		perror_msg_and_die("pid_to_str: snprintf");

	return buf;
}

/**
 * Returns a list of PID NS IDs for the specified PID.
 *
 * @param proc_pid PID (as present in /proc) to get information for.
 * @param ns_buf   Pointer to buffer that is able to contain at least
 *                 MAX_NS_DEPTH items.
 * @param last     ID of NS on which ascencion can be interrupted.
 *                 0 for no interruption.
 * @return         Amount of NS in list. 0 indicates error, MAX_NS_DEPTH + 1
 *                 indicates that ascension limit hasn't been reached (only
 *                 MAX_NS_DEPTH values have been written to the array, however).
 */
static size_t
get_ns_hierarchy(int proc_pid, uint64_t *ns_buf, size_t ns_buf_size,
		 uint64_t last)
{
	char path[PATH_MAX + 1];
	struct stat st;
	ssize_t ret;
	size_t n = 0;
	int fd;
	int parent_fd;

	ret = snprintf(path, sizeof(path), "/proc/%s/ns/pid",
		       pid_to_str(proc_pid));

	if ((ret < 0) || ((size_t) ret >= sizeof(path)))
		return 0;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return 0;

	while (1) {
		ret = fstat(fd, &st);
		if (ret)
			break;

		/* 32 is the hierarchy depth on modern Linux */
		if ((n >= MAX_NS_DEPTH) || (n >= ns_buf_size)) {
			n++;
			break;
		}

		ns_buf[n] = st.st_ino;
		if (debug_flag)
			error_msg("Got NS: %" PRIu64, ns_buf[n]);

		n++;

		if (!last || ns_buf[n - 1] == last)
			break;

		parent_fd = ioctl(fd, NS_GET_PARENT);
		if (parent_fd == -1) {
			switch (errno) {
			case EPERM:
				if (debug_flag)
					error_msg("Terminating NS ascending "
						  "after %zu levels on NS %"
						  PRIu64, n, ns_buf[n - 1]);
				break;

			case ENOTTY:
				error_msg("NS_* ioctl commands are not "
					  "supported by the kernel");
				break;
			default:
				perror_msg("get_ns_hierarchy: "
					   "ioctl(NS_GET_PARENT)");
				break;
			}

			break;
		}

		close(fd);
		fd = parent_fd;
	}

	//update_ns_hierarchy 

	//parent_fd = ge

	close(fd);

	return n;
}

/**
 * Get list of IDs present in NS* proc status record. IDs are placed as they are
 * stored in /proc (from top to bottom of NS hierarchy).
 *
 * @param proc_pid    PID (as present in /proc) to get information for.
 * @param id_buf      Pointer to buffer that is able to contain at least
 *                    MAX_NS_DEPTH items. Can be NULL.
 * @param type        Type of ID requested.
 * @return            Number of items stored in id_list. 0 indicates error,
 *                    MAX_NS_DEPTH + 1 indicates that status record contains
 *                    more that MAX_NS_DEPTH records and the id_buf provided
 *                    is unusable.
 */
static size_t
get_id_list(int proc_pid, int *id_buf, enum pid_type type)
{
	const char *ns_str = id_strs[type].str;
	size_t ns_str_size = id_strs[type].size;
	char *buf;
	char *p;
	char *endp;
	FILE *f;
	size_t idx;
	ssize_t ret;

	ret = asprintf(&buf, "/proc/%s/status", pid_to_str(proc_pid));

	if (ret < 0)
		return 0;

	f = fopen(buf, "r");
	free(buf);

	if (!f)
		return 0;

	while (fscanf(f, "%m[^\n]", &buf) == 1) {
		if (strncmp(buf, ns_str, ns_str_size)) {
			free(buf);
			continue;
		}

		p = buf + ns_str_size;

		for (idx = 0; idx < MAX_NS_DEPTH; idx++) {
			errno = 0;
			ret = strtol(p, &endp, 10);

			if (errno && (p[0] != '\t'))
				return 0;

			if (debug_flag)
				error_msg("PID %d: %s[%zu]: %zd",
					  proc_pid, ns_str, idx, ret);

			if (id_buf)
				id_buf[idx] = ret;

			strsep(&p, "\t");

			/* In order to distinguish MAX_NS_DEPTH items */
			if (!p)
				break;
		}
	}

	free(buf);

	return idx + 1;
}

static bool
is_proc_ours(void)
{
	static int cached_val = -1;

	if (cached_val < 0)
		cached_val = get_id_list(0, NULL, PT_TID) == 1;

	return cached_val;
}

static uint64_t
get_ns(struct tcb *tcp)
{
	if (!tcp->pid_ns_inited) {
		int pid = tcp->pid;

		if (!is_proc_ours())
			if (find_pid(NULL, tcp->pid, PT_TID, &pid) < 1)
				pid = -1;

		if ((pid == -1) || !get_ns_hierarchy(pid, &tcp->pid_ns, 1, 0))
			tcp->pid_ns = -1ULL;

		tcp->pid_ns_inited = true;
	}

	return tcp->pid_ns;
}

static uint64_t
get_our_ns(void)
{
	static uint64_t our_ns = 0;
	static bool our_ns_initialised = false;

	if (!our_ns_initialised) {
		uint64_t ns_buf[MAX_NS_DEPTH];
		size_t ret;

		if (!(ret = get_ns_hierarchy(0, ns_buf, ARRAY_SIZE(ns_buf), 0)))
			our_ns = -1ULL;
		else
			our_ns = ns_buf[0];

		our_ns_initialised = true;
	}

	return our_ns;
}


/**
 * Returns ID in our NS. If orig_ns_id is provided, also returns ID in orig_ns.
 */
/* static int
dens_id(int proc_pid,
	uint64_t *ns_buf, size_t ns_count,
	int *id_buf, size_t id_count,
	uint64_t orig_ns, uint64_t our_ns, int *orig_ns_id)
{
	bool orig_idx_found = false;
	size_t idx;

	if (!ns_count || (ns_count > MAX_NS_DEPTH) ||
	    !id_count || (id_count > MAX_NS_DEPTH))
		return -1;

	if (is_proc_ours()) {
	}

	for (idx = 0; idx < ns_count; idx++) {
		if (ns_buf[idx] != orig_ns)
			continue;

		orig_idx = idx;
		orig_idx_found = true;
		break;
	}

	if (!orig_idx_found) {
		free(ns_buf);

		return -1;
	}

} */

/**
 * Checks whether proc data record is actual, and updates it in case it doesn't.
 * Automatically removes invalid entries if found.
 *
 * -1 - error
 *  0 - cache is invalid
 *  1 - cache is valid
 *  2 - only NS cache is valid
 */
static int
check_proc_data_validity(struct proc_data *pd, enum pid_type type)
{
	/* ns_cnt = get_ns_hierarchy(proc_pid, &ns_buf, our_ns);
	if (!ns_cnt || (ns_cnt >= MAX_NS_DEPTH) ||
	    (ns_buf[ns_cnt - 1] != our_ns)) */
	return 0;

}

static struct proc_data *
get_proc_data(int proc_pid)
{
	struct proc_data *pd = calloc(1, sizeof(*pd));

	if (!pd)
		return NULL;

	pd->proc_pid = proc_pid;

	return pd;
}

static struct proc_data *
find_proc_data(int id, uint64_t ns, enum pid_type type)
{
	return NULL;
}

static void
put_proc_data(struct proc_data *pd)
{
	free(pd);
}

static void
update_proc_data_cache(struct proc_data *pd, enum pid_type type)
{
}

/**
 * Removes references to the proc_data entry from all caches.
 */
static void
invalidate_proc_data(struct proc_data *pd)
{
}

/**
 * Caches:
 *  * tidns:ns -> tid in our ns
 *   * How to check validity: get cached proc path, with additional check for
 *     ns and that it also has tidns at the relevant level in NSpid
 *  * tid (in our ns) -> proc_tid
 *   * How to check validity: open cached /proc/pid/status and check relevant
 *     NSpid record, check that /proc/pid/ns/pid is accessible [and leads to our
 *     ns]
 *
 *  Tracees have fixed pid ns.
 */

/**
 * tcp == NULL - strace's view
 * dest_pid == 0 - use the data from tcb
 */
int
find_pid(struct tcb *tcp, int dest_id, enum pid_type type, int *proc_pid_ptr)
{
	static long name_max = -1;

	const uint64_t our_ns = get_our_ns();
	uint64_t dest_ns;

	struct proc_data *pd;
	int pd_valid = 0;

	DIR *dp = NULL;
	struct dirent *entry;
	struct dirent *entry_buf;
	struct dirent *entry_ret;
	const char *id_str;
	size_t idx;
	size_t entry_size;
	long proc_pid = -1;
	int ret;
	int res = -1;

	if ((type >= PT_COUNT) || (type < 0))
		goto find_pid_exit;

	if (is_proc_ours() && (!tcp || get_ns(tcp) == our_ns)) {
		if (proc_pid_ptr)
			*proc_pid_ptr =
				dest_id ? dest_id : syscall(__NR_gettid);

		if (dest_id) {
			return dest_id;

		switch (type) {
		case PT_TID:	return syscall(__NR_gettid);
		case PT_TGID:	return getpid();
		case PT_PGID:	return getpgrp();
		case PT_SID:	return getsid(getpid());
		default:	return -1;
		}
	}

	dest_ns = tcp ? get_ns(tcp) : our_ns;

	pd = find_proc_data(dest_id, dest_ns, type);
	if (pd) {
		pd_valid = check_proc_data_validity(pd, type);
		if (pd_valid == -1)
			goto find_pid_pd;
		if (pd_valid == 0)
			put_proc_data(pd);
		if (pd_valid == 2)
			goto find_pid_get_ids;
	}

	if (pd_valid)
		goto find_pid_get_pid;

	dp = opendir("/proc");
	if (!dp)
		goto find_pid_pd;


	if (name_max == -1) {
		name_max = pathconf("/proc", _PC_NAME_MAX);
		if (name_max == -1)
			name_max = 255;
	}

	entry_size = offsetof(struct dirent, d_name) + name_max + 1;
	entry_buf = malloc(entry_size);
	if (!entry_buf)
		goto find_pid_dir;

	do {
		ret = readdir_r(dp, entry_buf, &entry);
		if (ret) {
			perror_msg("find_pid: readdir");
			goto find_pid_entry;
		}

		if (!entry)
			goto find_pid_entry;

		if (entry->d_type != DT_DIR)
			continue;

		errno = 0;
		proc_pid = strtol(entry->d_name, NULL, 10);
		if (errno)
			continue;
		if ((proc_pid < 1) || (proc_pid > INT_MAX))
			continue;

		pd = get_proc_data(proc_pid);
		pd_valid = check_proc_data_validity(pd, type);
		if (pd_valid == -1)
			goto find_pid_entry;
		if (pd_valid == 1)
			goto find_pid_get_pid;
		if (pd_valid == 0)
			pd->ns_count = get_ns_hierarchy(proc_pid,
				pd->ns_hierarchy, ARRAY_SIZE(pd->ns_hierarchy),
				our_ns);
find_pid_get_ids:
		if (!pd->id_hierarchy[type])
			pd->id_hierarchy[type] = calloc(MAX_NS_DEPTH,
				sizeof(pd->id_hierarchy[type][0]));
		if (!pd->id_hierarchy[type])
			goto find_pid_entry;

		pd->id_count[type] = get_id_list(proc_pid,
			pd->id_hierarchy[type], type);

		update_proc_data_cache(pd, type);

find_pid_get_pid:
		if (!pd->ns_count || (pd->ns_count > pd->id_count[type])) {
			continue;
		}

		if (pd->ns_hierarchy[pd->ns_count - 1] != dest_ns)
			continue;

		if (dest_ns == our_ns) {
			if (pd->id_hierarchy[type][pd->id_count[type] -
			    pd->ns_count] == dest_id) {
				res = dest_id;
				goto find_pid_entry;
			}
		} else {
			for (idx = 0; idx < pd->ns_count - 1; idx++) {
				if (pr->ns_hierarchy[idx] != dest_ns)
					continue;
				if (pr->id_hierarchy[type][pd->id_count[type] -
				    idx + 1] != dest_id)
					break;

				res = pd->id_hierarchy[type][pd->id_count[type] -
							     pd->ns_count]

				goto find_pid_entry;
			}
		}

		put_proc_data(pd);
	} while (1)

find_pid_entry:
	free(entry_buf);
find_pid_dir:
	closedir(dp);
find_pid_pd:
	put_proc_data(pd);

find_pid_exit:
	if (proc_pid_ptr)
		*proc_pid_ptr = proc_pid;

	return res;
}

int
get_proc_pid(struct *tcp)
{
	if (!is_proc_ours()) {
		int ret;

		if (find_pid(NULL, tcp->pid, PT_TID, &ret) < 0)
			return -1;

		return ret;
	}

	return tcp->pid;
}

/* To be called on tracee exits or other clear indications that pid is no more
 * relevant */
void
clear_proc_pid(struct tcb *tcp, int pid)
{
}

void
printpid(struct tcb *tcp, int pid, enum pid_type type)
{
	int strace_pid;

	tprintf("%d", pid);

	if (perform_ns_resolution) {
		find_pid(tcp, 0, type, NULL);

		if ((strace_pid > 0) && (pid != strace_pid))
			tprintf_comment("%d in strace's PID NS", strace_pid);
	}
}
#endif
