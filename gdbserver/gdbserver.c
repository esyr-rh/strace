/* Implementation of strace features over the GDB remote protocol.
 *
 * Copyright (c) 2015, 2016 Red Hat Inc.
 * Copyright (c) 2015 Josh Stone <cuviper@gmail.com>
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

#define _GNU_SOURCE 1
#include <stdlib.h>
#include <sys/wait.h>

#include "defs.h"
#include "protocol.h"
#include "signals.h"
#include "scno.h"

/* FIXME jistone: export hacks */
struct tcb *pid2tcb(int pid);
struct tcb *alloctcb(int pid);
void droptcb(struct tcb *tcp);
void newoutf(struct tcb *tcp);
void print_signalled(struct tcb *tcp, const int pid, int status);
void print_exited(struct tcb *tcp, const int pid, int status);
void print_stopped(struct tcb *tcp, const siginfo_t *si, const unsigned int sig);
struct tcb *current_tcp;
int strace_child;

char* gdbserver = NULL;
static int general_pid; // process id that gdbserver is focused on
static int general_tid; // thread id that gdbserver is focused on
static struct gdb_stop_reply stop;
static struct gdb_conn* gdb = NULL;
static bool gdb_extended = false;
static bool gdb_multiprocess = false;
static bool gdb_vcont = false;
static bool gdb_nonstop = false;

static const char * const gdb_signal_names[] = {
#define SET(symbol, constant, name, string) \
        [constant] = name,
#include "signals.def"
#undef SET
};

static int gdb_signal_map[SUPPORTED_PERSONALITIES][GDB_SIGNAL_LAST];

enum gdb_stop {
        gdb_stop_unknown, // O or F or anything else
        gdb_stop_error, // E
        gdb_stop_signal, // S or T
        gdb_stop_exited, // W
        gdb_stop_terminated, // X

        // specific variants of gdb_stop_signal 05
        gdb_stop_trap, // missing or unrecognized stop reason
        gdb_stop_syscall_entry,
        gdb_stop_syscall_return,
};


struct gdb_stop_reply {
        char *reply;
        size_t size;

        enum gdb_stop type;
        int code; // error, signal, exit status, scno
        int pid; // process id, aka kernel tgid
        int tid; // thread id, aka kernel tid
};

static int
gdb_map_signal(unsigned int gdb_sig) {
        /* strace "SIG_0" vs. gdb "0" -- it's all zero */
        if (gdb_sig == GDB_SIGNAL_0)
                return 0;

        /* real-time signals are "special", not even fully contiguous */
        if (gdb_sig == GDB_SIGNAL_REALTIME_32)
                return 32;
        if (GDB_SIGNAL_REALTIME_33 <= gdb_sig &&
                        gdb_sig <= GDB_SIGNAL_REALTIME_63)
                return gdb_sig - GDB_SIGNAL_REALTIME_33 + 33;
        if (GDB_SIGNAL_REALTIME_64 <= gdb_sig &&
                        gdb_sig <= GDB_SIGNAL_REALTIME_127)
                return gdb_sig - GDB_SIGNAL_REALTIME_64 + 64;

        const char *gdb_signame = gdb_signal_names[gdb_sig];
        if (!gdb_signame)
                return -1;

        /* many of the other signals line up, but not all. */
        if (gdb_sig < nsignals && !strcmp(gdb_signame, signame(gdb_sig)))
                return gdb_sig;

        /* scan the rest for a match */
        unsigned int sig;
        for (sig = 1; sig < nsignals; ++sig) {
                if (sig == gdb_sig)
                        continue;
                if (!strcmp(gdb_signame, signame(sig)))
                        return sig;
        }

        return -1;
}

static void
gdb_signal_map_init(void)
{
	unsigned int pers, old_pers = current_personality;

	for (pers = 0; pers < SUPPORTED_PERSONALITIES; ++pers) {
		if (current_personality != pers)
			set_personality(pers);

                unsigned int gdb_sig;
                int *map = gdb_signal_map[pers];
                for (gdb_sig = 0; gdb_sig < GDB_SIGNAL_LAST; ++gdb_sig)
                        map[gdb_sig] = gdb_map_signal(gdb_sig);
	}

	if (old_pers != current_personality)
		set_personality(old_pers);
}

static int
gdb_signal_to_target(struct tcb *tcp, unsigned int signal)
{
        unsigned int pers = tcp->currpers;
        if (pers < SUPPORTED_PERSONALITIES && signal < GDB_SIGNAL_LAST)
                return gdb_signal_map[pers][signal];
        return -1;
}

static void
gdb_parse_thread(const char *id, int *pid, int *tid)
{
        if (*id == 'p') {
                // pPID or pPID.TID
                ++id;
                *pid = gdb_decode_hex_str(id);

                // stop messages should always have the TID,
                // but if not, just use the PID.
                char *dot = strchr(id, '.');
                if (!dot) {
                        *tid = *pid;
                } else {
                        *tid = gdb_decode_hex_str(dot + 1);
                }
        } else {
                // just TID, assume same PID
                *tid = gdb_decode_hex_str(id);
                *pid = *tid;
        }
}

static void
gdb_recv_signal(struct gdb_stop_reply *stop)
{
        char *reply = stop->reply;

        stop->code = gdb_decode_hex_n(&reply[1], 2);
        stop->type = (stop->code == GDB_SIGNAL_TRAP ||
                        stop->code == GDB_SIGNAL_0)
                ? gdb_stop_trap : gdb_stop_signal;

        // tokenize the n:r pairs
        char *info = strdupa(reply + 3);
        char *savetok = NULL, *nr;
        for (nr = strtok_r(info, ";", &savetok); nr;
                        nr = strtok_r(NULL, ";", &savetok)) {
                char *n = strtok(nr, ":");
                char *r = strtok(NULL, "");
                if (!n || !r)
                        continue;

                if (!strcmp(n, "thread")) {
			if (stop->pid == -1) {
				gdb_parse_thread(r, &stop->pid, &stop->tid);
				general_pid = stop->pid;
				general_tid = stop->tid;
			}
			else
				// an optional 2nd thread component is the
				// thread that gdbserver is focused on
				gdb_parse_thread(r, &general_pid, &general_tid);
                }
                else if (!strcmp(n, "syscall_entry")) {
                        if (stop->type == gdb_stop_trap) {
                                stop->type = gdb_stop_syscall_entry;
                                stop->code = gdb_decode_hex_str(r);
                        }
                }
                else if (!strcmp(n, "syscall_return")) {
                        if (stop->type == gdb_stop_trap) {
                                stop->type = gdb_stop_syscall_return;
                                stop->code = gdb_decode_hex_str(r);
                        }
                }
        }

        // TODO guess architecture by the size of reported registers?
}

static void
gdb_recv_exit(struct gdb_stop_reply *stop)
{
        char *reply = stop->reply;

        stop->type = reply[0] == 'W' ?
                gdb_stop_exited : gdb_stop_terminated;
        stop->code = gdb_decode_hex_str(&reply[1]);

        const char *process = strstr(reply, ";process:");
        if (process) {
                stop->pid = gdb_decode_hex_str(process + 9);

                // we don't really know the tid, so just use PID for now
                // XXX should exits enumerate all threads we know of a process?
                stop->tid = stop->pid;
        }
}

static struct gdb_stop_reply
gdb_recv_stop(struct gdb_stop_reply *stop_reply)
{
        struct gdb_stop_reply stop = {
                .reply = NULL,
                .size = 0,

                .type = gdb_stop_unknown,
                .code = -1,
                .pid = -1,
                .tid = -1,
        };
	char *reply = NULL;
	size_t stop_size;


	if (stop_reply)
	    // pop_notification gave us a cached notification
	    stop = *stop_reply;
	else
	    stop.reply = gdb_recv(gdb, &stop.size, true);

	if (debug_flag)
	{
		printf ("%s:%d %s\n", __FUNCTION__, __LINE__, stop.reply);
		fflush(stdout);
	}

	if (gdb_has_non_stop(gdb) && !stop_reply) {
	    /* non-stop packet order:
	       client sends: $vCont;c
	       server sends: OK
	       server sends: %Stop:T05syscall_entry (possibly out of order)
	       client sends: $vStopped
	       server possibly sends 0 or more: T05syscall_entry
	       client sends to each: $vStopped
	       server sends: OK
	    */
	     /* Do we have an out of order notification?  (see gdb_recv) */
	     reply = pop_notification(&stop_size);
	     if (reply) {
		  if (debug_flag)
		       printf ("popped %s\n", reply);
		  stop.reply = reply;
		  reply = gdb_recv(gdb, &stop_size, false); /* vContc OK */
	     }
	     else {
		     while (stop.reply[0] != 'T' && stop.reply[0] != 'W')
			     stop.reply = gdb_recv(gdb, &stop.size, true);
	     }
	}
	if (gdb_has_non_stop(gdb) && (stop.reply[0] == 'T')) {
		do {
			size_t this_size;
			gdb_send(gdb,"vStopped",8);
			reply = gdb_recv(gdb, &this_size, true);
			if (strcmp (reply, "OK") == 0)
				break;
			push_notification(reply, this_size);
		} while (true);
	}

        // all good packets are at least 3 bytes
        switch (stop.size >= 3 ? stop.reply[0] : 0) {
                case 'E':
                        stop.type = gdb_stop_error;
                        stop.code = gdb_decode_hex_n(stop.reply + 1, 2);
                        break;
                case 'S':
                case 'T':
                        gdb_recv_signal(&stop);
                        break;
                case 'W':
                case 'X':
                        gdb_recv_exit(&stop);
                        break;
                default:
                        stop.type = gdb_stop_unknown;
                        break;
        }

        return stop;
}

static bool
gdb_ok(void)
{
        size_t size;
        char *reply = gdb_recv(gdb, &size, false);
        bool ok = size == 2 && !strcmp(reply, "OK");
        free(reply);
        return ok;
}


bool
gdb_prog_pid_check (char *exec_name, int nprocs)
{
	/* under gdbserver, we can reasonably allow having neither to use existing targets.  */
	if (!exec_name && !nprocs && !gdbserver)
		return false;
	return true;
}


bool
gdb_start_init(void)
{
# if ! defined X86_64
	error_msg("-G is not supported on this target.");
	return false;		/* Only supported on x86_64 */
# endif

        gdb_signal_map_init();

        if (gdbserver[0] == '|')
                gdb = gdb_begin_command(gdbserver + 1);
        else if (strchr(gdbserver, ':') && !strchr(gdbserver, '/')) {
		if (strchr(gdbserver, ';')) {
			const char *stop_option;
			gdbserver = strtok(gdbserver, ";");
			stop_option = strtok(NULL, "");
			stop_option += strspn(" ", stop_option);
			if (!strcmp(stop_option, "non-stop"))
				gdb_nonstop = true;
		}
                const char *node = strtok(gdbserver, ":");
                const char *service = strtok(NULL, "");
                gdb = gdb_begin_tcp(node, service);
        } else
                gdb = gdb_begin_path(gdbserver);

        if (!gdb_start_noack(gdb))
                error_msg("couldn't enable gdb noack mode");

        static char multi_cmd[] = "qSupported:multiprocess+"
		";fork-events+;vfork-events+";

	if (!followfork) {
		/* Remove fork and vfork */
		char *multi_cmd_semi = strchr (multi_cmd, ';');
		*multi_cmd_semi = '\0';
	}

        gdb_send(gdb, multi_cmd, sizeof(multi_cmd) - 1);

        size_t size;
	bool gdb_fork;
        char *reply = gdb_recv(gdb, &size, false);
        gdb_multiprocess = strstr(reply, "multiprocess+") != NULL;
        if (!gdb_multiprocess)
                error_msg("couldn't enable gdb multiprocess mode");
	if (followfork) {
		gdb_fork = strstr(reply, "fork-events+") != NULL;
		if (!gdb_fork)
			error_msg("couldn't enable gdb fork events handling");
		gdb_fork = strstr(reply, "vfork-events+") != NULL;
		if (!gdb_fork)
			error_msg("couldn't enable gdb vfork events handling");
	}
        free(reply);

        static const char extended_cmd[] = "!";
        gdb_send(gdb, extended_cmd, sizeof(extended_cmd) - 1);
        gdb_extended = gdb_ok();
        if (!gdb_extended)
                error_msg("couldn't enable gdb extended mode");

        static const char vcont_cmd[] = "vCont?";
        gdb_send(gdb, vcont_cmd, sizeof(vcont_cmd) - 1);
        reply = gdb_recv(gdb, &size, false);
        gdb_vcont = strncmp(reply, "vCont", 5) == 0;
        if (!gdb_vcont)
                error_msg("gdb server doesn't support vCont");
        free(reply);
	return true;
}


static void
gdb_init_syscalls(void)
{
	static const char syscall_cmd[] = "QCatchSyscalls:1";
	const char *syscall_set = "";
	bool want_syscall_set = false;
	unsigned sci;

	/* Only send syscall list if a filtered list was given with -e */
	for (sci = 0; sci < nsyscalls; sci++)
		if (! (qual_flags(sci) & QUAL_TRACE)) {
			want_syscall_set = true;
			break;
		}

	for (sci = 0; want_syscall_set && sci < nsyscalls; sci++)
		if (qual_flags(sci) & QUAL_TRACE)
			if (asprintf ((char**)&syscall_set, "%s;%x", syscall_set, sci) < 0)
				error_msg("couldn't enable gdb syscall catching");

	if (want_syscall_set)
		asprintf ((char**)&syscall_set, "%s%s", syscall_cmd, syscall_set);
	else
		syscall_set = syscall_cmd;
        gdb_send(gdb, syscall_set, strlen(syscall_set));
        if (!gdb_ok())
                error_msg("couldn't enable gdb syscall catching");
}

static struct tcb*
gdb_find_thread(int tid, bool current)
{
        if (tid < 0)
                return NULL;

        /* Look up 'tid' in our table. */
        struct tcb *tcp = pid2tcb(tid);
        if (!tcp) {
                tcp = alloctcb(tid);
		tcp->flags |= TCB_GDB_CONT_PID_TID;
                tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
                newoutf(tcp);

                if (!current) {
                        char cmd[] = "Hgxxxxxxxx";
                        sprintf(cmd, "Hg%x", tid);
                        gdb_send(gdb, cmd, strlen(cmd));
                        current = gdb_ok();
                        if (!current)
                                error_msg("couldn't set gdb to thread %d", tid);
                }
                if (current)
                        gdb_init_syscalls();
        }
        return tcp;
}

static void
gdb_enumerate_threads(void)
{
        // qfThreadInfo [qsThreadInfo]...
        // -> m thread
        // -> m thread,thread
        // -> l (finished)

        static const char qfcmd[] = "qfThreadInfo";

        gdb_send(gdb, qfcmd, sizeof(qfcmd) - 1);

        size_t size;
        char *reply = gdb_recv(gdb, &size, false);
        while (reply[0] == 'm') {
                char *thread;
                for (thread = strtok(reply + 1, ","); thread;
                                thread = strtok(NULL, "")) {
                        int pid, tid;
                        gdb_parse_thread(thread, &pid, &tid);

                        struct tcb *tcp = gdb_find_thread(tid, false);
                        if (tcp && !current_tcp)
                                current_tcp = tcp;
                }

                free(reply);

                static const char qscmd[] = "qsThreadInfo";
                gdb_send(gdb, qscmd, sizeof(qscmd) - 1);
                reply = gdb_recv(gdb, &size, false);
        }

        free(reply);
}

void
gdb_end_init(void)
{
        // We enumerate all attached threads to be sure, especially since we
        // get all threads on vAttach, not just the one pid.
        gdb_enumerate_threads();

        // Everything was stopped from startup_child/startup_attach,
        // now continue them all so the next reply will be a stop packet
        if (gdb_vcont) {
                static const char cmd[] = "vCont;c";
                gdb_send(gdb, cmd, sizeof(cmd) - 1);
        } else {
                static const char cmd[] = "c";
                gdb_send(gdb, cmd, sizeof(cmd) - 1);
        }
}

void
gdb_cleanup(void)
{
        if (gdb)
                gdb_end(gdb);
        gdb = NULL;
}

void
gdb_startup_child(char **argv)
{
        if (!gdb)
                error_msg_and_die("gdb server not connected!");

        if (!gdb_extended)
                error_msg_and_die("gdb server doesn't support starting processes!");

	/* Without knowing gdb's current tid, vCont of the correct thread for
	   the multithreaded nonstop case is difficult, so default to all-stop */

        size_t i;
        size_t size = 4; // vRun
        for (i = 0; argv[i]; ++i) {
                size += 1 + 2 * strlen(argv[i]); // ;hexified-argument
        }

	if (gdb_nonstop) {
		static const char nonstop_cmd[] = "QNonStop:1";
		gdb_send(gdb, nonstop_cmd, sizeof(nonstop_cmd) - 1);
		if (!gdb_ok())
			gdb_nonstop = false;
	}

        char *cmd = malloc(size);
        if (!cmd)
                error_msg_and_die("malloc failed!");
        char *cmd_ptr = cmd;
        memcpy(cmd_ptr, "vRun", 4);
        cmd_ptr += 4;
        for (i = 0; argv[i]; ++i) {
                *cmd_ptr++ = ';';
                const char *arg = argv[i];
                while (*arg) {
                        gdb_encode_hex(*arg++, cmd_ptr);
                        cmd_ptr += 2;
                }
        }

        gdb_send(gdb, cmd, size);
        free(cmd);

        struct gdb_stop_reply stop = gdb_recv_stop(NULL);
        if (stop.size == 0)
                error_msg_and_die("gdb server doesn't support vRun!");
        switch (stop.type) {
                case gdb_stop_error:
                        error_msg_and_die("gdb server failed vRun with %.*s",
                                        (int)stop.size, stop.reply);
                case gdb_stop_trap:
                        break;
                default:
                        error_msg_and_die("gdb server expected vRun trap, got: %.*s",
                                        (int)stop.size, stop.reply);
        }

        pid_t tid = stop.tid;
        free(stop.reply);

        strace_child = tid;

	struct tcb *tcp = alloctcb(tid);
        tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
        newoutf(tcp);
        gdb_init_syscalls();

	if (gdb_nonstop)
		gdb_set_non_stop(gdb, true);
        // TODO normal strace attaches right before exec, so the first syscall
        // seen is the execve with all its arguments.  Need to emulate that here?
	// Need to handle TCB_HIDE_LOG and hide_log(tcp) ?
}

void
gdb_startup_attach(struct tcb *tcp)
{
        if (!gdb)
                error_msg_and_die("gdb server not connected!");

        if (!gdb_extended)
                error_msg_and_die("gdb server doesn't support attaching processes!");

        char cmd[] = "vAttach;XXXXXXXX";
        struct gdb_stop_reply stop;
	static const char nonstop_cmd[] = "QNonStop:1";

	gdb_send(gdb, nonstop_cmd, sizeof(nonstop_cmd) - 1);
	if (gdb_ok())
	       gdb_set_non_stop(gdb, true);

        sprintf(cmd, "vAttach;%x", tcp->pid);
        gdb_send(gdb, cmd, strlen(cmd));

	do {
		/*
		  non-stop packet order:
		  client sends: vCont;t
		  server sends: OK
		  server sends: Stop:T05swbreak:;
		  client sends: vStopped
		  [ server sends: T05swbreak:;
		    client sends: vStopped ]
		  server sends: OK
		*/
		char cmd[] = "vCont;t:pXXXXXXXX";
		sprintf(cmd, "vCont;t:p%x.-1", tcp->pid);
		if (!gdb_ok()) {
		     stop.type = gdb_stop_unknown;
		     break;
		}
		gdb_send(gdb, cmd, strlen(cmd));
		stop = gdb_recv_stop(NULL);
	} while (0);

	if (stop.type == gdb_stop_unknown) {
		static const char nonstop_cmd[] = "QNonStop:0";
		gdb_send(gdb, nonstop_cmd, sizeof(nonstop_cmd) - 1);
		if (gdb_ok())
			gdb_set_non_stop(gdb, false);
		else
			error_msg_and_die("Cannot connect to process %d: gdb server doesn't support vAttach!", tcp->pid);
		gdb_send(gdb, cmd, strlen(cmd));
		stop = gdb_recv_stop(NULL);
		if (stop.size == 0)
			error_msg_and_die("Cannot connect to process %d: gdb server doesn't support vAttach!", tcp->pid);
		switch (stop.type) {
		case gdb_stop_error:
			error_msg_and_die("Cannot connect to process %d: gdb server failed vAttach with %.*s",
					  tcp->pid, (int)stop.size, stop.reply);
		case gdb_stop_trap:
			break;
		case gdb_stop_signal:
			if (stop.code == 0)
				break;
			// fallthrough
		default:
			error_msg_and_die("Cannot connect to process %d: gdb server expected vAttach trap, got: %.*s",
					  tcp->pid, (int)stop.size, stop.reply);
	    }
	  }

        pid_t tid = stop.tid;
        free(stop.reply);

        if (tid != tcp->pid) {
                droptcb(tcp);
                tcp = alloctcb(tid);
        }
        tcp->flags |= TCB_ATTACHED | TCB_STARTUP;
        newoutf(tcp);
        gdb_init_syscalls();

        if (!qflag)
		fprintf(stderr, "Process %u attached in %s mode\n", tcp->pid,
			gdb_has_non_stop (gdb) ? "non-stop" : "all-stop");
}

void
gdb_detach(struct tcb *tcp)
{
        if (gdb_multiprocess) {
                char cmd[] = "D;XXXXXXXX";
                sprintf(cmd, "D;%x", tcp->pid);
                gdb_send(gdb, cmd, strlen(cmd));
        } else {
                static const char cmd[] = "D";
                gdb_send(gdb, cmd, sizeof(cmd) - 1);
        }

        if (!gdb_ok()) {
                // is it still alive?
                char cmd[] = "T;XXXXXXXX";
                sprintf(cmd, "T;%x", tcp->pid);
                gdb_send(gdb, cmd, strlen(cmd));
                if (gdb_ok())
                        error_msg("gdb server failed to detach %d", tcp->pid);
                // otherwise it's dead, or already detached, fine.
        }
}


enum trace_event
gdb_next_event(int *pstatus, siginfo_t *si)
{
//	struct gdb_stop_reply stop;
	int gdb_sig = 0;
	pid_t tid;
	struct tcb *tcp = NULL;

	stop = gdb_recv_stop(NULL);
	if (stop.size == 0)
		error_msg_and_die("gdb server gave an empty stop reply!?");
	switch (stop.type) {
	case gdb_stop_unknown:
		error_msg_and_die("gdb server stop reply unknown: %.*s",
				(int)stop.size, stop.reply);
		break;
	case gdb_stop_error:
		// vCont error -> no more processes
		free(stop.reply);
		return TE_BREAK;
	default:
		break;
	}


	tid = -1;
	tcp = NULL;

	if (gdb_multiprocess) {
		tid = stop.tid;
		tcp = gdb_find_thread(tid, true);
		/* Set current output file */
		current_tcp = tcp;
	} else if (current_tcp) {
		tcp = current_tcp;
		tid = tcp->pid;
	}
	if (tid < 0 || tcp == NULL)
		error_msg_and_die("couldn't read tid from stop reply: %.*s",
				(int)stop.size, stop.reply);

	switch (stop.type) {
	case gdb_stop_exited:
		*pstatus = W_EXITCODE(stop.code, 0);
		return TE_EXITED;

	case gdb_stop_terminated:
		*pstatus = W_EXITCODE(0, gdb_signal_to_target(tcp, stop.code));
		return TE_SIGNALLED;

        case gdb_stop_unknown:	// already handled above
        case gdb_stop_error:	// already handled above
        case gdb_stop_trap:	// misc trap
        	break;
	case gdb_stop_syscall_entry:
		// If we thought we were already in a syscall -- missed
		// a return? -- skipping this report doesn't do much
		// good.  Might as well force it to be a new entry
		// regardless to sync up.
		tcp->flags &= ~TCB_INSYSCALL;
		tcp->scno = stop.code;
		gdb_sig = stop.code;
		*pstatus = gdb_signal_to_target(tcp, gdb_sig);
		return TE_SYSCALL_STOP;

	case gdb_stop_syscall_return:
		// If we missed the entry, recording a return will only
		// confuse things, so let's just report the good ones.
		if (exiting(tcp)) {
			tcp->scno = stop.code;
			gdb_sig = stop.code;
			*pstatus = gdb_signal_to_target(tcp, gdb_sig);
			return TE_SYSCALL_STOP;
		}
		break;

	case gdb_stop_signal:
	{
		size_t siginfo_size;
		char *siginfo_reply =
				gdb_xfer_read(gdb, "siginfo", "", &siginfo_size);
		if (siginfo_reply && siginfo_size == sizeof(siginfo_t))
			si = (siginfo_t *) siginfo_reply;

		// XXX gdbserver returns "native" siginfo of 32/64-bit target
		// but strace expects its own format as PTRACE_GETSIGINFO
		// would have given it.
		// (i.e. need to reverse siginfo_fixup)
		// ((i.e. siginfo_from_compat_siginfo))

		gdb_sig = stop.code;
		*pstatus = gdb_signal_to_target(tcp, gdb_sig);
		free(siginfo_reply);
		return TE_SIGNAL_DELIVERY_STOP;
	}

	default:
		// TODO Do we need to handle gdb_multiprocess here?
		break;
	}

	if (stop.code == __NR_exit_group) {
		return TE_GROUP_STOP;
	}

	return TE_RESTART;
}

// Returns true iff the main trace loop has to contionue.
// The gdb connection should be ready for a stop reply on entry,
// and we'll leave it the same way if we return true.
bool
gdb_dispatch_event(enum trace_event ret, int *pstatus, siginfo_t *si)
{
	int gdb_sig = 0;
	struct tcb *tcp = current_tcp;
	pid_t tid = current_tcp->pid;
	unsigned int sig = 0;


	if (! (tcp->flags & TCB_GDB_CONT_PID_TID)) {
		char cmd[] = "Hgxxxxxxxx";
		sprintf(cmd, "Hg%x.%x", general_pid, general_tid);
		if (debug_flag)
			printf ("%s %s\n", __FUNCTION__, cmd);
	}
	// TODO need code equivalent to PTRACE_EVENT_EXEC?

	/* Is this the very first time we see this tracee stopped? */
	if (tcp->flags & TCB_STARTUP) {
		tcp->flags &= ~TCB_STARTUP;
		if (get_scno(tcp) == 1)
			tcp->s_prev_ent = tcp->s_ent;
	}

	// TODO cflag means we need to update tcp->dtime/stime
	// usually through wait rusage, but how can we do it?

	switch (ret) {
	case TE_BREAK:
		return false;

	case TE_RESTART:
		break;

	case TE_SYSCALL_STOP:
		trace_syscall(tcp, &sig);
		break;

	case TE_SIGNAL_DELIVERY_STOP:
		sig = *pstatus;
		gdb_sig = stop.code;
		print_stopped(tcp, si, *pstatus);
		break;

	case TE_SIGNALLED:
		print_signalled(tcp, tid, *pstatus);
		droptcb(tcp);
		return false;

	case TE_EXITED:
		print_exited(tcp, tid, *pstatus);
		droptcb(tcp);
		return false;

	case TE_GROUP_STOP:
		sig = *pstatus;
		return false;

	case TE_STOP_BEFORE_EXECVE:
	case TE_STOP_BEFORE_EXIT:
		// TODO handle this?
		return false;

	case TE_NEXT:
		break;
	}


	free(stop.reply);
	// TODO Do we need to handle pop_notification here?

	if (gdb_sig) {
		if (gdb_vcont) {
			// send the signal to this target and continue everyone else
			char cmd[] = "vCont;Cxx:xxxxxxxx;c";
			sprintf(cmd, "vCont;C%02x:%x;c", gdb_sig, tid);
			gdb_send(gdb, cmd, strlen(cmd));
		} else {
			// just send the signal
			char cmd[] = "Cxx";
			sprintf(cmd, "C%02x", gdb_sig);
			gdb_send(gdb, cmd, strlen(cmd));
		}
	} else {
		if (gdb_vcont) {
			// For non-stop use $vCont;c:pid.tid where pid.tid is
			// the thread gdbserver is focused on
			char cmd[] = "vCont;c:xxxxxxxx.xxxxxxxx";

			struct tcb *general_tcp = gdb_find_thread(general_tid, true);
			if (gdb_has_non_stop (gdb) && general_pid != general_tid
					&& general_tcp->flags & TCB_GDB_CONT_PID_TID)
				sprintf(cmd, "vCont;c:p%x.%x", general_pid, general_tid);
			else
				sprintf(cmd, "vCont;c");
			gdb_send(gdb, cmd, sizeof(cmd) - 1);
		} else {
			static const char cmd[] = "c";
			gdb_send(gdb, cmd, sizeof(cmd) - 1);
		}
	}

	return true;
}


char *
gdb_get_all_regs(pid_t tid, size_t *size)
{
        if (!gdb)
                return NULL;

        /* NB: this assumes gdbserver's current thread is also tid.  If that
         * may not be the case, we should send "HgTID" first, and restore.  */
        gdb_send(gdb, "g", 1);
        return gdb_recv(gdb, size, false);
}


int
gdb_get_regs (pid_t pid, void *io)
#include "gdb_get_regs.c"


int
gdb_get_scno(struct tcb *tcp)
{
	return 1;
}

int
gdb_read_mem(pid_t tid, long addr, unsigned int len, bool check_nil, char *out)
{
        if (!gdb) {
                errno = EINVAL;
                return -1;
        }

        /* NB: this assumes gdbserver's current thread is also tid.  If that
         * may not be the case, we should send "HgTID" first, and restore.  */
        while (len) {
                char cmd[] = "mxxxxxxxxxxxxxxxx,xxxx";
                unsigned int chunk_len = len < 0x1000 ? len : 0x1000;
                sprintf(cmd, "m%lx,%x", addr, chunk_len);
                gdb_send(gdb, cmd, strlen(cmd));

                size_t size;
                char *reply = gdb_recv(gdb, &size, false);
                if (size < 2 || reply[0] == 'E' || size > len * 2
                    || gdb_decode_hex_buf(reply, size, out) < 0) {
                        errno = EINVAL;
                        return -1;
                }

                chunk_len = size / 2;
                if (check_nil && strnlen(out, chunk_len) < chunk_len)
                        return 1;

                addr += chunk_len;
                out += chunk_len;
                len -= chunk_len;
        }

        return 0;
}


int
gdb_umoven (struct tcb *const tcp, kernel_ulong_t addr, unsigned int len,
		void *const our_addr)
{
	return gdb_read_mem(tcp->pid, addr, len, false, our_addr);
}


int
gdb_umovestr (struct tcb *const tcp, kernel_ulong_t addr, unsigned int len, char *laddr)
{
	return gdb_read_mem(tcp->pid, addr, len, true, laddr);
}

int
gdb_upeek(int pid, unsigned long off, kernel_ulong_t *res)
{
       return gdb_read_mem(pid, off, current_wordsize, false, (char*)res);
}


int
gdb_getfdpath(struct tcb *tcp, int fd, char *buf, unsigned bufsize)
{
        if (!gdb || fd < 0)
                return -1;

        /*
         * As long as we assume a Linux target, we can peek at their procfs
         * just like normal getfdpath does.  Maybe that won't always be true.
         */
        char linkpath[sizeof("/proc/%u/fd/%u") + 2 * sizeof(int)*3];
        sprintf(linkpath, "/proc/%u/fd/%u", tcp->pid, fd);
        return gdb_readlink(gdb, linkpath, buf, bufsize);
}


bool
gdb_verify_args (const char *username, bool daemon, unsigned int *follow_fork)
{
	if (username) {
		error_msg_and_die("-u and -G are mutually exclusive");
	}

	if (daemon) {
		error_msg_and_die("-D and -G are mutually exclusive");
	}

	if (!*follow_fork) {
		error_msg("-G is always multithreaded, implies -f");
		*follow_fork = 1;
	}
	return true;
}


bool
gdb_handle_arg (char arg, char *optarg)
{
	if (arg != 'G')
		return false;

	gdbserver = optarg;
	backend.cleanup = gdb_cleanup;
	backend.detach = gdb_detach;
	backend.end_init = gdb_end_init;
	backend.get_regs = gdb_get_regs;
	backend.get_scno = gdb_get_scno;
	backend.getfdpath = gdb_getfdpath;
        backend.prog_pid_check = gdb_prog_pid_check;
	backend.start_init = gdb_start_init;
	backend.startup_attach = gdb_startup_attach;
	backend.startup_child = gdb_startup_child;
	backend.next_event = gdb_next_event;
	backend.dispatch_event = gdb_dispatch_event;
	backend.umoven = gdb_umoven;
	backend.umovestr = gdb_umovestr;
	backend.upeek_ = gdb_upeek;
	backend.verify_args = gdb_verify_args;
	return true;
}