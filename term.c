/*
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-2018 The strace developers.
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
/*
 * The C library's definition of struct termios might differ from
 * the kernel one, and we need to use the kernel layout.
 */
#include <linux/termios.h>

#include "xlat/tcxonc_options.h"
#include "xlat/tcflsh_options.h"
#include "xlat/baud_options.h"
#include "xlat/modem_flags.h"

#include "xlat/term_cflags.h"
#include "xlat/term_cflags_csize.h"
#include "xlat/term_iflags.h"
#include "xlat/term_lflags.h"
#include "xlat/term_oflags.h"
#include "xlat/term_oflags_bsdly.h"
#include "xlat/term_oflags_crdly.h"
#include "xlat/term_oflags_ffdly.h"
#include "xlat/term_oflags_nldly.h"
#include "xlat/term_oflags_tabdly.h"
#include "xlat/term_oflags_vtdly.h"

#include "xlat/term_line_discs.h"

#include "xlat/termio_cc.h"
#include "xlat/termios_cc.h"

#if !defined IBSHIFT && defined CIBAUD \
	&& ((CIBAUD == 002003600000) \
	 || (CIBAUD == 077600000) \
	 || (CIBAUD == 0x100f0000))
# define IBSHIFT 16
#endif


static void
decode_oflag(uint64_t val, size_t oflag_size)
{
	static const struct {
		const struct xlat *xl;
		uint64_t mask;
		const char *dfl;
	} xlats[] = {
		{ term_oflags_nldly,  NLDLY,  "NL?"  },
		{ term_oflags_crdly,  CRDLY,  "CR?"  },
		{ term_oflags_tabdly, TABDLY, "TAB?" },
		{ term_oflags_bsdly,  BSDLY,  "BS?"  },
		{ term_oflags_vtdly,  VTDLY,  "VT?"  },
		{ term_oflags_ffdly,  FFDLY,  "FF?"  },
	};

	unsigned i;
	uint64_t mask = (1ULL << (oflag_size * 8)) - 1;

	for (i = 0; i < ARRAY_SIZE(xlats); i++) {
		if (!(xlats[i].mask & mask))
			continue;

		printxval64(xlats[i].xl, val & xlats[i].mask, xlats[i].dfl);
		tprints("|");

		val &= ~xlats[i].mask;
	}

	printflags64(term_oflags, val, NULL);
}

static void
decode_cflag(uint64_t val)
{
	printxval64(baud_options, val & CBAUD, "B???");
	tprints("|");
#if defined CIBAUD && defined IBSHIFT
	if (val & CIBAUD) {
		printxval64(baud_options, (val & CIBAUD) >> IBSHIFT, "B???");
		tprintf("<<IBSHIFT|");
	}
#else
/* In order to simplify following val &= ~(CBAUD | CIBAUD | CSIZE); */
# define CIBAUD 0
#endif /* defined CIBAUD && defined IBSHIFT */
	printxval64(term_cflags_csize, val & CSIZE, "CS?");
	tprints("|");

	val &= ~(CBAUD | CIBAUD | CSIZE);
	printflags64(term_cflags, val, NULL);
}

static void
decode_flags(uint64_t iflag, uint64_t oflag, uint64_t cflag, uint64_t lflag,
	     size_t oflag_size)
{
	tprints("c_iflag=");
	printflags64(term_iflags, iflag, NULL);
	tprints(", c_oflag=");
	decode_oflag(oflag, oflag_size);
	tprints(", c_cflag=");
	decode_cflag(cflag);
	tprints(", c_lflag=");
	printflags64(term_lflags, lflag, NULL);
}

static void
decode_line_disc(uint64_t line)
{
	tprints("c_line=");
	printxval(term_line_discs, line, "N_???");
}

static void
print_cc_char(bool *first, const unsigned char *data, const char *s,
	      unsigned idx)
{
	if (*first)
		*first = false;
	else
		tprints(", ");

	if (s)
		tprintf("[%s] = ", s);
	else
		tprintf("[%u] = ", idx);

	tprintf("%#hhx", data[idx]);
}

static void
decode_term_cc(const struct xlat *xl, const unsigned char *data, unsigned size)
{
	unsigned i = 0;
	bool first = true;

	tprints("[");

	for (i = 0; i < size; i++)
		print_cc_char(&first, data, xlookup(xl, i), i);

	tprints("]");
}

#ifdef HAVE_STRUCT_TERMIOS2
static void
decode_termios2(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct termios2 tios;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &tios))
		return;

	tprints("{");
	decode_flags(tios.c_iflag, tios.c_oflag, tios.c_cflag, tios.c_lflag,
		     sizeof(tios.c_oflag));
	tprints(", ");

	if (abbrev(tcp)) {
		tprints("...");
	} else {
		decode_line_disc(tios.c_line);

		if (!(tios.c_lflag & ICANON))
			tprintf(", c_cc[VMIN]=%u, c_cc[VTIME]=%u",
				tios.c_cc[VMIN], tios.c_cc[VTIME]);
		tprints(", c_cc=");
		/* SPARC has two additional bytes in c_cc. */
		decode_term_cc(termios_cc, tios.c_cc, sizeof(tios.c_cc));

		tprintf(", c_ispeed=%u", tios.c_ispeed);
		tprintf(", c_ospeed=%u", tios.c_ospeed);
	}
	tprints("}");
}
#endif /* HAVE_STRUCT_TERMIOS2 */

static void
decode_termios(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct termios tios;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &tios))
		return;

	tprints("{");
	decode_flags(tios.c_iflag, tios.c_oflag, tios.c_cflag, tios.c_lflag,
		     sizeof(tios.c_oflag));
	tprints(", ");

	if (abbrev(tcp)) {
		tprints("...");
	} else {
		decode_line_disc(tios.c_line);

		if (!(tios.c_lflag & ICANON))
			tprintf(", c_cc[VMIN]=%u, c_cc[VTIME]=%u",
				tios.c_cc[VMIN], tios.c_cc[VTIME]);
		tprints(", c_cc=");
		/*
		 * Fun fact: MIPS has NCCS defined to 23, SPARC to 17 and
		 * everything else to 19.
		 */
		decode_term_cc(termios_cc, tios.c_cc,
			       MIN(NCCS, sizeof(tios.c_cc)));

		/*
		 * alpha and powerpc have those in struct termios instead of
		 * having a separate struct termios2.
		 */
#ifdef HAVE_STRUCT_TERMIOS_C_ISPEED
		tprintf(", c_ispeed=%u", tios.c_ispeed);
#endif
#ifdef HAVE_STRUCT_TERMIOS_C_OSPEED
		tprintf(", c_ospeed=%u", tios.c_ospeed);
#endif
	}
	tprints("}");
}

static void
decode_termio(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct termio tio;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &tio))
		return;

	tprints("{");
	decode_flags(tio.c_iflag, tio.c_oflag, tio.c_cflag, tio.c_lflag,
		     sizeof(tio.c_oflag));
	tprints(", ");

	if (abbrev(tcp)) {
		tprints("...");
	} else {
		decode_line_disc(tio.c_line);

#ifdef _VMIN /* thanks, alpha and powerpc */
		if (!(tio.c_lflag & ICANON))
			tprintf(", c_cc[_VMIN]=%d, c_cc[_VTIME]=%d",
				tio.c_cc[_VMIN], tio.c_cc[_VTIME]);

		tprints(", c_cc=");
		decode_term_cc(termio_cc, tio.c_cc,
			       MIN(NCC, sizeof(tio.c_cc)));
#else /* !_VMIN */
		if (!(tio.c_lflag & ICANON))
			tprintf(", c_cc[VMIN]=%d, c_cc[VTIME]=%d",
				tio.c_cc[VMIN], tio.c_cc[VTIME]);

		tprints(", c_cc=");
		decode_term_cc(termios_cc, tio.c_cc,
			       MIN(NCC, sizeof(tio.c_cc)));
#endif /* !_VMIN */
	}

	tprints("}");
}

static void
decode_winsize(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct winsize ws;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &ws))
		return;
	tprintf("{ws_row=%d, ws_col=%d, ws_xpixel=%d, ws_ypixel=%d}",
		ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
}

#ifdef TIOCGSIZE
static void
decode_ttysize(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct ttysize ts;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &ts))
		return;
	tprintf("{ts_lines=%d, ts_cols=%d}",
		ts.ts_lines, ts.ts_cols);
}
#endif

static void
decode_modem_flags(struct tcb *const tcp, const kernel_ulong_t addr)
{
	int i;

	tprints(", ");
	if (umove_or_printaddr(tcp, addr, &i))
		return;
	tprints("[");
	printflags(modem_flags, i, "TIOCM_???");
	tprints("]");
}

int
term_ioctl(struct tcb *const tcp, const unsigned int code,
	   const kernel_ulong_t arg)
{
	switch (code) {
#ifdef HAVE_STRUCT_TERMIOS2
	/* struct termios2 */
#ifdef TCGETS2
	case TCGETS2:
#endif
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
#ifdef TCSETS2
	case TCSETS2:
#endif
#ifdef TCSETSW2
	case TCSETSW2:
#endif
#ifdef TCSETSF2
	case TCSETSF2:
#endif
		decode_termios2(tcp, arg);
		break;
#endif /* HAVE_STRUCT_TERMIOS2 */

	/* struct termios */
	case TCGETS:
	case TIOCGLCKTRMIOS:
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
	case TCSETS:
	case TCSETSW:
	case TCSETSF:
	case TIOCSLCKTRMIOS:
		decode_termios(tcp, arg);
		break;

	/* struct termio */
	case TCGETA:
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
	case TCSETA:
	case TCSETAW:
	case TCSETAF:
		decode_termio(tcp, arg);
		break;

	/* struct winsize */
	case TIOCGWINSZ:
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
	case TIOCSWINSZ:
		decode_winsize(tcp, arg);
		break;

	/* struct ttysize */
#ifdef TIOCGSIZE
	case TIOCGSIZE:
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
	case TIOCSSIZE:
		decode_ttysize(tcp, arg);
		break;
#endif

	/* ioctls with a direct decodable arg */
	case TCXONC:
		tprints(", ");
		printxval64(tcxonc_options, arg, "TC???");
		break;
	case TCFLSH:
		tprints(", ");
		printxval64(tcflsh_options, arg, "TC???");
		break;
	case TCSBRK:
	case TCSBRKP:
	case TIOCSCTTY:
		tprintf(", %d", (int) arg);
		break;

	/* ioctls with an indirect parameter displayed as modem flags */
	case TIOCMGET:
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
	case TIOCMBIS:
	case TIOCMBIC:
	case TIOCMSET:
		decode_modem_flags(tcp, arg);
		break;

	/* ioctls with an indirect parameter displayed in decimal */
	case TIOCGPGRP:
	case TIOCGSID:
	case TIOCGETD:
	case TIOCGSOFTCAR:
	case TIOCGPTN:
	case FIONREAD:
	case TIOCOUTQ:
#ifdef TIOCGEXCL
	case TIOCGEXCL:
#endif
#ifdef TIOCGDEV
	case TIOCGDEV:
#endif
		if (entering(tcp))
			return 0;
		ATTRIBUTE_FALLTHROUGH;
	case TIOCSPGRP:
	case TIOCSETD:
	case FIONBIO:
	case FIOASYNC:
	case TIOCPKT:
	case TIOCSSOFTCAR:
	case TIOCSPTLCK:
		tprints(", ");
		printnum_int(tcp, arg, "%d");
		break;

	/* ioctls with an indirect parameter displayed as a char */
	case TIOCSTI:
		tprints(", ");
		printstrn(tcp, arg, 1);
		break;

	/* ioctls with no parameters */

	case TIOCSBRK:
	case TIOCCBRK:
	case TIOCCONS:
	case TIOCNOTTY:
	case TIOCEXCL:
	case TIOCNXCL:
	case FIOCLEX:
	case FIONCLEX:
#ifdef TIOCVHANGUP
	case TIOCVHANGUP:
#endif
#ifdef TIOCSSERIAL
	case TIOCSSERIAL:
#endif
		break;

	/* ioctls which are unknown */

	default:
		return RVAL_DECODED;
	}

	return RVAL_IOCTL_DECODED;
}
