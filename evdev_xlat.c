#include "defs.h"

#ifdef HAVE_LINUX_INPUT_H

# include <linux/ioctl.h>
# include <linux/input.h>

# include "xlat/evdev_abs.h"
# include "xlat/evdev_autorepeat.h"
# include "xlat/evdev_ff_status.h"
# include "xlat/evdev_ff_types.h"
# include "xlat/evdev_keycode.h"
# include "xlat/evdev_leds.h"
# include "xlat/evdev_misc.h"
# include "xlat/evdev_prop.h"
# include "xlat/evdev_relative_axes.h"
# include "xlat/evdev_snd.h"
# include "xlat/evdev_switch.h"
# include "xlat/evdev_sync.h"

void print_evdev_ff_type(const kernel_ulong_t val)
{
	printxval(evdev_ff_types, val, "FF_???");
}

void print_evdev_keycode(const unsigned int keycode)
{
	printxval(evdev_keycode, keycode, "KEY_???");
}

static int
decode_bitset(struct tcb *const tcp, const kernel_ulong_t arg,
	      const struct xlat decode_nr[], const unsigned int max_nr,
	      const char *const dflt)
{
	tprints(", ");

	unsigned int size;
	if ((kernel_ulong_t) tcp->u_rval > max_nr)
		size = max_nr;
	else
		size = tcp->u_rval;
	char decoded_arg[size];

	if (umove_or_printaddr(tcp, arg, &decoded_arg))
		return RVAL_IOCTL_DECODED;

	tprints("[");

	int bit_displayed = 0;
	int i = next_set_bit(decoded_arg, 0, size);
	if (i < 0) {
		tprints(" 0 ");
	} else {
		printxval(decode_nr, i, dflt);

		while ((i = next_set_bit(decoded_arg, i + 1, size)) > 0) {
			if (abbrev(tcp) && bit_displayed >= 3) {
				tprints(", ...");
				break;
			}
			tprints(", ");
			printxval(decode_nr, i, dflt);
			bit_displayed++;
		}
	}

	tprints("]");

	return RVAL_IOCTL_DECODED;
}

int
bit_ioctl(struct tcb *const tcp, const unsigned int ev_nr,
	  const kernel_ulong_t arg)
{
	switch (ev_nr) {
		case EV_SYN:
			return decode_bitset(tcp, arg, evdev_sync,
					     SYN_MAX, "SYN_???");
		case EV_KEY:
			return decode_bitset(tcp, arg, evdev_keycode,
					     KEY_MAX, "KEY_???");
		case EV_REL:
			return decode_bitset(tcp, arg, evdev_relative_axes,
					     REL_MAX, "REL_???");
		case EV_ABS:
			return decode_bitset(tcp, arg, evdev_abs,
					     ABS_MAX, "ABS_???");
		case EV_MSC:
			return decode_bitset(tcp, arg, evdev_misc,
					     MSC_MAX, "MSC_???");
# ifdef EV_SW
		case EV_SW:
			return decode_bitset(tcp, arg, evdev_switch,
					     SW_MAX, "SW_???");
# endif
		case EV_LED:
			return decode_bitset(tcp, arg, evdev_leds,
					     LED_MAX, "LED_???");
		case EV_SND:
			return decode_bitset(tcp, arg, evdev_snd,
					     SND_MAX, "SND_???");
		case EV_REP:
			return decode_bitset(tcp, arg, evdev_autorepeat,
					     REP_MAX, "REP_???");
		case EV_FF:
			return decode_bitset(tcp, arg, evdev_ff_types,
					     FF_MAX, "FF_???");
		case EV_PWR:
			tprints(", ");
			printnum_int(tcp, arg, "%d");
			return RVAL_IOCTL_DECODED;
		case EV_FF_STATUS:
			return decode_bitset(tcp, arg, evdev_ff_status,
					     FF_STATUS_MAX, "FF_STATUS_???");
		default:
			tprints(", ");
			printaddr(arg);
			return RVAL_IOCTL_DECODED;
	}
}

int
evdev_bitset_ioctl(struct tcb * const tcp, const unsigned int code,
		   const kernel_ulong_t arg)
{
	switch (_IOC_NR(code)) {
# ifdef EVIOCGPROP
		case _IOC_NR(EVIOCGPROP(0)):
			return decode_bitset(tcp, arg, evdev_prop,
					     INPUT_PROP_MAX, "PROP_???");
# endif
		case _IOC_NR(EVIOCGSND(0)):
			return decode_bitset(tcp, arg, evdev_snd,
					     SND_MAX, "SND_???");
# ifdef EVIOCGSW
		case _IOC_NR(EVIOCGSW(0)):
			return decode_bitset(tcp, arg, evdev_switch,
					     SW_MAX, "SW_???");
# endif
		case _IOC_NR(EVIOCGKEY(0)):
			return decode_bitset(tcp, arg, evdev_keycode,
					     KEY_MAX, "KEY_???");
		case _IOC_NR(EVIOCGLED(0)):
			return decode_bitset(tcp, arg, evdev_leds,
					     LED_MAX, "LED_???");
	}

	error_func_msg("Unexpected code: %u", code);

	return -1;
}

#endif /* HAVE_LINUX_INPUT_H */
