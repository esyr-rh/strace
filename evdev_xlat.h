#ifndef _STRACE_EVDEV_XLAT_H_
#define _STRACE_EVDEV_XLAT_H_

extern void print_evdev_ff_type(const kernel_ulong_t val);
extern void print_evdev_keycode(const unsigned int keycode);

extern int bit_ioctl(struct tcb *const tcp, const unsigned int ev_nr,
		     const kernel_ulong_t arg);
extern int evdev_bitset_ioctl(struct tcb * const tcp, const unsigned int code,
			      const kernel_ulong_t arg);

#endif /* _STRACE_EVDEV_XLAT_H_ */
