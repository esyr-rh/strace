#include "defs.h"

#include <stdint.h>
#include <linux/videodev2.h>

/* v4l2_fourcc_be was added by Linux commit v3.18-rc1~101^2^2~127 */
#ifndef v4l2_fourcc_be
# define v4l2_fourcc_be(a, b, c, d) (v4l2_fourcc(a, b, c, d) | (1 << 31))
#endif

#include "xlat/v4l2_pix_fmts.h"
#include "xlat/v4l2_sdr_fmts.h"

static void
print_pixelformat(uint32_t fourcc, const struct xlat *xlat)
{
	unsigned char a[] = {
		(unsigned char) fourcc,
		(unsigned char) (fourcc >> 8),
		(unsigned char) (fourcc >> 16),
		(unsigned char) (fourcc >> 24),
	};
	unsigned int i;

	tprints("v4l2_fourcc(");
	for (i = 0; i < ARRAY_SIZE(a); ++i) {
		unsigned char c = a[i];

		if (i)
			tprints(", ");
		if (c == '\'' || c == '\\') {
			char sym[] = {
				'\'',
				'\\',
				c,
				'\'',
				'\0'
			};
			tprints(sym);
		} else if (c >= ' ' && c <= 0x7e) {
			char sym[] = {
				'\'',
				c,
				'\'',
				'\0'
			};
			tprints(sym);
		} else {
			char hex[] = {
				'\'',
				'\\',
				'x',
				"0123456789abcdef"[c >> 4],
				"0123456789abcdef"[c & 0xf],
				'\'',
				'\0'
			};
			tprints(hex);
		}
	}
	tprints(")");

	if (xlat) {
		const char *pixfmt_name = xlookup(xlat, fourcc);

		if (pixfmt_name)
			tprints_comment(pixfmt_name);
	}
}

void
print_pix_fmt(uint32_t fourcc)
{
	print_pixelformat(fourcc, v4l2_pix_fmts);
}

void
print_sdr_fmt(uint32_t fourcc)
{
	print_pixelformat(fourcc, v4l2_sdr_fmts);
}
