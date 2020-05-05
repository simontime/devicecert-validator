// Copyright 2007,2008  Segher Boessenkool  <segher@kernel.crashing.org>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
// obtained from http://git.infradead.org/?p=users/segher/wii.git

#include <string.h>
#include <stdio.h>

#include "types.h"

static void bn_zero(u8 *d, u32 n)
{
	memset(d, 0, n);
}

static void bn_copy(u8 *d, u8 *a, u32 n)
{
	memcpy(d, a, n);
}

int bn_compare(u8 *a, u8 *b, u32 n)
{
	u32 i;

	for (i = 0; i < n; i++) {
		if (a[i] < b[i])
			return -1;
		if (a[i] > b[i])
			return 1;
	}

	return 0;
}

void bn_sub_modulus(u8 *a, u8 *N, u32 n)
{
	u32 i;
	u32 dig;
	u8 c;

	c = 0;
	for (i = n - 1; i < n; i--) {
		dig = N[i] + c;
		c = (a[i] < dig);
		a[i] -= dig;
	}
}

void bn_add(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	u32 i;
	u32 dig;
	u8 c;

	c = 0;
	for (i = n - 1; i < n; i--) {
		dig = a[i] + b[i] + c;
		c = (dig >= 0x100);
		d[i] = (u8)dig;
	}

	if (c)
		bn_sub_modulus(d, N, n);

	if (bn_compare(d, N, n) >= 0)
		bn_sub_modulus(d, N, n);
}

void bn_mul(u8 *d, u8 *a, u8 *b, u8 *N, u32 n)
{
	u32 i;
	u8 mask;

	bn_zero(d, n);

	for (i = 0; i < n; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			bn_add(d, d, d, N, n);
			if ((a[i] & mask) != 0)
				bn_add(d, d, b, N, n);
		}
}

void bn_exp(u8 *d, u8 *a, u8 *N, u32 n, u8 *e, u32 en)
{
	u8 t[512];
	u32 i;
	u8 mask;

	bn_zero(d, n);
	d[n-1] = 1;
	for (i = 0; i < en; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			bn_mul(t, d, d, N, n);
			if ((e[i] & mask) != 0)
				bn_mul(d, t, a, N, n);
			else
				bn_copy(d, t, n);
		}
}

// only for prime N -- stupid but lazy, see if I care
void bn_inv(u8 *d, u8 *a, u8 *N, u32 n)
{
	u8 t[512], s[512];

	bn_copy(t, N, n);
	bn_zero(s, n);
	s[n-1] = 2;
	bn_sub_modulus(t, s, n);
	bn_exp(d, a, N, n, t, n);
}

void bn_shiftr(u8 *in, u32 size, u32 shiftn){ //this is to help convert sha1 ecdsa to sha256. this curve is limited to 233 bits so the 256 bit hash needs to be shifted right 23 bits. 
	u8 carry=0;
	u8 temp=0;
	for(int j=0;j<shiftn;j++){
		for(int i=0;i<size;i++){
			temp=*(in+i) & 1;
			*(in+i)=(*(in+i) >> 1 ) | carry<<7;
			carry=temp;
		}
		carry=0; temp=0;
	}
}

// order of the addition group of points
static u8 ec_N[30] =
{
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0xE9, 0x74, 0xE7, 0x2F,
	0x8A, 0x69, 0x22, 0x03, 0x1D, 0x26, 0x03, 0xCF, 0xE0, 0xD7
};

// base point
static u8 ec_G[60] =
{
	0x00, 0xFA, 0xC9, 0xDF, 0xCB, 0xAC, 0x83, 0x13, 0xBB, 0x21,
	0x39, 0xF1, 0xBB, 0x75, 0x5F, 0xEF, 0x65, 0xBC, 0x39, 0x1F,
	0x8B, 0x36, 0xF8, 0xF8, 0xEB, 0x73, 0x71, 0xFD, 0x55, 0x8B,
	0x01, 0x00, 0x6A, 0x08, 0xA4, 0x19, 0x03, 0x35, 0x06, 0x78,
	0xE5, 0x85, 0x28, 0xBE, 0xBF, 0x8A, 0x0B, 0xEF, 0xF8, 0x67,
	0xA7, 0xCA, 0x36, 0x71, 0x6F, 0x7E, 0x01, 0xF8, 0x10, 0x52
};

static void elt_copy(u8 *d, u8 *a)
{
	memcpy(d, a, 30);
}

static void elt_zero(u8 *d)
{
	memset(d, 0, 30);
}

static int elt_is_zero(u8 *d)
{
	u32 i;

	for (i = 0; i < 30; i++)
		if (d[i] != 0)
			return 0;

	return 1;
}

static void elt_add(u8 *d, u8 *a, u8 *b)
{
	u32 i;

	for (i = 0; i < 30; i++)
		d[i] = a[i] ^ b[i];
}

static void elt_mul_x(u8 *d, u8 *a)
{
	u8 carry, x, y;
	u32 i;

	carry = a[0] & 1;

	x = 0;
	for (i = 0; i < 29; i++) {
		y = a[i + 1];
		d[i] = x ^ (y >> 7);
		x = (u8)(y << 1);
	}
	d[29] = x ^ carry;

	d[20] ^= carry << 2;
}

static void elt_mul(u8 *d, u8 *a, u8 *b)
{
	u32 i, n;
	u8 mask;

	elt_zero(d);

	i = 0;
	mask = 1;
	for (n = 0; n < 233; n++) {
		elt_mul_x(d, d);

		if ((a[i] & mask) != 0)
			elt_add(d, d, b);

		mask >>= 1;
		if (mask == 0) {
			mask = 0x80;
			i++;
		}
	}
}

static const u8 square[16] =
	{ 0x00, 0x01, 0x04, 0x05, 0x10, 0x11, 0x14, 0x15, 0x40, 0x41, 0x44, 0x45, 0x50, 0x51, 0x54, 0x55 };

static void elt_square_to_wide(u8 *d, u8 *a)
{
	u32 i;

	for (i = 0; i < 30; i++) {
		d[2*i] = square[a[i] >> 4];
		d[2*i + 1] = square[a[i] & 15];
	}
}

static void wide_reduce(u8 *d)
{
	u32 i;
	u8 x;

	for (i = 0; i < 30; i++) {
		x = d[i];

		d[i + 19] ^= x >> 7;
		d[i + 20] ^= x << 1;

		d[i + 29] ^= x >> 1;
		d[i + 30] ^= x << 7;
	}

	x = d[30] & ~1;

	d[49] ^= x >> 7;
	d[50] ^= x << 1;

	d[59] ^= x >> 1;

	d[30] &= 1;
}

static void elt_square(u8 *d, u8 *a)
{
	u8 wide[60];

	elt_square_to_wide(wide, a);
	wide_reduce(wide);

	elt_copy(d, wide + 30);
}

static void itoh_tsujii(u8 *d, u8 *a, u8 *b, u32 j)
{
	u8 t[30];

	elt_copy(t, a);
	while (j--) {
		elt_square(d, t);
		elt_copy(t, d);
	}

	elt_mul(d, t, b);
}

static void elt_inv(u8 *d, u8 *a)
{
	u8 t[30];
	u8 s[30];

	itoh_tsujii(t, a, a, 1);
	itoh_tsujii(s, t, a, 1);
	itoh_tsujii(t, s, s, 3);
	itoh_tsujii(s, t, a, 1);
	itoh_tsujii(t, s, s, 7);
	itoh_tsujii(s, t, t, 14);
	itoh_tsujii(t, s, a, 1);
	itoh_tsujii(s, t, t, 29);
	itoh_tsujii(t, s, s, 58);
	itoh_tsujii(s, t, t, 116);
	elt_square(d, s);
}

static int point_is_zero(u8 *p)
{
	return elt_is_zero(p) && elt_is_zero(p + 30);
}

static void point_double(u8 *r, u8 *p)
{
	u8 s[30], t[30];
	u8 *px, *py, *rx, *ry;

	px = p;
	py = p + 30;
	rx = r;
	ry = r + 30;

	if (elt_is_zero(px)) {
		elt_zero(rx);
		elt_zero(ry);

		return;
	}

	elt_inv(t, px); // t = 1/px
	elt_mul(s, py, t); // s = py/px
	elt_add(s, s, px); // s = py/px + px

	elt_square(t, px); // t = px*px

	elt_square(rx, s); // rx = s*s
	elt_add(rx, rx, s); // rx = s*s + s
	rx[29] ^= 1; // rx = s*s + s + 1

	elt_mul(ry, s, rx); // ry = s * rx
	elt_add(ry, ry, rx); // ry = s*rx + rx
	elt_add(ry, ry, t); // ry = s*rx + rx + px*px
}

static void point_add(u8 *r, u8 *p, u8 *q)
{
	u8 s[30], t[30], u[30];
	u8 *px, *py, *qx, *qy, *rx, *ry;

	px = p;
	py = p + 30;
	qx = q;
	qy = q + 30;
	rx = r;
	ry = r + 30;

	if (point_is_zero(p)) {
		elt_copy(rx, qx);
		elt_copy(ry, qy);
		return;
	}

	if (point_is_zero(q)) {
		elt_copy(rx, px);
		elt_copy(ry, py);
		return;
	}

	elt_add(u, px, qx);

	if (elt_is_zero(u)) {
		elt_add(u, py, qy);
		if (elt_is_zero(u))
			point_double(r, p);
		else {
			elt_zero(rx);
			elt_zero(ry);
		}

		return;
	}

	elt_inv(t, u);
	elt_add(u, py, qy);
	elt_mul(s, t, u);

	elt_square(t, s);
	elt_add(t, t, s);
	elt_add(t, t, qx);
	t[29] ^= 1;

	elt_mul(u, s, t);
	elt_add(s, u, py);
	elt_add(rx, t, px);
	elt_add(ry, s, rx);
}

static void point_mul(u8 *d, u8 *a, u8 *b)	// a is bignum
{
	u32 i;
	u8 mask;

	elt_zero(d);
	elt_zero(d + 30);

	for (i = 0; i < 30; i++)
		for (mask = 0x80; mask != 0; mask >>= 1) {
			point_double(d, d);
			if ((a[i] & mask) != 0)
				point_add(d, d, b);
		}
}

int check_ecdsa(u8 *Q, u8 *R, u8 *S, u8 *hash, int isSHA256)
{
	u8 Sinv[30];
	u8 e[30];
	u8 w1[30], w2[30];
	u8 r1[60], r2[60];

	bn_inv(Sinv, S, ec_N, 30);

	elt_zero(e);

	if (isSHA256)
	{
		bn_shiftr(hash, 32, 7);  //shift right 7 bits.
		memcpy(e, hash, 30);     //then shift 16 more bits right by cutting off the last two bytes of 32 byte sha256.
    	                         //this gets our bignum sha256 hash to fit in the 233 bit limit of this ecdsa curve.
	}
	else
	{
		// Simon - New addition: added support for SHA1, very insecure as top 80 bits are always zeroes
		memcpy(e + 10, hash, 20);
	}

	bn_mul(w1, e, Sinv, ec_N, 30);
	bn_mul(w2, R, Sinv, ec_N, 30);

	point_mul(r1, w1, ec_G);
	point_mul(r2, w2, Q);

	point_add(r1, r1, r2);

	if (bn_compare(r1, ec_N, 30) >= 0)
		bn_sub_modulus(r1, ec_N, 30);

	return (bn_compare(r1, R, 30) == 0);
}