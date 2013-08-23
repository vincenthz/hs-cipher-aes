/*
 * Copyright (c) 2012 Vincent Hanquez <vincent@snarc.org>
 * 
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
 * 3. Neither the name of the author nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef BLOCK128_H
#define BLOCK128_H

#include "bitfn.h"

typedef union {
       uint64_t q[2];
       uint32_t d[4];
       uint16_t w[8];
       uint8_t  b[16];
} block128;

static inline void block128_copy_bytes(block128 *block, uint8_t *src, uint32_t len)
{
	int i;
	for (i = 0; i < len; i++) block->b[i] = src[i];
}

static inline void block128_copy(block128 *d, block128 *s)
{
	d->q[0] = s->q[0]; d->q[1] = s->q[1];
}

static inline void block128_zero(block128 *d)
{
	d->q[0] = 0; d->q[1] = 0;
}

static inline void block128_xor(block128 *d, block128 *s)
{
	d->q[0] ^= s->q[0];
	d->q[1] ^= s->q[1];
}

static inline void block128_vxor(block128 *d, block128 *s1, block128 *s2)
{
	d->q[0] = s1->q[0] ^ s2->q[0];
	d->q[1] = s1->q[1] ^ s2->q[1];
}

static inline void block128_xor_bytes(block128 *block, uint8_t *src, uint32_t len)
{
	int i;
	for (i = 0; i < len; i++) block->b[i] ^= src[i];
}

static inline void block128_inc_be(block128 *b)
{
	uint64_t v = be64_to_cpu(b->q[1]);
	if (++v == 0) {
		b->q[0] = cpu_to_be64(be64_to_cpu(b->q[0]) + 1);
		b->q[1] = 0;
	} else
		b->q[1] = cpu_to_be64(v);
}

#ifdef IMPL_DEBUG
#include <stdio.h>
static inline void block128_print(block128 *b)
{
	int i;
	for (i = 0; i < 16; i++) {
		printf("%02x ", b->b[i]);
	}
	printf("\n");
}
#endif

#endif
