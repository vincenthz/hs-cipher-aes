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
#include <wmmintrin.h>
#include <tmmintrin.h>
#include "aes.h"
#include "aes_x86ni.h"
#include "cpu.h"

#ifdef ARCH_X86
#define ALIGN_UP(addr, size) (((addr) + ((size) - 1)) & (~((size) - 1)))
#define ALIGNMENT(n) __attribute__((aligned(n)))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened)
{
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

static void aes_generate_key128(aes_key *key, uint8_t *ikey)
{
	__m128i k[20];
	uint64_t *out = (uint64_t *) key->data;
	int i;

	k[0] = _mm_loadu_si128((const __m128i*) ikey);

#define AES_128_key_exp(K, RCON) aes_128_key_expansion(K, _mm_aeskeygenassist_si128(K, RCON))
	k[1]  = AES_128_key_exp(k[0], 0x01);
	k[2]  = AES_128_key_exp(k[1], 0x02);
	k[3]  = AES_128_key_exp(k[2], 0x04);
	k[4]  = AES_128_key_exp(k[3], 0x08);
	k[5]  = AES_128_key_exp(k[4], 0x10);
	k[6]  = AES_128_key_exp(k[5], 0x20);
	k[7]  = AES_128_key_exp(k[6], 0x40);
	k[8]  = AES_128_key_exp(k[7], 0x80);
	k[9]  = AES_128_key_exp(k[8], 0x1B);
	k[10] = AES_128_key_exp(k[9], 0x36);

	/* generate decryption keys in reverse order.
	 * k[10] is shared by last encryption and first decryption rounds
	 * k[20] is shared by first encryption round (and is the original user key) */
	k[11] = _mm_aesimc_si128(k[9]);
	k[12] = _mm_aesimc_si128(k[8]);
	k[13] = _mm_aesimc_si128(k[7]);
	k[14] = _mm_aesimc_si128(k[6]);
	k[15] = _mm_aesimc_si128(k[5]);
	k[16] = _mm_aesimc_si128(k[4]);
	k[17] = _mm_aesimc_si128(k[3]);
	k[18] = _mm_aesimc_si128(k[2]);
	k[19] = _mm_aesimc_si128(k[1]);

	for (i = 0; i < 20; i++)
		_mm_storeu_si128(((__m128i *) out) + i, k[i]);
}

void aes_ni_init(aes_key *key, uint8_t *origkey, uint8_t size)
{
	switch (size) {
	case 16: aes_generate_key128(key, origkey); break;
	default: break;
	}
}


#define PRELOAD_ENC_KEYS(k) \
	__m128i K0  = _mm_loadu_si128(((__m128i *) k)+0); \
	__m128i K1  = _mm_loadu_si128(((__m128i *) k)+1); \
	__m128i K2  = _mm_loadu_si128(((__m128i *) k)+2); \
	__m128i K3  = _mm_loadu_si128(((__m128i *) k)+3); \
	__m128i K4  = _mm_loadu_si128(((__m128i *) k)+4); \
	__m128i K5  = _mm_loadu_si128(((__m128i *) k)+5); \
	__m128i K6  = _mm_loadu_si128(((__m128i *) k)+6); \
	__m128i K7  = _mm_loadu_si128(((__m128i *) k)+7); \
	__m128i K8  = _mm_loadu_si128(((__m128i *) k)+8); \
	__m128i K9  = _mm_loadu_si128(((__m128i *) k)+9); \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+10);

#define DO_ENC_BLOCK(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesenc_si128(m, K1); \
	m = _mm_aesenc_si128(m, K2); \
	m = _mm_aesenc_si128(m, K3); \
	m = _mm_aesenc_si128(m, K4); \
	m = _mm_aesenc_si128(m, K5); \
	m = _mm_aesenc_si128(m, K6); \
	m = _mm_aesenc_si128(m, K7); \
	m = _mm_aesenc_si128(m, K8); \
	m = _mm_aesenc_si128(m, K9); \
	m = _mm_aesenclast_si128(m, K10);

#define PRELOAD_DEC_KEYS(k) \
	__m128i K0  = _mm_loadu_si128(((__m128i *) k)+10+0); \
	__m128i K1  = _mm_loadu_si128(((__m128i *) k)+10+1); \
	__m128i K2  = _mm_loadu_si128(((__m128i *) k)+10+2); \
	__m128i K3  = _mm_loadu_si128(((__m128i *) k)+10+3); \
	__m128i K4  = _mm_loadu_si128(((__m128i *) k)+10+4); \
	__m128i K5  = _mm_loadu_si128(((__m128i *) k)+10+5); \
	__m128i K6  = _mm_loadu_si128(((__m128i *) k)+10+6); \
	__m128i K7  = _mm_loadu_si128(((__m128i *) k)+10+7); \
	__m128i K8  = _mm_loadu_si128(((__m128i *) k)+10+8); \
	__m128i K9  = _mm_loadu_si128(((__m128i *) k)+10+9); \
	__m128i K10 = _mm_loadu_si128(((__m128i *) k)+0);

#define DO_DEC_BLOCK(m) \
	m = _mm_xor_si128(m, K0); \
	m = _mm_aesdec_si128(m, K1); \
	m = _mm_aesdec_si128(m, K2); \
	m = _mm_aesdec_si128(m, K3); \
	m = _mm_aesdec_si128(m, K4); \
	m = _mm_aesdec_si128(m, K5); \
	m = _mm_aesdec_si128(m, K6); \
	m = _mm_aesdec_si128(m, K7); \
	m = _mm_aesdec_si128(m, K8); \
	m = _mm_aesdec_si128(m, K9); \
	m = _mm_aesdeclast_si128(m, K10);

void aes_ni_encrypt_ecb(uint8_t *out, aes_key *key, uint8_t *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;

	PRELOAD_ENC_KEYS(k);

	while (blocks-- > 0) {
		__m128i m = _mm_loadu_si128((__m128i *) in);

		DO_ENC_BLOCK(m);

		_mm_storeu_si128((__m128i *) out, m);
		in += 16;
		out += 16;
	}
}

void aes_ni_decrypt_ecb(uint8_t *out, aes_key *key, uint8_t *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;

	PRELOAD_DEC_KEYS(k);

	while (blocks-- > 0) {
		__m128i m = _mm_loadu_si128((__m128i *) in);

		DO_DEC_BLOCK(m);

		_mm_storeu_si128((__m128i *) out, m);
		in += 16;
		out += 16;
	}
}

void aes_ni_encrypt_cbc(uint8_t *out, aes_key *key, uint8_t *_iv, uint8_t *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_ENC_KEYS(k);

	while (blocks-- > 0) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		m = _mm_xor_si128(m, iv);

		DO_ENC_BLOCK(m);

		_mm_storeu_si128((__m128i *) out, m);
		iv = m;

		in += 16;
		out += 16;
	}
}

void aes_ni_decrypt_cbc(uint8_t *out, aes_key *key, uint8_t *_iv, uint8_t *in, uint32_t blocks)
{
	__m128i *k = (__m128i *) key->data;
	__m128i iv = _mm_loadu_si128((__m128i *) _iv);

	PRELOAD_DEC_KEYS(k);

	while (blocks-- > 0) {
		__m128i m = _mm_loadu_si128((__m128i *) in);
		__m128i ivnext = m;

		DO_DEC_BLOCK(m);
		m = _mm_xor_si128(m, iv);

		_mm_storeu_si128((__m128i *) out, m);
		iv = ivnext;

		in += 16;
		out += 16;
	}
}

/* TO OPTIMISE: use pcmulqdq... or some faster code.
 * this is the lamest way of doing it, but i'm out of time.
 * this is basically a copy of gf_mulx in gf.c */
static __m128i gfmulx(__m128i v)
{
	uint64_t v_[2] ALIGNMENT(16);
	const uint64_t gf_mask = 0x8000000000000000;

	_mm_store_si128((__m128i *) v_, v);
	uint64_t r = ((v_[1] & gf_mask) ? 0x87 : 0);
	v_[1] = (v_[1] << 1) | (v_[0] & gf_mask ? 1 : 0);
	v_[0] = (v_[0] << 1) ^ r;
	v = _mm_load_si128((__m128i *) v_);
	return v;
}

void aes_ni_encrypt_xts(uint8_t *out, aes_key *key1, aes_key *key2,
                        uint8_t *_tweak, uint32_t spoint, uint8_t *in, uint32_t blocks)
{
	__m128i tweak = _mm_loadu_si128((__m128i *) _tweak);

	do {
		__m128i *k2 = (__m128i *) key2->data;
		PRELOAD_ENC_KEYS(k2);
		DO_ENC_BLOCK(tweak);

		while (spoint-- > 0)
			tweak = gfmulx(tweak);
	} while (0) ;

	do {
		__m128i *k1 = (__m128i *) key1->data;
		PRELOAD_ENC_KEYS(k1);

		for ( ; blocks-- > 0; in += 16, out += 16, tweak = gfmulx(tweak)) {
			__m128i m = _mm_loadu_si128((__m128i *) in);

			m = _mm_xor_si128(m, tweak);
			DO_ENC_BLOCK(m);
			m = _mm_xor_si128(m, tweak);

			_mm_storeu_si128((__m128i *) out, m);
		}
	} while (0);
}

#endif
