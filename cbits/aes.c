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

#include "cpu.h"
#include "aes.h"
#include "aes_generic.h"
#include "bitfn.h"
#include <string.h>
#include <stdio.h>

#include "gf.h"
#include "aes_x86ni.h"

void aes_generic_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
void aes_generic_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
void aes_generic_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
void aes_generic_decrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
void aes_generic_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t length);
void aes_generic_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks);
void aes_generic_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks);

enum {
	/* init */
	INIT_128, INIT_192, INIT_256,
	/* single block */
	ENCRYPT_BLOCK_128, ENCRYPT_BLOCK_192, ENCRYPT_BLOCK_256,
	DECRYPT_BLOCK_128, DECRYPT_BLOCK_192, DECRYPT_BLOCK_256,
	/* ecb */
	ENCRYPT_ECB_128, ENCRYPT_ECB_192, ENCRYPT_ECB_256,
	DECRYPT_ECB_128, DECRYPT_ECB_192, DECRYPT_ECB_256,
	/* cbc */
	ENCRYPT_CBC_128, ENCRYPT_CBC_192, ENCRYPT_CBC_256,
	DECRYPT_CBC_128, DECRYPT_CBC_192, DECRYPT_CBC_256,
	/* ctr */
	ENCRYPT_CTR_128, ENCRYPT_CTR_192, ENCRYPT_CTR_256,
	/* xts */
	ENCRYPT_XTS_128, ENCRYPT_XTS_192, ENCRYPT_XTS_256,
	DECRYPT_XTS_128, DECRYPT_XTS_192, DECRYPT_XTS_256,
};

void *branch_table[] = {
	/* INIT */
	[INIT_128]          = aes_generic_init,
	[INIT_192]          = aes_generic_init,
	[INIT_256]          = aes_generic_init,
	/* BLOCK */
	[ENCRYPT_BLOCK_128] = aes_generic_encrypt_block,
	[ENCRYPT_BLOCK_192] = aes_generic_encrypt_block,
	[ENCRYPT_BLOCK_256] = aes_generic_encrypt_block,
	[DECRYPT_BLOCK_128] = aes_generic_decrypt_block,
	[DECRYPT_BLOCK_192] = aes_generic_decrypt_block,
	[DECRYPT_BLOCK_256] = aes_generic_decrypt_block,
	/* ECB */
	[ENCRYPT_ECB_128]   = aes_generic_encrypt_ecb,
	[ENCRYPT_ECB_192]   = aes_generic_encrypt_ecb,
	[ENCRYPT_ECB_256]   = aes_generic_encrypt_ecb,
	[DECRYPT_ECB_128]   = aes_generic_decrypt_ecb,
	[DECRYPT_ECB_192]   = aes_generic_decrypt_ecb,
	[DECRYPT_ECB_256]   = aes_generic_decrypt_ecb,
	/* CBC */
	[ENCRYPT_CBC_128]   = aes_generic_encrypt_cbc,
	[ENCRYPT_CBC_192]   = aes_generic_encrypt_cbc,
	[ENCRYPT_CBC_256]   = aes_generic_encrypt_cbc,
	[DECRYPT_CBC_128]   = aes_generic_decrypt_cbc,
	[DECRYPT_CBC_192]   = aes_generic_decrypt_cbc,
	[DECRYPT_CBC_256]   = aes_generic_decrypt_cbc,
	/* CTR */
	[ENCRYPT_CTR_128]   = aes_generic_encrypt_ctr,
	[ENCRYPT_CTR_192]   = aes_generic_encrypt_ctr,
	[ENCRYPT_CTR_256]   = aes_generic_encrypt_ctr,
	/* XTS */
	[ENCRYPT_XTS_128]   = aes_generic_encrypt_xts,
	[ENCRYPT_XTS_192]   = aes_generic_encrypt_xts,
	[ENCRYPT_XTS_256]   = aes_generic_encrypt_xts,
	[DECRYPT_XTS_128]   = aes_generic_decrypt_xts,
	[DECRYPT_XTS_192]   = aes_generic_decrypt_xts,
	[DECRYPT_XTS_256]   = aes_generic_decrypt_xts,
};

typedef void (*init_f)(aes_key *, uint8_t *, uint8_t);
typedef void (*ecb_f)(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks);
typedef void (*cbc_f)(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks);
typedef void (*ctr_f)(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t length);
typedef void (*xts_f)(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit, uint32_t spoint, aes_block *input, uint32_t nb_blocks);
typedef void (*block_f)(aes_block *output, aes_key *key, aes_block *input);

#ifdef WITH_AESNI
#define GET_INIT(strength) \
	((init_f) (branch_table[INIT_128 + strength]))
#define GET_ECB_ENCRYPT(strength) \
	((ecb_f) (branch_table[ENCRYPT_ECB_128 + strength]))
#define GET_ECB_DECRYPT(strength) \
	((ecb_f) (branch_table[DECRYPT_ECB_128 + strength]))
#define GET_CBC_ENCRYPT(strength) \
	((cbc_f) (branch_table[ENCRYPT_CBC_128 + strength]))
#define GET_CBC_DECRYPT(strength) \
	((cbc_f) (branch_table[DECRYPT_CBC_128 + strength]))
#define GET_CTR_ENCRYPT(strength) \
	((ctr_f) (branch_table[ENCRYPT_CTR_128 + strength]))
#define GET_XTS_ENCRYPT(strength) \
	((xts_f) (branch_table[ENCRYPT_XTS_128 + strength]))
#define GET_XTS_DECRYPT(strength) \
	((xts_f) (branch_table[DECRYPT_XTS_128 + strength]))
#define aes_encrypt_block(o,k,i) \
	(((block_f) (branch_table[ENCRYPT_BLOCK_128 + k->strength]))(o,k,i))
#define aes_decrypt_block(o,k,i) \
	(((block_f) (branch_table[DECRYPT_BLOCK_128 + k->strength]))(o,k,i))
#else
#define GET_INIT(strenght) aes_generic_init
#define GET_ECB_ENCRYPT(strength) aes_generic_encrypt_ecb
#define GET_ECB_DECRYPT(strength) aes_generic_decrypt_ecb
#define GET_CBC_ENCRYPT(strength) aes_generic_encrypt_cbc
#define GET_CBC_DECRYPT(strength) aes_generic_decrypt_cbc
#define GET_CTR_ENCRYPT(strength) aes_generic_encrypt_ctr
#define GET_XTS_ENCRYPT(strength) aes_generic_encrypt_xts
#define GET_XTS_DECRYPT(strength) aes_generic_decrypt_xts
#define aes_encrypt_block(o,k,i) aes_generic_encrypt_block(o,k,i)
#define aes_decrypt_block(o,k,i) aes-generic_decrypt_block(o,k,i)
#endif

void initialize_table_ni(void)
{
	branch_table[INIT_128] = aes_ni_init;
	branch_table[INIT_256] = aes_ni_init;

	branch_table[ENCRYPT_BLOCK_128] = aes_ni_encrypt_block128;
	branch_table[DECRYPT_BLOCK_128] = aes_ni_decrypt_block128;
	branch_table[ENCRYPT_BLOCK_256] = aes_ni_encrypt_block256;
	branch_table[DECRYPT_BLOCK_256] = aes_ni_decrypt_block256;
	/* ECB */
	branch_table[ENCRYPT_ECB_128] = aes_ni_encrypt_ecb128;
	branch_table[DECRYPT_ECB_128] = aes_ni_decrypt_ecb128;
	branch_table[ENCRYPT_ECB_256] = aes_ni_encrypt_ecb256;
	branch_table[DECRYPT_ECB_256] = aes_ni_decrypt_ecb256;
	/* CBC */
	branch_table[ENCRYPT_CBC_128] = aes_ni_encrypt_cbc128;
	branch_table[DECRYPT_CBC_128] = aes_ni_decrypt_cbc128;
	branch_table[ENCRYPT_CBC_256] = aes_ni_encrypt_cbc256;
	branch_table[DECRYPT_CBC_256] = aes_ni_decrypt_cbc256;
	/* CTR */
	branch_table[ENCRYPT_CTR_128] = aes_ni_encrypt_ctr128;
	branch_table[ENCRYPT_CTR_256] = aes_ni_encrypt_ctr256;
	/* XTS */
	branch_table[ENCRYPT_XTS_128] = aes_ni_encrypt_xts128;
	branch_table[ENCRYPT_XTS_256] = aes_ni_encrypt_xts256;
}

void aes_initkey(aes_key *key, uint8_t *origkey, uint8_t size)
{
	switch (size) {
	case 16: key->nbr = 10; key->strength = 0; break;
	case 24: key->nbr = 12; key->strength = 1; break;
	case 32: key->nbr = 14; key->strength = 2; break;
	}
#if defined(ARCH_X86) && defined(WITH_AESNI)
	have_aesni(initialize_table_ni);
#endif
	init_f _init = GET_INIT(key->strength);
	_init(key, origkey, size);
}

void aes_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	ecb_f e = GET_ECB_ENCRYPT(key->strength);
	e(output, key, input, nb_blocks);
}

void aes_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	ecb_f d = GET_ECB_DECRYPT(key->strength);
	d(output, key, input, nb_blocks);
}

void aes_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks)
{
	cbc_f e = GET_CBC_ENCRYPT(key->strength);
	e(output, key, iv, input, nb_blocks);
}

void aes_decrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks)
{
	cbc_f d = GET_CBC_DECRYPT(key->strength);
	d(output, key, iv, input, nb_blocks);
}

void aes_gen_ctr(aes_block *output, aes_key *key, aes_block *iv, uint32_t nb_blocks)
{
	aes_block block;

	/* preload IV in block */
	block128_copy(&block, iv);

	for ( ; nb_blocks-- > 0; output++, block128_inc_be(&block)) {
		aes_encrypt_block(output, key, &block);
	}
}

void aes_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len)
{
	ctr_f e = GET_CTR_ENCRYPT(key->strength);
	e(output, key, iv, input, len);
}

void aes_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                     uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	xts_f e = GET_XTS_ENCRYPT(k1->strength);
	e(output, k1, k2, dataunit, spoint, input, nb_blocks);
}

void aes_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                     uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	aes_generic_decrypt_xts(output, k1, k2, dataunit, spoint, input, nb_blocks);
}

static void gcm_ghash_add(aes_gcm *gcm, block128 *b)
{
	block128_xor(&gcm->tag, b);
	gf_mul(&gcm->tag, &gcm->h);
}

void aes_gcm_init(aes_gcm *gcm, aes_key *key, uint8_t *iv, uint32_t len)
{
	gcm->length_aad = 0;
	gcm->length_input = 0;

	block128_zero(&gcm->h);
	block128_zero(&gcm->tag);
	block128_zero(&gcm->iv);

	/* prepare H : encrypt_K(0^128) */
	aes_encrypt_block(&gcm->h, key, &gcm->h);

	if (len == 12) {
		block128_copy_bytes(&gcm->iv, iv, 12);
		gcm->iv.b[15] = 0x01;
	} else {
		uint32_t origlen = len << 3;
		int i;
		for (; len >= 16; len -= 16, iv += 16) {
			block128_xor(&gcm->iv, (block128 *) iv);
			gf_mul(&gcm->iv, &gcm->h);
		}
		if (len > 0) {
			block128_xor_bytes(&gcm->iv, iv, len);
			gf_mul(&gcm->iv, &gcm->h);
		}
		for (i = 15; origlen; --i, origlen >>= 8)
			gcm->iv.b[i] ^= (uint8_t) origlen;
		gf_mul(&gcm->iv, &gcm->h);
	}

	block128_copy(&gcm->civ, &gcm->iv);
}

void aes_gcm_aad(aes_gcm *gcm, uint8_t *input, uint32_t length)
{
	gcm->length_aad += length;
	for (; length >= 16; input += 16, length -= 16) {
		gcm_ghash_add(gcm, (block128 *) input);
	}
	if (length > 0) {
		aes_block tmp;
		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		gcm_ghash_add(gcm, &tmp);
	}

}

void aes_gcm_encrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	aes_block out;

	gcm->length_input += length;
	for (; length >= 16; input += 16, output += 16, length -= 16) {
		block128_inc_be(&gcm->civ);

		aes_encrypt_block(&out, key, &gcm->civ);
		block128_xor(&out, (block128 *) input);
		gcm_ghash_add(gcm, &out);
		block128_copy((block128 *) output, &out);
	}
	if (length > 0) {
		aes_block tmp;
		int i;

		block128_inc_be(&gcm->civ);
		/* create e(civ) in out */
		aes_encrypt_block(&out, key, &gcm->civ);
		/* initialize a tmp as input and xor it to e(civ) */
		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		block128_xor_bytes(&tmp, out.b, length); 

		gcm_ghash_add(gcm, &tmp);

		for (i = 0; i < length; i++) {
			output[i] = tmp.b[i];
		}
	}
}

void aes_gcm_decrypt(uint8_t *output, aes_gcm *gcm, aes_key *key, uint8_t *input, uint32_t length)
{
	aes_block out;

	gcm->length_input += length;
	for (; length >= 16; input += 16, output += 16, length -= 16) {
		block128_inc_be(&gcm->civ);

		aes_encrypt_block(&out, key, &gcm->civ);
		gcm_ghash_add(gcm, (block128 *) input);
		block128_xor(&out, (block128 *) input);
		block128_copy((block128 *) output, &out);
	}
	if (length > 0) {
		aes_block tmp;
		int i;

		block128_inc_be(&gcm->civ);

		block128_zero(&tmp);
		block128_copy_bytes(&tmp, input, length);
		gcm_ghash_add(gcm, &tmp);

		aes_encrypt_block(&out, key, &gcm->civ);
		block128_xor_bytes(&tmp, out.b, length); 

		for (i = 0; i < length; i++) {
			output[i] = tmp.b[i];
		}
	}
}

void aes_gcm_finish(uint8_t *tag, aes_gcm *gcm, aes_key *key)
{
	aes_block lblock;
	int i;

	/* tag = (tag-1 xor (lenbits(a) | lenbits(c)) ) . H */
	lblock.q[0] = cpu_to_be64(gcm->length_aad << 3);
	lblock.q[1] = cpu_to_be64(gcm->length_input << 3);
	gcm_ghash_add(gcm, &lblock);

	aes_encrypt_block(&lblock, key, &gcm->iv);
	block128_xor(&gcm->tag, &lblock);

	for (i = 0; i < 16; i++) {
		tag[i] = gcm->tag.b[i];
	}
}

void aes_generic_encrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for ( ; nb_blocks-- > 0; input++, output++) {
		aes_generic_encrypt_block(output, key, input);
	}
}

void aes_generic_decrypt_ecb(aes_block *output, aes_key *key, aes_block *input, uint32_t nb_blocks)
{
	for ( ; nb_blocks-- > 0; input++, output++) {
		aes_generic_decrypt_block(output, key, input);
	}
}

void aes_generic_encrypt_cbc(aes_block *output, aes_key *key, aes_block *iv, aes_block *input, uint32_t nb_blocks)
{
	aes_block block;

	/* preload IV in block */
	block128_copy(&block, iv);
	for ( ; nb_blocks-- > 0; input++, output++) {
		block128_xor(&block, (block128 *) input);
		aes_generic_encrypt_block(&block, key, &block);
		block128_copy((block128 *) output, &block);
	}
}

void aes_generic_decrypt_cbc(aes_block *output, aes_key *key, aes_block *ivini, aes_block *input, uint32_t nb_blocks)
{
	aes_block block, blocko;
	aes_block iv;

	/* preload IV in block */
	block128_copy(&iv, ivini);
	for ( ; nb_blocks-- > 0; input++, output++) {
		block128_copy(&block, (block128 *) input);
		aes_generic_decrypt_block(&blocko, key, &block);
		block128_vxor((block128 *) output, &blocko, &iv);
		block128_copy(&iv, &block);
	}
}

void aes_generic_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len)
{
	aes_block block, o;
	uint32_t nb_blocks = len / 16;
	int i;

	/* preload IV in block */
	block128_copy(&block, iv);

	for ( ; nb_blocks-- > 0; block128_inc_be(&block), output += 16, input += 16) {
		aes_encrypt_block(&o, key, &block);
		block128_vxor((block128 *) output, &o, (block128 *) input);
	}

	if ((len % 16) != 0) {
		aes_encrypt_block(&o, key, &block);
		for (i = 0; i < (len % 16); i++) {
			*output = ((uint8_t *) &o)[i] ^ *input;
			output++;
			input++;
		}
	}
}

void aes_generic_encrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	aes_block block, tweak;

	/* load IV and encrypt it using k2 as the tweak */
	block128_copy(&tweak, dataunit);
	aes_encrypt_block(&tweak, k2, &tweak);

	/* TO OPTIMISE: this is really inefficient way to do that */
	while (spoint-- > 0)
		gf_mulx(&tweak);

	for ( ; nb_blocks-- > 0; input++, output++, gf_mulx(&tweak)) {
		block128_vxor(&block, input, &tweak);
		aes_encrypt_block(&block, k1, &block);
		block128_vxor(output, &block, &tweak);
	}
}

void aes_generic_decrypt_xts(aes_block *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                             uint32_t spoint, aes_block *input, uint32_t nb_blocks)
{
	aes_block block, tweak;

	/* load IV and encrypt it using k2 as the tweak */
	block128_copy(&tweak, dataunit);
	aes_encrypt_block(&tweak, k2, &tweak);

	/* TO OPTIMISE: this is really inefficient way to do that */
	while (spoint-- > 0)
		gf_mulx(&tweak);

	for ( ; nb_blocks-- > 0; input++, output++, gf_mulx(&tweak)) {
		block128_vxor(&block, input, &tweak);
		aes_decrypt_block(&block, k1, &block);
		block128_vxor(output, &block, &tweak);
	}
}
