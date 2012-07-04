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

void aes_encrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
#ifdef ARCH_X86
	if (have_aesni() && key->nbr == 10)
		return aes_ni_encrypt_ecb((uint8_t *) output, key, (uint8_t *) input, 1);
#endif
	aes_generic_encrypt_block(output, key, input);
}

void aes_decrypt_block(aes_block *output, aes_key *key, aes_block *input)
{
#ifdef ARCH_X86
	if (have_aesni() && key->nbr == 10)
		return aes_ni_decrypt_ecb((uint8_t *) output, key, (uint8_t *) input, 1);
#endif
	aes_generic_decrypt_block(output, key, input);
}

void aes_init(aes_key *key, uint8_t *origkey, uint8_t size)
{
	switch (size) {
	case 16: key->nbr = 10; break;
	case 24: key->nbr = 12; break;
	case 32: key->nbr = 14; break;
	}
#ifdef ARCH_X86
	if (have_aesni() && size == 16)
		return aes_ni_init(key, origkey, size);
#endif
	aes_generic_init(key, origkey, size);
}

void aes_encrypt_ecb(uint8_t *output, aes_key *key, uint8_t *input, uint32_t nb_blocks)
{
	aes_block block;

	if (!nb_blocks)
		return;

#ifdef ARCH_X86
	if (have_aesni() && key->nbr == 10)
		return aes_ni_encrypt_ecb(output, key, input, nb_blocks);
#endif

	while (nb_blocks-- > 0) {
		block.q[0] = ((uint64_t *) input)[0];
		block.q[1] = ((uint64_t *) input)[1];

		aes_encrypt_block(&block, key, &block);

		((uint64_t *) output)[0] = block.q[0];
		((uint64_t *) output)[1] = block.q[1];
		input += 16;
		output += 16;
	}
}

void aes_decrypt_ecb(uint8_t *output, aes_key *key, uint8_t *input, uint32_t nb_blocks)
{
	aes_block block;

	if (!nb_blocks)
		return;

#ifdef ARCH_X86
	if (have_aesni() && key->nbr == 10)
		return aes_ni_decrypt_ecb(output, key, input, nb_blocks);
#endif

	while (nb_blocks-- > 0) {
		block.q[0] = ((uint64_t *) input)[0];
		block.q[1] = ((uint64_t *) input)[1];

		aes_decrypt_block(&block, key, &block);

		((uint64_t *) output)[0] = block.q[0];
		((uint64_t *) output)[1] = block.q[1];
		input += 16;
		output += 16;
	}
}

void print_block(char *label, uint8_t *data)
{
	int i;
	printf("%s: ", label);
	for (i = 0; i < 16; i++) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

void aes_encrypt_cbc(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t nb_blocks)
{
	aes_block block;

	if (!nb_blocks)
		return;
#ifdef ARCH_X86
	if (have_aesni() && key->nbr == 10)
		return aes_ni_encrypt_cbc(output, key, (uint8_t *) iv, input, nb_blocks);
#endif

	/* preload IV in block */
	block128_copy(&block, iv);

	while (nb_blocks-- > 0) {
		block128_xor(&block, (block128 *) input);

		aes_encrypt_block(&block, key, &block);

		block128_copy((block128 *) output, &block);
		input += 16;
		output += 16;
	}
}

void aes_decrypt_cbc(uint8_t *output, aes_key *key, aes_block *ivini, uint8_t *input, uint32_t nb_blocks)
{
	aes_block block,blocko;
	aes_block iv;

	if (!nb_blocks)
		return;
#ifdef ARCH_X86
	if (have_aesni() && key->nbr == 10) {
		return aes_ni_decrypt_cbc(output, key, (uint8_t *) ivini, input, nb_blocks);
	}
#endif

	/* preload IV in block */
	iv.q[0] = ivini->q[0];
	iv.q[1] = ivini->q[1];

	aes_decrypt_block(&block, key, &block);

	while (nb_blocks-- > 0) {
		block128_copy(&block, (block128 *) input);

		aes_decrypt_block(&blocko, key, &block);

		block128_xor(&blocko, &iv);
		block128_copy(&iv, &block);

		block128_copy((block128 *) output, &blocko);
		input += 16;
		output += 16;
	}
}

void aes_gen_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint32_t nb_blocks)
{
	aes_block block, o;

	if (!nb_blocks)
		return;
	/* preload IV in block */
	block.q[0] = iv->q[0];
	block.q[1] = iv->q[1];

	while (nb_blocks-- > 0) {
		aes_encrypt_block(&o, key, &block);
		block128_copy((block128 *) output, &o);
		block128_inc_be(&block);
		output += 16;
	}
}

void aes_encrypt_ctr(uint8_t *output, aes_key *key, aes_block *iv, uint8_t *input, uint32_t len)
{
	aes_block block, o;
	uint32_t nb_blocks = len / 16;
	int i;

	/* preload IV in block */
	block.q[0] = iv->q[0];
	block.q[1] = iv->q[1];

	while (nb_blocks-- > 0) {
		aes_encrypt_block(&o, key, &block);
		((uint64_t *) output)[0] = o.q[0] ^ ((uint64_t *) input)[0];
		((uint64_t *) output)[1] = o.q[1] ^ ((uint64_t *) input)[1];

		block128_inc_be(&block);
		output += 16;
		input += 16;
	}

	if ((len % 16) != 0) {
		aes_encrypt_block(&o, key, &block);
		for (i = 0; i < (len % 16); i++) {
			*output = ((uint8_t *) &o)[i] ^ *input;
			output += 1;
			input += 1;
		}
	}
}

void aes_encrypt_xts(uint8_t *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                     uint32_t spoint, uint8_t *input, uint32_t nb_blocks)
{
	aes_block block, tweak;

	if (!nb_blocks)
		return;

#ifdef ARCH_X86
	if (have_aesni() && k1->nbr == 10) {
		aes_ni_encrypt_xts(output, k1, k2, (uint8_t *) dataunit, spoint, input, nb_blocks);
		return;
	}
#endif

	/* load IV and encrypt it using k2 as the tweak */
	block128_copy(&tweak, dataunit);
	aes_encrypt_block(&tweak, k2, &tweak);

	/* TO OPTIMISE: this is really inefficient way to do that */
	while (spoint-- > 0)
		gf_mulx(&tweak);

	while (nb_blocks-- > 0) {
		block128_copy(&block, (block128 *) input);

		block128_xor(&block, &tweak);
		aes_encrypt_block(&block, k1, &block);
		block128_xor(&block, &tweak);

		gf_mulx(&tweak);

		block128_copy((block128 *) output, &block);
		input += 16;
		output += 16;
	}
}

void aes_decrypt_xts(uint8_t *output, aes_key *k1, aes_key *k2, aes_block *dataunit,
                     uint32_t spoint, uint8_t *input, uint32_t nb_blocks)
{
	aes_block block, tweak;

	if (!nb_blocks)
		return;

	/* load IV and encrypt it using k2 as the tweak */
	block128_copy(&tweak, dataunit);
	aes_encrypt_block(&tweak, k2, &tweak);

	/* TO OPTIMISE: this is really inefficient way to do that */
	while (spoint-- > 0)
		gf_mulx(&tweak);

	while (nb_blocks-- > 0) {
		block128_copy(&block, (block128 *) input);

		block128_xor(&block, &tweak);
		aes_decrypt_block(&block, k1, &block);
		block128_xor(&block, &tweak);

		gf_mulx(&tweak);
		block128_copy((block128 *) output, &block);

		input += 16;
		output += 16;
	}
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

	memcpy(&gcm->key, key, sizeof(aes_key));

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

void aes_gcm_encrypt(uint8_t *output, aes_gcm *gcm, uint8_t *input, uint32_t length)
{
	aes_block out;

	gcm->length_input += length;
	for (; length >= 16; input += 16, output += 16, length -= 16) {
		block128_inc_be(&gcm->civ);

		aes_encrypt_block(&out, &gcm->key, &gcm->civ);
		block128_xor(&out, (block128 *) input);
		gcm_ghash_add(gcm, &out);
		block128_copy((block128 *) output, &out);
	}
	if (length > 0) {
		aes_block tmp;
		int i;

		block128_inc_be(&gcm->civ);
		/* create e(civ) in out */
		aes_encrypt_block(&out, &gcm->key, &gcm->civ);
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

void aes_gcm_decrypt(uint8_t *output, aes_gcm *gcm, uint8_t *input, uint32_t length)
{
	aes_block out;

	gcm->length_input += length;
	for (; length >= 16; input += 16, output += 16, length -= 16) {
		block128_inc_be(&gcm->civ);

		aes_encrypt_block(&out, &gcm->key, &gcm->civ);
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

		aes_encrypt_block(&out, &gcm->key, &gcm->civ);
		block128_xor_bytes(&tmp, out.b, length); 

		for (i = 0; i < length; i++) {
			output[i] = tmp.b[i];
		}
	}
}

void aes_gcm_finish(uint8_t *tag, aes_gcm *gcm)
{
	aes_block lblock;
	int i;

	/* tag = (tag-1 xor (lenbits(a) | lenbits(c)) ) . H */
	lblock.q[0] = cpu_to_be64(gcm->length_aad << 3);
	lblock.q[1] = cpu_to_be64(gcm->length_input << 3);
	gcm_ghash_add(gcm, &lblock);

	aes_encrypt_block(&lblock, &gcm->key, &gcm->iv);
	block128_xor(&gcm->tag, &lblock);

	for (i = 0; i < 16; i++) {
		tag[i] = gcm->tag.b[i];
	}
}
