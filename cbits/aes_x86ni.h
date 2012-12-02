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

#ifndef AES_X86NI_H
#define AES_X86NI_H

#ifdef WITH_AESNI

#if defined(__i386__) || defined(__x86_64__)

#include <wmmintrin.h>
#include <tmmintrin.h>
#include "aes.h"

void aes_ni_init(aes_key *key, uint8_t *origkey, uint8_t size);
void aes_ni_encrypt_ecb(uint8_t *out, aes_key *key, uint8_t *in, uint32_t blocks);
void aes_ni_decrypt_ecb(uint8_t *out, aes_key *key, uint8_t *in, uint32_t blocks);
void aes_ni_encrypt_cbc(uint8_t *out, aes_key *key, uint8_t *_iv, uint8_t *in, uint32_t blocks);
void aes_ni_decrypt_cbc(uint8_t *out, aes_key *key, uint8_t *_iv, uint8_t *in, uint32_t blocks);
void aes_ni_encrypt_xts(uint8_t *out, aes_key *key1, aes_key *key2,
                        uint8_t *_tweak, uint32_t spoint, uint8_t *in, uint32_t blocks);

void gf_mul_x86ni(block128 *res, block128 *a_, block128 *b_);

#endif

#endif

#endif
