/*
 *  Advanced Encryption Standard and SHA-256 implementation
 *
 *  Copyright (C) 2016 Asawaree Bhide
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include "my_sha256.h"

/* rotate right (circular right shift) operation */
word ROTR(word a , word b) {
	return (a >> b) | (a << (32 - b));
}

/* right shift operation */
word SHR(word a, word b) {
	return a >> b;
}

/* six logical functions, each operates on 32-bit words */
word F1(word a) {
	return ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
}

word F2(word a) {
	return ROTR(a, 6) ^ ROTR(a, 11) ^ ROTR(a, 25);
}

word F3(word a) {
	return ROTR(a, 7) ^ ROTR(a, 18) ^ SHR(a, 3);
}

word F4(word a) {
	return ROTR(a, 17) ^ ROTR(a, 19) ^ SHR(a, 10);
}

word Ch(word a, word b, word c) {
	return (a & b) ^ (~(a) & c);
}

word Maj(word a, word b, word c) {
	return (a & b) ^ (a & c) ^ (b & c);
}


void append(SHA256_CTX *sha256) {
	int i;
	for(i = 0 ; i < 4 ; i++) {
		sha256->buffer[56 + i] = sha256->bitlen[1] >> (24 - i * 8);
		sha256->buffer[60 + i] = sha256->bitlen[0] >> (24 - i * 8);
	}
}

void reverse(byte hash[], SHA256_CTX *sha256) {
	int i;
	for(i = 0 ; i < 4 ; i++) { 
		hash[i]    = (sha256->state[0] >> (24 - i * 8)) & 0x000000ff; 
		hash[i+4]  = (sha256->state[1] >> (24 - i * 8)) & 0x000000ff; 
		hash[i+8]  = (sha256->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i+12] = (sha256->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i+16] = (sha256->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i+20] = (sha256->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i+24] = (sha256->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i+28] = (sha256->state[7] >> (24 - i * 8)) & 0x000000ff;
	} 
}

void SHA256_Init(SHA256_CTX *sha256) {
	int i;

	/* setting initial hash value */
	for(i = 0 ; i < 8 ; i++)
		sha256->state[i] = initial_hash[i];

	for(i = 0 ; i < 64 ; i++)
		sha256->buffer[i] = 0;
	
	sha256->bitcount = 0 ;
	sha256->bitlen[0] = 0; 
	sha256->bitlen[1] = 0; 
}

void SHA256_computation(SHA256_CTX *ctx, byte buffer[]) {  
	word a, b, c, d, e, f, g, h, t1, t2, W[64];
	int i , j;
      
	/* preparing message schedule */
	for(i = 0, j = 0 ; i < 16 ; i++, j += 4)
		W[i] = (buffer[j] << 24) | (buffer[j+1] << 16) | (buffer[j+2] << 8) | (buffer[j+3]);
	
	for( ; i < 64 ; i++)
		W[i] = F4(W[i-2]) + W[i-7] + F3(W[i-15]) + W[i-16];
	
	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];
   
	for(i = 0 ; i < 64 ; i++) {
		t1 = h + F2(e) + Ch(e,f,g) + sha256_const[i] + W[i];
		t2 = F1(a) + Maj(a,b,c);	
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
   
	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
} 

void SHA256_Update(SHA256_CTX *sha256, byte key[], int len) {  
	if(len == 0)
		return;
	int i;
	for(i = 0 ; i < len ; i++) {  
		sha256->buffer[sha256->bitcount] = key[i]; 
		sha256->bitcount++; 
		if (sha256->bitcount == 64) { 
			SHA256_computation(sha256, sha256->buffer);
			sha256->bitlen[0] += sha256->bitcount * 8;
			sha256->bitcount = 0; 
		} 
	}  
} 

void SHA256_Final(byte hash[], SHA256_CTX *sha256) {    
	int i = sha256->bitcount;
	sha256->buffer[i++] = 0x80;
		
	/* padding whatever data is left in the buffer */ 
	if (sha256->bitcount < 56) {  
		while (i < 56) 
			sha256->buffer[i++] = 0x00; 
	}  

	else {  
		while (i < 64) 
			sha256->buffer[i++] = 0x00; 

		SHA256_computation(sha256, sha256->buffer);
		memset(sha256->buffer, 0, 56); 
	}  
	   
	/* append to the padding the total message's length in bits and compute */ 

	sha256->bitlen[0] += sha256->bitcount * 8;
	append(sha256);
	SHA256_computation(sha256, sha256->buffer);

	/*
	 * the 32-bit words used assume little endian byte ordering.
	 * SHA-256 uses big endian, so bytes are reversed when copying to output hash
	 */
	
	reverse(hash, sha256);
} 
