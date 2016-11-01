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
#include "lookup_tables.h"
#include "my_aes.h"

void exor(byte *a, byte *b, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = a[j] ^ b[j];
}

void copy(byte a[4][4], byte b[4][4]) {
	int j, k;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++) 
			a[j][k] = b[j][k];
	}
}

void set(byte a[4][4]) {
	int i, j;
	for(i = 0; i < 4 ; i++) {
		for(j = 0 ; j < 4 ; j++)
			a[i][j] = 0;
	}
}

/* core key schedule for AES */
void key_core(byte *rkey, int i) {
	byte temp;	
	temp = rkey[0];
	rkey[0] = rkey[1];
	rkey[1] = rkey[2];
	rkey[2] = rkey[3];
	rkey[3] = temp;
	sub_bytes_two(rkey, 4);
	rkey[0] = rkey[0] ^ rcon[i];
}

/* key expansion step for aes128 */
void key_exp128(const byte *key, byte *rkey) {
	memcpy(rkey, key, 16);
	int i = 1, bytes = 16, j;
	byte t[4];
	while(bytes < 176) {
		memcpy(t, rkey + bytes - 4, 4);
		key_core(t, i);
		i++;
		
		exor(t, rkey + bytes - 16, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			exor(t, rkey + bytes - 16, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
	}
}

/* key expansion step for aes192 */
void key_exp192(const byte *key, byte *rkey) {
	memcpy(rkey, key, 24);
	int i = 1, bytes = 24, j;
	byte t[4];
	while(bytes < 208) {
		memcpy(t, rkey + bytes - 4, 4);
		key_core(t, i);
		i++;
		
		exor(t, rkey + bytes - 24, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			exor(t, rkey + bytes - 24, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}

		for(j = 0 ; j < 2 ; j++) {
			if(bytes == 208)
				break;
			memcpy(t, rkey + bytes - 4, 4);
			exor(t, rkey + bytes - 24, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
	}
}	

/* key expansion step for aes256 */
void key_exp256(const byte *key, byte *rkey) {
	memcpy(rkey, key, 32);
	int i = 1, bytes = 32, j;
	byte t[4];
	while(bytes < 240) {
		memcpy(t, rkey + bytes - 4, 4);
		key_core(t, i);
		i++;
		
		exor(t, rkey + bytes - 32, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			exor(t, rkey + bytes - 32, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}

		if(bytes == 240)
			break;
		memcpy(t, rkey + bytes - 4, 4);	
				
		sub_bytes_two(t, 4);
		exor(t, rkey + bytes - 32, 4);	
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			exor(t, rkey + bytes - 32, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
	}
}

/*** encryption functions **********************************/

void sub_bytes_one(byte a[4][4]) {
	int j, k;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = sbox[a[j][k]];
	}
}

void sub_bytes_two(byte *a, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = sbox[a[j]];		
}

void shift_rows(byte a[4][4]) {
	int j, k, z;
	byte temp[4][4];
	
	copy(temp, a);
	for(j = 0 ; j < 4 ; j++) {
		z = j;
		for(k = 0 ; k < 4 ; k++) {			
			a[j][k] = temp[z++][k];
			if(z == 4)
				z = 0;
		}
	}		
}

void mix_cols(byte a[4][4]) {
	int j;
	byte t0, t1, t2, t3;
	for(j = 0 ; j < 4 ; j++) {
		t0 = a[j][0];
		t1 = a[j][1];
		t2 = a[j][2];
		t3 = a[j][3];
		a[j][0] = lookup_g2[t0] ^ lookup_g3[t1] ^ t2 ^ t3;
       	 	a[j][1] = lookup_g2[t1] ^ lookup_g3[t2] ^ t3 ^ t0;
       	 	a[j][2] = lookup_g2[t2] ^ lookup_g3[t3] ^ t0 ^ t1;
		a[j][3] = lookup_g2[t3] ^ lookup_g3[t0] ^ t1 ^ t2;	
	} 
}		

void add_round_key(byte a[4][4], byte *roundkey) {
	int j, k, z = 0;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = a[j][k] ^ roundkey[z++];
	}
}

void encrypt_128(byte orig[4][4], const byte *key, byte cipher[4][4]) {
	int i;
	byte rkey[176];
	key_exp128(key, rkey);

	copy(cipher, orig);
	add_round_key(cipher, rkey);

	/* 10 rounds for 128 key size */
	for(i = 0 ; i < 9; i++) {
		sub_bytes_one(cipher);
		shift_rows(cipher);
		mix_cols(cipher);
		add_round_key(cipher, rkey + ((i + 1) * 16));
	}

	/* last round doesn't have mix_cols */
	sub_bytes_one(cipher);
	shift_rows(cipher);
	add_round_key(cipher, rkey + 160);
}

void encrypt_192(byte orig[4][4], const byte *key, byte cipher[4][4]) {
	int i;
	byte rkey[208];
	key_exp192(key, rkey);

	copy(cipher, orig);
	add_round_key(cipher, rkey);

	/* 12 rounds for 192 key size */
	for(i = 0 ; i < 11; i++) {
		sub_bytes_one(cipher);
		shift_rows(cipher);
		mix_cols(cipher);
		add_round_key(cipher, rkey + ((i + 1) * 16));
	}

	/* last round doesn't have mix_cols */
	sub_bytes_one(cipher);
	shift_rows(cipher);
	add_round_key(cipher, rkey + 192);
}

void encrypt_256(byte orig[4][4], const byte *key, byte cipher[4][4]) {
	int i;
	byte rkey[240];
	key_exp256(key, rkey);

	copy(cipher, orig);
	add_round_key(cipher, rkey);

	/* 14 rounds for 256 key size */
	for(i = 0 ; i < 13; i++) {
		sub_bytes_one(cipher);
		shift_rows(cipher);
		mix_cols(cipher);
		add_round_key(cipher, rkey + ((i + 1) * 16));
	}

	/* last round doesn't have mix_cols */
	sub_bytes_one(cipher);
	shift_rows(cipher);
	add_round_key(cipher, rkey + 224);
}

/*** decryption functions **********************************/

void add_round_key_inv(byte a[4][4], byte *roundkey) {
	int j, k, z = 0;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = a[j][k] ^ roundkey[z++];
	}	
}

void mix_col_inv(byte a[4][4]) {
	int j;
	byte t0, t1, t2, t3;
	for(j = 0 ; j < 4 ; j++) {
		t0 = a[j][0];
		t1 = a[j][1];
		t2 = a[j][2];
		t3 = a[j][3];
		a[j][0] = lookup_g14[t0] ^ lookup_g9[t3] ^ lookup_g13[t2] ^ lookup_g11[t1];
       	 	a[j][1] = lookup_g14[t1] ^ lookup_g9[t0] ^ lookup_g13[t3] ^ lookup_g11[t2];
       	 	a[j][2] = lookup_g14[t2] ^ lookup_g9[t1] ^ lookup_g13[t0] ^ lookup_g11[t3];
		a[j][3] = lookup_g14[t3] ^ lookup_g9[t2] ^ lookup_g13[t1] ^ lookup_g11[t0];	
	} 
}

void shift_rows_inv(byte a[4][4]) {
	int j, k, z;
	byte temp[4][4];
	copy(temp, a);
	for(j = 0 ; j < 4 ; j++) {
		z = j;
		for(k = 0 ; k < 4 ; k++) {			
			a[j][k] = temp[z--][k];
			if(z == -1)
				z = 3;
		}
	}
}

void sub_bytes_inv(byte a[4][4]) {
	int j, k;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = sbox_inv[a[j][k]];
	}		
}

void decrypt_128(byte cipher[4][4], const byte *key, byte orig[4][4]) {
	int i;
	byte rkey[176];
	key_exp128(key, rkey);

	copy(orig, cipher);

	/* first round doesn't have mix_cols */
	add_round_key_inv(orig, rkey + 160);
	shift_rows_inv(orig);
	sub_bytes_inv(orig);
	
	/* 10 rounds for 128 key size */
	for(i = 0 ; i < 9; i++) {
		add_round_key_inv(orig, rkey + ((9 - i) * 16));
		mix_col_inv(orig);
		shift_rows_inv(orig);
		sub_bytes_inv(orig);
	}
	
	add_round_key_inv(orig, rkey);
}

void decrypt_192(byte cipher[4][4], const byte *key, byte orig[4][4]) {
	int i;
	byte rkey[208];
	key_exp192(key, rkey);

	copy(orig, cipher);

	/* first round doesn't have mix_cols */
	add_round_key_inv(orig, rkey + 192);
	shift_rows_inv(orig);
	sub_bytes_inv(orig);
	
	/* 12 rounds for 192 key size */
	for(i = 0 ; i < 11; i++) {
		add_round_key_inv(orig, rkey + ((11 - i) * 16));
		mix_col_inv(orig);
		shift_rows_inv(orig);
		sub_bytes_inv(orig);
	}
	
	add_round_key_inv(orig, rkey);
}

void decrypt_256(byte cipher[4][4], const byte *key, byte orig[4][4]) {
	int i;
	byte rkey[240];
	key_exp256(key, rkey);

	copy(orig, cipher);

	/* first round doesn't have mix_cols */
	add_round_key_inv(orig, rkey + 224);
	shift_rows_inv(orig);
	sub_bytes_inv(orig);
	
	/* 14 rounds for 256 key size */
	for(i = 0 ; i < 13; i++) {
		add_round_key_inv(orig, rkey + ((13 - i) * 16));
		mix_col_inv(orig);
		shift_rows_inv(orig);
		sub_bytes_inv(orig);
	}
	
	add_round_key_inv(orig, rkey);
}
