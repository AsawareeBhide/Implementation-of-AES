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

typedef unsigned char byte;

void exor(byte *a, byte *b, int i);
void sub_bytes_one(byte a[4][4]);
void sub_bytes_two(byte *a, int i);
void key_core(byte *a, int i);
void key_exp128(const byte *a, byte *b);
void key_exp192(const byte *a, byte *b);
void key_exp256(const byte *a, byte *b);
void shift_rows(byte a[4][4]);
void mix_cols(byte a[4][4]);
void add_round_key(byte a[4][4], byte *b);
void copy(byte a[4][4], byte b[4][4]);
void encrypt_128(byte a[4][4], const byte *key, byte b[4][4]);
void encrypt_192(byte a[4][4], const byte *key, byte b[4][4]);
void encrypt_256(byte a[4][4], const byte *key, byte b[4][4]);
void add_round_key_inv(byte a[4][4], byte *b);
void mix_cols_inv(byte a[4][4]);
void shift_rows_inv(byte a[4][4]);
void sub_bytes_inv(byte a[4][4]);
void decrypt_128(byte a[4][4], const byte *key, byte b[4][4]);
void decrypt_192(byte a[4][4], const byte *key, byte b[4][4]);
void decrypt_256(byte a[4][4], const byte *key, byte b[4][4]);
void set(byte a[4][4]);
