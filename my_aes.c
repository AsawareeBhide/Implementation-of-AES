#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>	 
#include <errno.h>
#include <openssl/sha.h>
#include "lookup_tables.h"
#include "my_aes.h"

void xor(byte *a, byte *b, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = a[j] ^ b[j];
}

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

void key_exp128(const byte *key, byte *rkey) {
	memcpy(rkey, key, 16);
	int i = 1, bytes = 16, j;
	byte t[4];
	while(bytes < 176) {
		memcpy(t, rkey + bytes - 4, 4);
		key_core(t, i);
		i++;
		
		xor(t, rkey + bytes - 16, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			xor(t, rkey + bytes - 16, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
	}
}

void key_exp192(const byte *key, byte *rkey) {
	memcpy(rkey, key, 24);
	int i = 1, bytes = 24, j;
	byte t[4];
	while(bytes < 208) {
		memcpy(t, rkey + bytes - 4, 4);
		key_core(t, i);
		i++;
		
		xor(t, rkey + bytes - 24, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			xor(t, rkey + bytes - 24, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}

		for(j = 0 ; j < 2 ; j++) {
			if(bytes == 208)
				break;
			memcpy(t, rkey + bytes - 4, 4);
			xor(t, rkey + bytes - 24, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
	}
}	

void key_exp256(const byte *key, byte *rkey) {
	memcpy(rkey, key, 32);
	int i = 1, bytes = 32, j;
	byte t[4];
	while(bytes < 240) {
		memcpy(t, rkey + bytes - 4, 4);
		key_core(t, i);
		i++;
		
		xor(t, rkey + bytes - 32, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			xor(t, rkey + bytes - 32, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
		if(bytes == 240)
			break;
		memcpy(t, rkey + bytes - 4, 4);	
				
		sub_bytes_two(t, 4);
		xor(t, rkey + bytes - 32, 4);	
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;

		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			xor(t, rkey + bytes - 32, 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}
	}
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

void copy(byte a[4][4], byte b[4][4]) {
	int j, k;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++) 
			a[j][k] = b[j][k];
	}
}

void encrypt_128(byte orig[4][4], const byte *key, byte cipher[4][4]) {
	int i;
	byte rkey[176];
	key_exp128(key, rkey);

	copy(cipher, orig);
	add_round_key(cipher, rkey);
	//10 rounds for 128 key size
	for(i = 0 ; i < 9; i++) {
		sub_bytes_one(cipher);
		shift_rows(cipher);
		mix_cols(cipher);
		add_round_key(cipher, rkey + ((i + 1) * 16));
	}

	//last round doesnt have mix_cols
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
	//12 rounds for 192 key size
	for(i = 0 ; i < 11; i++) {
		sub_bytes_one(cipher);
		shift_rows(cipher);
		mix_cols(cipher);
		add_round_key(cipher, rkey + ((i + 1) * 16));
	}

	//last round doesnt have mix_cols
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
	//14 rounds for 256 key size
	for(i = 0 ; i < 13; i++) {
		sub_bytes_one(cipher);
		shift_rows(cipher);
		mix_cols(cipher);
		add_round_key(cipher, rkey + ((i + 1) * 16));
	}

	//last round doesnt have mix_cols
	sub_bytes_one(cipher);
	shift_rows(cipher);
	add_round_key(cipher, rkey + 224);
}


//same as add_round_key
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
	//first round doesnt have mix_cols
	add_round_key_inv(orig, rkey + 160);
	shift_rows_inv(orig);
	sub_bytes_inv(orig);
	
	//10 rounds for 128 key size
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
	//first round doesnt have mix_cols
	add_round_key_inv(orig, rkey + 192);
	shift_rows_inv(orig);
	sub_bytes_inv(orig);
	
	//12 rounds for 192 key size
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
	//first round doesnt have mix_cols
	add_round_key_inv(orig, rkey + 224);
	shift_rows_inv(orig);
	sub_bytes_inv(orig);
	
	//14 rounds for 256 key size
	for(i = 0 ; i < 13; i++) {
		add_round_key_inv(orig, rkey + ((13 - i) * 16));
		mix_col_inv(orig);
		shift_rows_inv(orig);
		sub_bytes_inv(orig);
	}
	
	add_round_key_inv(orig, rkey);
}

void set(byte a[4][4]) {
	int i, j;
	for(i = 0; i < 4 ; i++) {
		for(j = 0 ; j < 4 ; j++)
			a[i][j] = 0;
	}
}

void help() {
	printf("Usage : ./my_aes aes[128/192/256] password source destination command[encrypt/decrypt]\n");
	printf("AES Variants :\n");	
	printf("aes128 :  128 bit\n");
	printf("aes192 :  192 bit\n");
	printf("aes256 :  256 bit\n");
	printf("Commands :\n");
	printf("encrypt :  encrypts source file \n");
	printf("decrypt :  decrypts encrypted file\n");
	exit(1);
}

int main(int argc, char *argv[]) {
	int key_len;
	int p1, p2;
	int i, no = 16, no1;
	unsigned int no2, file_size;
	char *buf, *temp;

	byte orig[4][4], cipher[4][4], decrypted[4][4];
	
	byte key_128[16];
	byte key_192[24];
	byte key_256[32];
	
	byte hash_256[32];

	byte password_256[32];
	
	if(strcmp(argv[1], "-h") == 0)
		help();

	if(argc < 6) {
		errno = EINVAL;
		perror("Usage : ./my_aes <aes128/aes192/aes256> <password> <source file> <destination file> <encrypt/decrypt>");
		return errno;
	}

	
	if(strcmp(argv[1], "aes128") == 0) {
		key_len = 16;
	}

	if(strcmp(argv[1], "aes192") == 0) {
		key_len = 24;	
	}

	if(strcmp(argv[1], "aes256") == 0) {
		key_len = 32;
	}

	for(i = 0 ; i < 32 ; i++)
		key_256[i] = '\0';	
	memcpy(key_256, argv[2], strlen(argv[2]));

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, key_256, 32);
	SHA256_Final(hash_256, &sha256);

	memcpy(key_128, hash_256, 16);
	memcpy(key_192, hash_256, 24);
	
   		
	if ((p1 = open(argv[3], O_RDONLY)) == -1){
       		printf("Error opening message file");
       		exit(1);        
   	}

	if ((p2 = open(argv[4], O_WRONLY | O_CREAT| O_TRUNC  , S_IRUSR | S_IWUSR)) == -1){
       		printf("Error opening encrypted file");
       		exit(1);        
   	}
   	
   	if(strcmp("encrypt", argv[5]) == 0) {
		write(p2, hash_256, 32);
		while((no1 = read(p1, orig, 16))) {
			switch(key_len) {
				case 16 :
					encrypt_128(orig, key_128, cipher);
					break; 
				case 24 :
					encrypt_192(orig, key_192, cipher);
					break;
				case 32 :
					encrypt_256(orig, hash_256, cipher);
					break;
			}
			
			write(p2, cipher, 16);
			if(no1 < 16) {
				write(p2, &no1, sizeof(int));
				break;
			}
			set(orig);
		}
	}
	
	else if(strcmp("decrypt", argv[5]) == 0) {
		read(p1, password_256, 32);
		if(key_len == 16) {
			if(memcmp(hash_256, password_256, 32) != 0) {
				printf("Incorrect password.\n");
				exit(1);
			}
		}

		if(key_len == 24) {
			if(memcmp(hash_256, password_256, 32) != 0) {
				printf("Incorrect password.\n");
				exit(1);
			}
		}

		if(key_len == 32) {
			if(memcmp(hash_256, password_256, 32) != 0) {
				printf("Incorrect password.\n");
				exit(1);
			}
		}

		file_size = lseek(p1, 0, SEEK_END) - 32;
		buf = (char*)malloc(sizeof(char)*file_size);
		temp = buf;
		lseek(p1, 32, 0);
		while((no2 = read(p1, cipher, 16))) {
			if(no2 == 16) {
				switch(key_len) {
				case 16 :
					decrypt_128(cipher, key_128, decrypted);
					break; 
				case 24 :
					decrypt_192(cipher, key_192, decrypted);
					break;
				case 32 :
					decrypt_256(cipher, hash_256, decrypted);
					break;
				}
					
				memcpy(temp, decrypted, 16);
				temp+=16;
			}
			else 
				memcpy(&no, cipher, 4);

			set(cipher);
		}
	
		write(p2, buf, temp - buf - (16 - no));
	}
	
	close(p1);
	close(p2);		
	return 0;
}
