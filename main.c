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
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>	 
#include <errno.h> 
#include "my_aes.h"
#include "my_sha256.h"

void help() {
	printf("Usage : ./project aes[128/192/256] password source destination command[encrypt/decrypt]\n");
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

	if(argc == 1) {
		printf("./project -h for help\n");
		exit(1);
	}

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
