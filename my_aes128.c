#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>	      
#include "lookup_tables.c"
#include "my_aes128.h"


void xor(byte *a, byte *b, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = a[j] ^ b[j];
}

void Sub_Bytes_one(byte a[4][4]) {
	int j, k;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = sbox[a[j][k]];
	}
}

void Sub_Bytes_two(byte *a, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = sbox[a[j]];		
}

void KeyCore(byte *rkey, int i) {
	byte temp;	
	temp = rkey[0];
	rkey[0] = rkey[1];
	rkey[1] = rkey[2];
	rkey[2] = rkey[3];
	rkey[3] = temp;
	Sub_Bytes_two(rkey, 4);
	//rkey[0] = rkey[0] ^ pow(2, (i - 1));
	rkey[0] = rkey[0] ^ rcon[i];
}

void KeyExp(const byte *key, byte *rkey) {
	memcpy(rkey, key, 16);
	
	int i = 1, bytes = 16, j;
	byte t[4];
	while(bytes < 176) {
		memcpy(t, rkey + bytes - 4, 4);
		KeyCore(t, i);
		i++;
		xor(t, rkey + bytes - 16, 4);
		memcpy(rkey + bytes, t, 4);
		bytes+= 4;
		for(j = 0 ; j < 3 ; j++) {
			memcpy(t, rkey + bytes - 4, 4);
			xor(t, rkey + bytes - 16 , 4);
			memcpy(rkey + bytes, t, 4);
			bytes+= 4;
		}		
	}
}	

void ShiftRows(byte a[4][4]) {
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

void MixCols(byte a[4][4]) {
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

void AddRoundKey(byte a[4][4], byte *roundkey) {
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

void encrypt(byte orig[4][4], const byte *key, byte cipher[4][4]) {
	int i;
	byte rkey[176];
	KeyExp(key, rkey);

	copy(cipher, orig);
	AddRoundKey(cipher, rkey);
	//10 rounds for 128 key size
	for(i = 0 ; i < 9; i++) {
		Sub_Bytes_one(cipher);
		ShiftRows(cipher);
		MixCols(cipher);
		AddRoundKey(cipher, rkey + ((i + 1) * 16));
	}

	//last round doesnt have MixCols
	Sub_Bytes_one(cipher);
	ShiftRows(cipher);
	AddRoundKey(cipher, rkey + 160);
}

//same as AddRoundKey
void AddRoundKey_inv(byte a[4][4], byte *roundkey) {
	int j, k, z = 0;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = a[j][k] ^ roundkey[z++];
	}	
}

void MixColInv(byte a[4][4]) {
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

void ShiftRows_inv(byte a[4][4]) {
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

void SubBytes_inv(byte a[4][4]) {
	int j, k;
	for(j = 0 ; j < 4 ; j++) {
		for(k = 0 ; k < 4 ; k++)	
			a[j][k] = sbox_inv[a[j][k]];
	}		
}

void decrypt(byte cipher[4][4], const byte *key, byte orig[4][4]) {
	int i;
	byte rkey[176];
	KeyExp(key, rkey);

	copy(orig, cipher);
	//first round doesnt have MixCols
	AddRoundKey_inv(orig, rkey + 160);
	ShiftRows_inv(orig);
	SubBytes_inv(orig);
	
	//10 rounds for 128 key size
	for(i = 0 ; i < 9; i++) {
		AddRoundKey_inv(orig, rkey + ((9 - i) * 16));
		MixColInv(orig);
		ShiftRows_inv(orig);
		SubBytes_inv(orig);
	}
	
	AddRoundKey_inv(orig, rkey);
}

void set(byte a[4][4]) {
	int i, j;
	for(i = 0; i < 4 ; i++) {
		for(j = 0 ; j < 4 ; j++)
			a[i][j] = 0;
	}
}

int main() {
	int p1, p2, p3;
	int no, no1;
	unsigned int no2, file_size;
	char *buf, *temp;

	//byte key[] = "abcdefghijklmnop";
	//printf("Pls enter 16 byte key\n");
	//scanf("%s", key);

	int random, result;
	if((random = open("/dev/random", O_RDONLY)) == -1) {
		printf("/dev/random cannot be opened.\n");
		exit(1);
	}

	byte key[16];
	int len = 0;
	while(len < 16) {
		result = read(random, key + len, 16 - len);
		if(result < 0) 
			printf("Unable to read /dev/random\n");
		len+=result;
	}

	close(random);

	/*byte key[16];
	int t;
	for(t = 0 ; t < 16 ; t++)
		printf("%c ", key[t]);*/

	byte orig[4][4], cipher[4][4], decrypted[4][4];	
   		
	if ((p1 = open("message.txt", O_RDONLY)) == -1){
       		printf("Error opening message file");
       		exit(1);        
   	}

	if ((p2 = open("encrypted.txt", O_WRONLY | O_CREAT| O_TRUNC  , S_IRUSR | S_IWUSR)) == -1){
       		printf("Error opening encrypted file");
       		exit(1);        
   	}
   	
	if ((p3 = open("decrypted.txt", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR)) == -1){
       		printf("Error opening encrypted file");
       		exit(1);        
   	}
	int i, j;
	while(no1 = read(p1, orig, 16)) {
		encrypt(orig, key, cipher); 
		write(p2, cipher, 16);
		if(no1 < 16) {
			write(p2, &no1, sizeof(int));
			break;
		}
		set(orig);
	}

	close(p2);
	if ((p2 = open("encrypted.txt", O_RDONLY)) == -1){
       		printf("Error opening message file");
       		exit(1);        
   	}
	
	file_size = lseek(p2, 0, SEEK_END);
	buf = (char*)malloc(sizeof(char)*file_size);
	temp = buf;
	lseek(p2, 0, SEEK_SET);

	while(no2 = read(p2, cipher, 16)) {
		if(no2 == 16){
			decrypt(cipher, key, decrypted);	
			memcpy(temp, decrypted, 16);
			temp+=16;
		}
		else 
			memcpy(&no, cipher, 4);

		set(cipher);
	}
	
	write(p3, buf, temp - buf - (16 - no));
	close(p1);
	close(p2);
	close(p3);
	return 0;
}
