#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>	      
#include "lookup_tables.c"

typedef unsigned char byte;

static const byte RowShift[] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};

static const byte RowShift_inv[] = {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};


void xor(byte *a, byte *b, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = a[j] ^ b[j];
}

void SubBytes(byte *msg, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		msg[j] = sbox[msg[j]];		
}

void KeyCore(byte *rkey, int i) {
	byte temp;	
	temp = rkey[0];
	rkey[0] = rkey[1];
	rkey[1] = rkey[2];
	rkey[2] = rkey[3];
	rkey[3] = temp;
	SubBytes(rkey, 4);
	//rkey[0] = rkey[0] ^ pow(2, (i - 1));
	rkey[0] = rkey[0] ^ rcon[i];
}

void KeyExp(const byte *key, byte *rkey) {
	memcpy(rkey, key, 16);
	int k;
	for(k = 0 ; k < 16 ;k++)
		printf("%c ", rkey[k] );
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

void ShiftRows(byte *msg) {
	int i;
	byte temp[16];
	memcpy(temp, msg, 16);
	for(i = 0 ; i < 16 ; i++) 
		msg[i] = temp[RowShift[i]];
}

/*void mix_col(byte *msg) {
	byte a0, a1, a2, a3;
	a0  = msg[0];
	a1  = msg[1];
	a2  = msg[2];
	a3  = msg[3];
	msg[0] = a0 + a1 + 2 * a2 + 3 * a3; 
	msg[1] = 3 * a0 + a1 + a2 + 2 * a3;
	msg[2] = 2 * a0 + 3 * a1 + a2 + a3;
	msg[3] = a0 + 2 * a1 + 3 * a2 + a3;	
}*/

/*void mix_col(byte *msg) {
	byte a0, a1, a2, a3;
	a0  = msg[0];
	a1  = msg[1];
	a2  = msg[2];
	a3  = msg[3];
	msg[0] = 2 * a0 + 3 * a1 + a2 + a3; 
	msg[1] = a0 + 2 * a1 + 3 * a2 + a3;
	msg[2] = a0 + a1 + 2 * a2 + 3 * a3;
	msg[3] = 3 * a0 + a1 + a2 + 2 * a3;	
}*/

void mix_col(byte *msg) {
	byte a0, a1, a2, a3;
	a0  = msg[0];
	a1  = msg[1];
	a2  = msg[2];
	a3  = msg[3];
	msg[0] = lookup_g2[a0] ^ lookup_g3[a1] ^ a2 ^ a3;
        msg[1] = lookup_g2[a1] ^ lookup_g3[a2] ^ a3 ^ a0;
        msg[2] = lookup_g2[a2] ^ lookup_g3[a3] ^ a0 ^ a1;
	msg[3] = lookup_g2[a3] ^ lookup_g3[a0] ^ a1 ^ a2;
}

void MixCols(byte *msg) {
	mix_col(msg);
	mix_col(msg + 4);
	mix_col(msg + 8);
	mix_col(msg + 12); 
}

void AddRoundKey(byte *msg, byte * roundkey) {
	int i;
	for(i = 0 ; i < 16 ; i++)	
		msg[i] = msg[i] ^ roundkey[i];
}

void encrypt(const byte *orig, const byte *key, byte *cipher) {
	int i;
	byte rkey[176];
	KeyExp(key, rkey);

	memcpy(cipher, orig, 16);
	AddRoundKey(cipher, rkey);
	//10 rounds for 128 key size
	for(i = 0 ; i < 9; i++) {
		SubBytes(cipher, 16);
		ShiftRows(cipher);
		MixCols(cipher);
		AddRoundKey(cipher, rkey + ((i + 1) * 16));
	}

	//last round doesnt have MixCols
	SubBytes(cipher, 16);
	ShiftRows(cipher);
	AddRoundKey(cipher, rkey + 160);
}

//same as AddRoundKey
void AddRoundKey_inv(byte *msg, byte * roundkey) {
	int i;
	for(i = 0 ; i < 16 ; i++)	
		msg[i] = msg[i] ^ roundkey[i];
}

void mix_col_inv(byte *msg) {
	byte a0, a1, a2, a3;
	a0  = msg[0];
	a1  = msg[1];
	a2  = msg[2];
	a3  = msg[3];
	//uses diff lookup tables
	msg[0] = lookup_g14[a0] ^ lookup_g9[a3] ^ lookup_g13[a2] ^ lookup_g11[a1];
    	msg[1] = lookup_g14[a1] ^ lookup_g9[a0] ^ lookup_g13[a3] ^ lookup_g11[a2];
    	msg[2] = lookup_g14[a2] ^ lookup_g9[a1] ^ lookup_g13[a0] ^ lookup_g11[a3];
	msg[3] = lookup_g14[a3] ^ lookup_g9[a2] ^ lookup_g13[a1] ^ lookup_g11[a0];
}

void MixColInv(byte *msg) {
	mix_col_inv(msg);
	mix_col_inv(msg + 4);
	mix_col_inv(msg + 8);
	mix_col_inv(msg + 12);
}

void ShiftRows_inv(byte *msg) {
	int i;
	byte temp[16];
	memcpy(temp, msg, 16);
	for(i = 0 ; i < 16 ; i++) 
		msg[i] = temp[RowShift_inv[i]];
}

void SubBytes_inv(byte *msg, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		msg[j] = sbox_inv[msg[j]];		
}

void decrypt(byte *cipher, const byte *key, byte *orig) {
	int i;
	byte rkey[176];
	KeyExp(key, rkey);

	memcpy(orig, cipher, 16);

	//first round shudnt have MixCols
	AddRoundKey(orig, rkey + 160);
	ShiftRows_inv(orig);
	SubBytes_inv(orig, 16);
	
	//10 rounds for 128 key size
	for(i = 0 ; i < 9; i++) {
		AddRoundKey(orig, rkey + ((9 - i) * 16));
		MixColInv(orig);
		ShiftRows_inv(orig);
		SubBytes_inv(orig, 16);
	}
	
	AddRoundKey(orig, rkey);
}

int main() {
	int p1, p2, p3;
	int no, no1;
	unsigned int no2, file_size;
	char *buf, *temp;

	byte key[16];
	printf("Pls enter 16 byte key\n");
	scanf("%s", key);

	byte orig[16], cipher[16], decrypted[16];	
   		
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
	
	while(no1 = read(p1, orig, 16)) { 	
		encrypt(orig, key, cipher); 
		write(p2, cipher, 16);
		if(no1 < 16) {
			write(p2, &no1, sizeof(int));
			break;
		}
		memset(orig, 0, 16);
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

		memset(cipher, 0, 16);
	}
	
	write(p3, buf, temp - buf - (16 - no));
	close(p1);
	close(p2);
	close(p3);
	return 0;
}
