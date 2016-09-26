#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
//#include <linux/random.h>
#include "lookup_tables.c"

typedef unsigned char byte;

static const byte RowShift[] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
//static const int RowShift[16] = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
static const byte RowShift_inv[] = {0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3};

static void xor(byte *a, const byte *b, int i) {
	int j;
	for(j = 0 ; j < i ; j++)
		a[j] = a[j] ^ b[j];
}

/*void SubBytes(byte *msg) {
	int i;
	//char *temp;
	for(i = 0 ; i < 16 ; i++)
		msg[i] = sbox[msg[i]];		
}*/

static void SubBytes(byte *msg, int i) {
	int j;
	//char *temp;
	for(j = 0 ; j < i ; j++)
		msg[j] = sbox[msg[j]];		
}

static void KeyCore(byte *rkey, int i) {
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

static void KeyExp(const byte *key, byte *rkey) {
	memcpy(rkey, key, 32);
	//memcpy(rkey, key, 16);
	int i = 1, bytes = 32, j;
	byte t[4];
	while(bytes < 240) {
		memcpy(t, rkey + bytes - 4, 4);
		KeyCore(t, i);
		i++;
		//xor(t, rkey + bytes - 32, 4);
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
		//run thru sbox		
		SubBytes(t, 4);
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

 /* k[0] ^= rj_sbox(k[29]) ^ (*rc);
    k[1] ^= rj_sbox(k[30]);
    k[2] ^= rj_sbox(k[31]);
    k[3] ^= rj_sbox(k[28]);
    *rc = rj_xtime( *rc);

    for(i = 4; i < 16; i += 4)  k[i] ^= k[i - 4],   k[i + 1] ^= k[i - 3],
                                            k[i + 2] ^= k[i - 2], k[i + 3] ^= k[i - 1];
    k[16] ^= rj_sbox(k[12]);
    k[17] ^= rj_sbox(k[13]);
    k[18] ^= rj_sbox(k[14]);
    k[19] ^= rj_sbox(k[15]);

    for(i = 20; i < 32; i += 4) k[i] ^= k[i - 4],   k[i + 1] ^= k[i - 3],
                                            k[i + 2] ^= k[i - 2], k[i + 3] ^= k[i - 1];

}*/

static void ShiftRows(byte *msg) {
	int i;
	byte temp[16];
	//temp = msg;
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

static void mix_col(byte *msg) {
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

static void MixCols(byte *msg) {
	mix_col(msg);
	mix_col(msg + 4);
	mix_col(msg + 8);
	mix_col(msg + 12); 
}

static void AddRoundKey(byte *msg, const byte * roundkey) {
	int i;
	for(i = 0 ; i < 16 ; i++)	
		msg[i] = msg[i] ^ roundkey[i];
}

//void encrypt(byte *orig, byte *key, byte *cipher) 
static void encrypt(const byte *orig, const byte *key, byte *cipher) {
	int i;
	byte rkey[240];
	KeyExp(key, rkey);
	
	memcpy(cipher, orig, 16);
	AddRoundKey(cipher, rkey);
	
	//14 rounds for 256 key size
	for(i = 0 ; i < 13 ; i++) {
		SubBytes(cipher, 16);
		ShiftRows(cipher);
		MixCols(cipher);
		AddRoundKey(cipher, rkey + ((i + 1) * 16));
	}
	
	//last round doesnt have MixCols
	SubBytes(cipher, 16);
	ShiftRows(cipher);
	AddRoundKey(cipher, rkey + 224);
}

//same as AddRoundKey
static void AddRoundKey_inv(byte *msg, byte * roundkey) {
	int i;
	for(i = 0 ; i < 16 ; i++)	
		msg[i] = msg[i] ^ roundkey[i];
}

static void mix_col_inv(byte *msg) {
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

static void MixColInv(byte *msg) {
	mix_col_inv(msg);
	mix_col_inv(msg + 4);
	mix_col_inv(msg + 8);
	mix_col_inv(msg + 12);
}

static void ShiftRows_inv(byte *msg) {
	int i;
	byte temp[16];
	//temp = msg;
	memcpy(temp, msg, 16);
	for(i = 0 ; i < 16 ; i++) 
		msg[i] = temp[RowShift_inv[i]];
}

static void SubBytes_inv(byte *msg, int i) {
	int j;
	//char *temp;
	for(j = 0 ; j < i ; j++)
		msg[j] = sbox_inv[msg[j]];		
}

static void decrypt(byte *cipher, const byte *key, byte *orig) {
	int i;
	byte rkey[240];
	KeyExp(key, rkey);

	memcpy(orig, cipher, 16);
	//AddRoundKey(cipher, rkey);

	//first round shudnt have MixCols?
	AddRoundKey(orig, rkey + 224);
	ShiftRows_inv(orig);
	SubBytes_inv(orig, 16);
	
	//14 rounds for 256 key size
	for(i = 0 ; i < 13; i++) {
		AddRoundKey(orig, rkey + ((13 - i) * 16));
		MixColInv(orig);
		ShiftRows_inv(orig);
		SubBytes_inv(orig, 16);
	}
	
	AddRoundKey(orig, rkey);
}

int main() {

	int p1, p2, p3;
	int no, no1, no2, i;
	unsigned int file_size;
	char *temp, *buf;
	//byte key[] = "abcdefghijklmnop";
	
	int random, result;
	if((random = open("/dev/random", O_RDONLY)) == -1) {
		printf("/dev/random cannot be opened.\n");
		exit(1);
	}

	byte key[32];
	int len = 0;
	while(len < 32) {
		result = read(random, key + len, 32 - len);
		if(result < 0) 
			printf("Unable to read /dev/random\n");
		len+=result;
	}
	close(random);

	/*for(i = 0 ; i < 32 ; i++)
		printf("%c\n", key[i]);*/

	byte orig[16], cipher[16], decrypted[16];	
	
	if((p1 = open("msg.txt", O_RDONLY)) == -1) {
		printf("File cannot be opened.\n");
		exit(1);
	}	

	if((p2 = open("enc.txt", O_WRONLY | O_CREAT | O_TRUNC , S_IWUSR | S_IRUSR)) == -1) {
		printf("File cannot be opened.\n");
		exit(1);
	}

	if((p3 = open("dec.txt", O_WRONLY | O_CREAT | O_TRUNC , S_IWUSR | S_IRUSR)) == -1) {
		printf("File cannot be opened.\n");
		exit(1);
	}

	while(no1 = read(p1, orig, 16)) {
		encrypt(orig, key, cipher);
		//printf("%s\n", orig);
		write(p2, cipher, 16);
		if(no1 < 16) {
			write(p2, &no1, sizeof(int));
			break;
		}
		//memset(orig, 0, 16);
	}

	file_size = lseek(p2, 0, SEEK_END);
	
	buf = (char *)malloc(file_size);
	//memcpy(buf, &p2, file_size);
	temp = buf;
	
	close(p2);
	if((p2 = open("enc.txt", O_RDONLY)) == -1) {
		printf("File cannot be opened.\n");
		exit(1);
	}

	//lseek(p2, 0, SEEK_SET);
	
	while(no2 = read(p2, cipher, 16)) {
		if(no2 == 16) {
			decrypt(cipher, key, decrypted);			
			memcpy(temp, decrypted, 16);
			temp+=16;
		}
		else
			memcpy(&no, cipher, 4);
	}		
	
	write(p3, buf, file_size - sizeof(int) - (16 - no));
	//write(p3, buf, temp - buf - (16 - no));
	close(p1);
	close(p2);
	close(p3);
	return 0;
}
