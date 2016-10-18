try_my_aes : my_aes.h my_aes.c lookup_tables.h
	gcc -o my_aes my_aes.c -lcrypto -Wall
