project: main.o my_aes.o my_sha256.o
	gcc main.o my_aes.o my_sha256.o -o project
main.o: main.c
	gcc -Wall -c main.c
my_aes.o: my_aes.c my_aes.h
	gcc -Wall -c my_aes.c
my_sha256.o: my_sha256.c my_sha256.h
	gcc -Wall -c my_sha256.c
clean: 
	rm *.o

