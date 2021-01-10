
unity: unity.o
	gcc -o unity unity.o -lcrypto

unity.o: unity.c
	gcc -c -Wall unity.c

clean:
	rm -f *.o unity
