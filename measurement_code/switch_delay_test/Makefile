all: switch_code_test

switch_code_test: main.o
	gcc `pkg-config --libs libconfig` `curl-config --libs` -lsnmp -o switch_code_test main.o

main.o: main.c
	gcc `pkg-config --cflags libconfig` `curl-config --cflags` -c main.c

clean: 
	rm -f *.o *~ switch_code_test