all: switch_code_test

switch_code_test: main.o
	gcc -o switch_code_test main.o

main.o: main.o
	gcc -c main.c

clean: 
	rm -f *.o *~ switch_code_test