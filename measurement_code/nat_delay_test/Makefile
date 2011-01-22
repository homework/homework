all: nat_delay_test

nat_delay_test: main.o
	gcc -g `pkg-config --libs libconfig` `curl-config --libs` -lpcap -lnl -lnl-route \
	-lsnmp -lpthread `pkg-config --libs gobject-2.0` `pkg-config --libs json-glib-1.0`\
	-o nat_delay_test main.o

main.o: main.c
	gcc -g `pkg-config --cflags libconfig` `curl-config --cflags` \
	`pkg-config --cflags gobject-2.0` `pkg-config --cflags json-glib-1.0`\
	-c main.c

clean:
	rm -f *.o *~ nat_delay_test
