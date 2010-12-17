all: switch_code_test

switch_code_test: main.o
	gcc -g `pkg-config --libs libconfig` `curl-config --libs` -lpcap \
	-lsnmp -lpthread `pkg-config --libs gobject-2.0` `pkg-config --libs json-glib-1.0`\
	-o switch_code_test main.o

main.o: main.c
#	wget http://ftp.gnome.org/pub/GNOME/sources/json-glib/0.12/json-glib-0.12.0.tar.bz2
#	tar -xjf json-glib-0.12.0.tar.bz2
#	make -C json-glib-0.12.0/
#	make -C json-glib-0.12.0/ install
	gcc -g `pkg-config --cflags libconfig` `curl-config --cflags` \
	`pkg-config --cflags gobject-2.0` `pkg-config --cflags json-glib-1.0`\
	-c main.c

clean: 
	rm -f *.o *~ switch_code_test
