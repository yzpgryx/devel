CC=$(CROSS_COMPILE)gcc
CFLAGS=-I../


all: daemon

daemon:
	$(CC) $(CFLAGS) -o daemon daemon.c ../util.c

.PHONY: all clean daemon
clean:
	rm -rf daemon

