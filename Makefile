CC=gcc
CFLAGS=-g -Wall -Werror -Iinclude -std=c99

all: ish ishd plugin-icmp.so

ifeq ($(ISH_DEBUG), 1)
CFLAGS+=-DDEBUG -g
endif

debug: CFLAGS+=-DDEBUG -g
debug: all

ish: src/ish.c src/plugin.c
	mkdir -p bin
	$(CC) $(CFLAGS) $^ -ldl -o bin/$@
  
ishd: src/ishd.c src/plugin.c
	mkdir -p bin
	$(CC) $(CFLAGS) $^ -ldl -o bin/$@

plugin-icmp: plugin-icmp.so

plugin-icmp.so: src/plugins/icmp.c
	mkdir -p bin
	$(CC) $(CFLAGS) -fpic -shared $^ -o bin/$@

test:
	valgrind sudo ./bin/ishd 127.0.0.1 ls

clean:
	rm build/*
	rm bin/*