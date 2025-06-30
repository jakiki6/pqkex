ifdef DEBUG
CFLAGS := -O2 -g
else
CFLAGS := -O3 -march=native -mtune=native -Wall -Werror -Wunused -Wextra -Wpedantic
endif

CC := clang

all: libpqkex.so libpqkex.a test

check: test
	./test

test: test.c libpqkex.a
	$(CC) $(CFLAGS) -o $@ test.c libpqkex.a

libpqkex.a: libpqkex.o
	ar rs $@ $^

libpqkex.o: pqkex.c
	$(CC) $(CFLAGS) -c -o $@ $^

libpqkex.so: pqkex.c
	$(CC) $(CFLAGS) -shared -o $@ $^
ifndef DEBUG
	strip $@
endif

clean:
	rm -f libpqkex.so libpqkex.o libpqkex.a

.PHONY: all clean check
