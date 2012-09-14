CFLAGS = -flat_namespace -Wall -O0 -ggdb3

default: test run

libjgmalloc.dylib: CFLAGS+=-fPIC -dynamiclib -flat_namespace

libjgmalloc.dylib: malloc.c
	$(CC) $(CFLAGS) -o $@ $^

test : test.c libjgmalloc.dylib
	$(CC) $(CFLAGS) test.c -o test

run:
	@export DYLD_INSERT_LIBRARIES=./libjgmalloc.dylib && ./test

clean:
	@rm libjgmalloc.dylib
	@rm test
