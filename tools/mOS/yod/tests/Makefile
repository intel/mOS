CFLAGS=-g -Wall -I..

TESTS=hello affinity_test
all:	$(TESTS)

hello:	hello.c
affinity_test:	affinity_test.o
	$(CC) -o $@ $^ ../cpuset.o

test:	$(TESTS)
	chmod +x *.sh runtests
	./runtests $(YODTEST)

clean:
	rm -f *.o $(TESTS)
