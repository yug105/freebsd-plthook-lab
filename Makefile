CC ?= cc
CFLAGS ?= -Wall -Wextra -g
LDLIBS ?= -lutil

PROGS = testprog claimcheck
TESTPROG_OBJS = testprog.o
CLAIMCHECK_OBJS = claimcheck.o

.PHONY: all clean

all: $(PROGS)

testprog: $(TESTPROG_OBJS)
	$(CC) $(CFLAGS) -o testprog $(TESTPROG_OBJS) $(LDLIBS)

claimcheck: $(CLAIMCHECK_OBJS)
	$(CC) $(CFLAGS) -o claimcheck $(CLAIMCHECK_OBJS) $(LDLIBS)

testprog.o: testprog.c
	$(CC) $(CFLAGS) -c testprog.c

claimcheck.o: claimcheck.c
	$(CC) $(CFLAGS) -c claimcheck.c

clean:
	rm -f $(PROGS) $(TESTPROG_OBJS) $(CLAIMCHECK_OBJS)
