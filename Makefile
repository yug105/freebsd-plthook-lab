CC ?= cc
CFLAGS ?= -Wall -Wextra -g
LDLIBS ?= -lutil

PROG = testprog
OBJS = testprog.o

.PHONY: all clean

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(LDLIBS)

testprog.o: testprog.c
	$(CC) $(CFLAGS) -c testprog.c

clean:
	rm -f $(PROG) $(OBJS)
