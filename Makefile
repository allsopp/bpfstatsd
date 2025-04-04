CFLAGS:=-g -Wall -Wextra -Wpedantic -Werror -std=c99

bpfstatsd: main.o bpf.o loop.o
	$(CC) ${LDFLAGS} -o $@ $>

%.o:
	$(CC) ${CFLAGS} -o $@ $>

.PHONY: install
install:
	install -o root -g wheel -m 4755 bpfstatsd /usr/local/bin/bpfstatsd

.PHONY: clean
clean:
	rm -f bpfstatsd *.o
