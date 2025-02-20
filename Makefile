LDFLAGS:=`pkg-config --libs libcurl`
CFLAGS:=-g -Wall -Wextra -Wpedantic -Werror -std=c99 `pkg-config --cflags libcurl`

bpfstatsd: main.o bpf.o
	$(CC) ${LDFLAGS} -o $@ $>

%.o:
	$(CC) ${CFLAGS} -o $@ $>

.PHONY: install
install:
	install -o root -g wheel -m 4755 bpfstatsd /usr/local/bin/bpfstatsd

.PHONY: clean
clean:
	rm -f bpfstatsd *.o
