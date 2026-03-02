#ifndef _TYPES_H
#define _TYPES_H

#include <cstddef>

struct bpf {
	int fd;
	size_t len;
	void *buf;
};

struct opts {
	unsigned long count;
	const char *ifname;
	const char *path;
	char **argv;
	int verbose;
};

#endif
