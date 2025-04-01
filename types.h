#ifndef _TYPES_H
#define _TYPES_H

struct bpf {
	int fd;
	size_t len;
	void *buf;
};

struct opts {
	unsigned count;
	const char *ifname;
	const char *path;
	char **argv;
	int verbose;
};

#endif
