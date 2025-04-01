#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/wait.h>

#include "types.h"
#include "bpf.h"
#include "loop.h"

void
usage(void)
{
	fprintf(stderr, "usage: %s [-hv] [-c count] [-i interface] "
		"<command> [args...]\n", getprogname());
}

int
main(int argc, char **argv)
{
	int rs;
	char ch, err[256];
	FILE *log;

	struct bpf bpf;

	/* defaults */
	struct opts opts;
	opts.count = 1;
	opts.ifname = "pflog0";
	opts.verbose = 0;

	while ((ch = getopt(argc, argv, "c:hi:vw:")) != -1) {
		switch (ch) {
		case 'c':
			opts.count = strtoul(optarg, NULL, 10);
			if (!opts.count) {
				fprintf(stderr, "option 'c' must be greater than zero");
				return EXIT_FAILURE;
			}
			break;
		case 'i':
			opts.ifname = optarg;
			break;
		case 'v':
			opts.verbose = 1;
			break;
		case 'h':
		default:
			usage();
			return EXIT_FAILURE;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc) {
		opts.path = argv[0];
		opts.argv = calloc(1 + argc, sizeof *opts.argv);
		if (opts.argv == NULL) {
			perror("calloc");
			return EXIT_FAILURE;
		}
		for (int i = 0; i < argc; ++i)
			opts.argv[i] = argv[i];
	} else {
		usage();
		return EXIT_FAILURE;
	}

	unveil("/dev/bpf", "r");
	unveil("/dev/null", "rw");
	unveil(opts.path, "x");
	unveil(NULL, NULL);

	if (opts.verbose) {
		log = stderr;
	}
	else {
		log = fopen("/dev/null", "r+e");
		if (log == NULL) {
			perror("failed to open /dev/null");
			return EXIT_FAILURE;
		}
	}

	bpf.fd = open("/dev/bpf", O_RDONLY | O_CLOEXEC);
	if (bpf.fd == -1) {
		perror("failed to open /dev/bpf");
		return EXIT_FAILURE;
	}
	rs = setresuid(getuid(), getuid(), getuid());
	if (rs) {
		perror("failed to drop setuid privileges");
		return EXIT_FAILURE;
	}
	rs = bpf_setif(bpf.fd, opts.ifname, err, sizeof err);
	if (rs) {
		fprintf(stderr, "failed to set interface: %s\n", err);
		return EXIT_FAILURE;
	}

	/*
	 * everything that can be done before BIOCLOCK is now done
	 */
	rs = bpf_lock(bpf.fd, err, sizeof err);
	if (rs) {
		fprintf(stderr, "failed to lock bpf: %s\n", err);
		return EXIT_FAILURE;
	}

	rs = bpf_gblen(bpf.fd, &bpf.len, err, sizeof err);
	if (rs) {
		fprintf(stderr, "failed to get buffer size: %s\n", err);
		return EXIT_FAILURE;
	}
	bpf.buf = malloc(bpf.len);
	if (bpf.buf == NULL) {
		perror("malloc");
		return EXIT_FAILURE;
	}
	rs = bpf_immediate(bpf.fd, 1, err, sizeof err);
	if (rs) {
		fprintf(stderr, "failed to set immediate mode: %s\n", err);
		return EXIT_FAILURE;
	}
	rs = pledge("bpf exec proc stdio", NULL);
	if (rs) {
		perror("pledge");
		return EXIT_FAILURE;
	}
	rs = loop(log, &bpf, &opts);
	if (rs)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
