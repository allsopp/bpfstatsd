#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/wait.h>

#include "bpf.h"

struct opts {
	unsigned int count;
	unsigned int wait;
	const char *ifname;
	const char *path;
	char **argv;
	int verbose;
} opts;

void
usage(void)
{
	fprintf(stderr, "usage: %s [-hv] [-c count] [-i interface] [-w wait] "
		"<command> [args...]\n", getprogname());
}

int
main(int argc, char **argv)
{
	int fd, rs;
	char ch, err[256];
	unsigned int prev = 0;

	/* defaults */
	opts.count = 1;
	opts.wait = 1;
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
		case 'w':
			opts.wait = strtoul(optarg, NULL, 10);
			if (!opts.wait) {
				fprintf(stderr, "option 'w' must be greater than zero");
				return EXIT_FAILURE;
			}
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
	unveil(opts.path, "x");
	unveil(NULL, NULL);

	/* only need to open for reading
	 * and set to close on exec */
	fd = open("/dev/bpf", O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		perror("failed to open /dev/bpf");
		return EXIT_FAILURE;
	}
	/* drop setuid privilieges */
	rs = setresuid(getuid(), getuid(), getuid());
	if (rs) {
		perror("failed to drop setuid privileges");
		return EXIT_FAILURE;
	}
	rs = bpf_setif(fd, opts.ifname, err, sizeof err);
	if (rs) {
		fprintf(stderr, "failed to set interface: %s\n", err);
		return EXIT_FAILURE;
	}
	rs = bpf_lock(fd, err, sizeof err);
	if (rs) {
		fprintf(stderr, "failed to lock bpf: %s\n", err);
		return EXIT_FAILURE;
	}
	rs = pledge("bpf exec proc stdio", NULL);
	if (rs) {
		perror("pledge");
		return EXIT_FAILURE;
	}

	if (opts.verbose)
		fprintf(stderr, "monitoring for packets on %s interface\n", opts.ifname);

	while (1) {
		unsigned int cur;
		pid_t pid;
		int status;

		rs = bpf_gstats(fd, &cur, err, sizeof err);
		if (rs) {
			fprintf(stderr, "failed to get interface stats: %s\n", err);
			return EXIT_FAILURE;
		}
		if (cur < prev) {
			fprintf(stderr, "overflow detected\n");
			prev = cur;
		}
		else if (cur - prev > opts.count) {
			if (opts.verbose) {
				fprintf(stderr, "packet count reached "
						"(prev=%u cur=%u)\n", prev, cur);
			}
			prev = cur;

			pid = fork();
			if (pid == -1) {
				perror("fork");
				return EXIT_FAILURE;
			}
			else if (pid == 0) {
				if (opts.verbose) {
					fprintf(stderr, "child process started\n");
					fprintf(stderr, "running command: %s", opts.path);
					for (int i = 1; i < argc; ++i)
						fprintf(stderr, " %s", argv[i]);
					fprintf(stderr, "\n");
				}
				rs = execve(opts.path, opts.argv, NULL);
				if (rs == -1) {
					perror("execve");
					return EXIT_FAILURE;
				}
				return EXIT_SUCCESS;
			}
			else {
				rs = waitpid(pid, &status, 0);
				if (rs == -1) {
					perror("waitpid");
					return EXIT_FAILURE;
				}
				if (WIFSIGNALED(status))
					fprintf(stderr, "child process terminated by signal %d\n", WTERMSIG(status));
				else if (opts.verbose || WEXITSTATUS(status))
					fprintf(stderr, "child process exited with exit code: %d\n", WEXITSTATUS(status));
			}
		}
		sleep(opts.wait);
	}

	return EXIT_SUCCESS;
}
