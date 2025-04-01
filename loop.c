#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>

#include "types.h"
#include "bpf.h"

int
loop(const struct bpf *bpf, FILE *log, const struct opts *opts)
{
	unsigned cur;
	int rs;
	char err[256];
	unsigned prev = 0;

	assert(bpf);
	assert(opts);

	fprintf(log, "monitoring for packets on %s interface\n", opts->ifname);
	while (1) {
		(void)read(bpf->fd, bpf->buf, bpf->len); /* blocks until there are packets */

		rs = bpf_gstats(bpf->fd, &cur, err, sizeof err);
		if (rs) {
			fprintf(stderr, "failed to get interface stats: %s\n", err);
			return 1;
		}
		if (cur < prev) {
			fprintf(log, "overflow detected\n");
			prev = cur;
		}
		else if (cur - prev > opts->count) {
			pid_t pid;

			fprintf(log, "packet count reached "
					"(prev=%u cur=%u)\n", prev, cur);
			prev = cur;

			pid = fork();
			if (pid == -1) {
				perror("fork");
				return 1;
			}
			else if (pid == 0) {
				fprintf(log, "child process started\n");
				(void)execve(opts->path, opts->argv, NULL);
				perror("execve");
				return 1;
			}
			else {
				int status;

				rs = waitpid(pid, &status, 0);
				if (rs == -1) {
					perror("waitpid");
					return 1;
				}
				if (WIFSIGNALED(status)) {
					int sig = WTERMSIG(status);
					const char *desc = strsignal(sig);
					fprintf(log, "child process terminated by signal: %d (%s)\n", sig, desc);
				}
				else {
					fprintf(WEXITSTATUS(status) ? stderr : log,
							"child process exited with exit code %d\n",
							WEXITSTATUS(status));
				}
			}
		}
	}
}
