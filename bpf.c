#include <assert.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>

int
bpf_setif(int fd, const char *s, char *strerrbuf, size_t buflen)
{
	struct ifreq i;
	int rs;

	strlcpy(i.ifr_name, s, sizeof i.ifr_name);
	rs = ioctl(fd, BIOCSETIF, &i);
	if (rs == -1) {
		assert(strerrbuf);
		strerror_r(errno, strerrbuf, buflen);
		return 1;
	}

	return 0;
}

int
bpf_lock(int fd, char *strerrbuf, size_t buflen)
{
	int rs;

	rs = ioctl(fd, BIOCLOCK);
	if (rs == -1) {
		assert(strerrbuf);
		strerror_r(errno, strerrbuf, buflen);
		return 1;
	}

	return 0;
}

int
bpf_immediate(int fd, unsigned value, char *strerrbuf, size_t buflen)
{
	int rs;

	rs = ioctl(fd, BIOCIMMEDIATE, &value);
	if (rs == 1) {
		assert(strerrbuf);
		strerror_r(errno, strerrbuf, buflen);
		return 1;
	}

	return 0;
}

int
bpf_gblen(int fd, size_t *len, char *strerrbuf, size_t buflen)
{
	int rs;

	assert(len);
	rs = ioctl(fd, BIOCGBLEN, len);
	if (rs == 1) {
		assert(strerrbuf);
		strerror_r(errno, strerrbuf, buflen);
		return 1;
	}

	return 0;
}

int
bpf_gstats(int fd, unsigned *recv, char *strerrbuf, size_t buflen)
{
	struct bpf_stat s;
	int rs;

	rs = ioctl(fd, BIOCGSTATS, &s);
	if (rs == -1) {
		assert(strerrbuf);
		strerror_r(errno, strerrbuf, buflen);
		return 1;
	}

	assert(recv);
	*recv = s.bs_recv;
	return 0;
}
