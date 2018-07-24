#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "igd_md5.h"
#include <stdlib.h>

#define TOLOWER(x) ((x) | 0x20)

/* read file , return n bytes read, or -1 if error */
int igd_safe_read(int fd, unsigned char *dst, int len)
{
	int count = 0;
	int ret;

	while (len > 0) {
		ret = read(fd, dst, len);
		if (!ret) 
			break;
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) 
				continue;
			if (errno == EINTR) 
				continue;
			return -1;
		}
		count += ret;
		len -= ret;
		dst += ret;
	}
	return count;
}

static inline int isdigit(int ch)
{
	return (ch >= '0') && (ch <= '9');
}

static inline int isxdigit(int ch)
{
	if (isdigit(ch))
		return 1;

	if ((ch >= 'a') && (ch <= 'f'))
		return 1;

	return (ch >= 'A') && (ch <= 'F');
}

static unsigned int simple_guess_base(const char *cp)
{
	if (cp[0] == '0') {
		if (TOLOWER(cp[1]) == 'x' && isxdigit(cp[2]))
			return 16;
		else
			return 8;
	} else {
		return 10;
	}
}

unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	unsigned long long result = 0;

	if (!base)
		base = simple_guess_base(cp);

	if (base == 16 && cp[0] == '0' && TOLOWER(cp[1]) == 'x')
		cp += 2;

	while (isxdigit(*cp)) {
		unsigned int value;

		value = isdigit(*cp) ? *cp - '0' : TOLOWER(*cp) - 'a' + 10;
		if (value >= base)
			break;
		result = result * base + value;
		cp++;
	}
	if (endp)
		*endp = (char *)cp;

	return result;
}

time_t uptime()
{
	struct sysinfo info;
	if (!sysinfo(&info)) {
		return info.uptime;
	}
	return 0;
}

char * strdup(const char *s)
{
	char *new;

	if ((s == NULL)	||
	    ((new = malloc (strlen(s) + 1)) == NULL) ) {
		return NULL;
	}

	strcpy (new, s);
	return new;
}


int igd_md5sum(char *file, void *md5)
{
	int fd, size, len;
	unsigned char buf[4096] = {0};
	oemMD5_CTX context;
	struct stat st;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0)
		goto err;

	size = (int)st.st_size;
	if (size < 0)
		goto err;

	oemMD5Init(&context);
	while (size > 0) {
		len = igd_safe_read(fd, buf, sizeof(buf));
		if (len == sizeof(buf) || len == size) {
			oemMD5Update(&context, buf, len);
			size -= len;
		} else {
			goto err;
		}
	}
	close(fd);
	oemMD5Final(md5, &context);
	return 0;
err:
	close(fd);
	return -1;
}

