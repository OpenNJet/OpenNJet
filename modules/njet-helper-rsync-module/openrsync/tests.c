#if TEST___PROGNAME
int
main(void)
{
	extern char *__progname;

	return !__progname;
}
#endif /* TEST___PROGNAME */
#if TEST_ARC4RANDOM
#include <stdlib.h>

int
main(void)
{
	return (arc4random() + 1) ? 0 : 1;
}
#endif /* TEST_ARC4RANDOM */
#if TEST_B64_NTOP
#include <netinet/in.h>
#include <resolv.h>

int
main(void)
{
	const char *src = "hello world";
	char output[1024];

	return b64_ntop((const unsigned char *)src, 11, output, sizeof(output)) > 0 ? 0 : 1;
}
#endif /* TEST_B64_NTOP */
#if TEST_CAPSICUM
#include <sys/capsicum.h>

int
main(void)
{
	cap_enter();
	return(0);
}
#endif /* TEST_CAPSICUM */
#if TEST_CRYPT
#if defined(__linux__)
# define _GNU_SOURCE /* old glibc */
# define _DEFAULT_SOURCE /* new glibc */
#endif
#if defined(__sun)
# ifndef _XOPEN_SOURCE /* SunOS already defines */
#  define _XOPEN_SOURCE /* XPGx */
# endif
# define _XOPEN_SOURCE_EXTENDED 1 /* XPG4v2 */
# ifndef __EXTENSIONS__ /* SunOS already defines */
#  define __EXTENSIONS__ /* reallocarray, etc. */
# endif
#endif
#include <unistd.h>

int main(void)
{
	char	*v;

	v = crypt("this_is_a_key", "123455");
	return v == NULL;
}
#endif /* TEST_CRYPT */
#if TEST_CRYPT_NEWHASH
#include <pwd.h> /* _PASSWORD_LEN */
#include <unistd.h>

int
main(void)
{
	const char	*v = "password";
	char		 hash[_PASSWORD_LEN];

	if (crypt_newhash(v, "bcrypt,a", hash, sizeof(hash)) == -1)
		return 1;
	if (crypt_checkpass(v, hash) == -1)
		return 1;

	return 0;
}
#endif /* TEST_CRYPT_NEWHASH */
#if TEST_ENDIAN_H
#ifdef __linux__
# define _DEFAULT_SOURCE
#endif
#include <endian.h>

int
main(void)
{
	return !htole32(23);
}
#endif /* TEST_ENDIAN_H */
#if TEST_ERR
/*
 * Copyright (c) 2015 Ingo Schwarze <schwarze@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <errno.h>

int
main(void)
{
	warnx("%d. warnx", 1);
	warnc(ENOENT, "%d. warn", ENOENT);
	warn("%d. warn", 2);
	err(0, "%d. err", 3);
	errx(0, "%d. err", 3);
	errc(0, ENOENT, "%d. err", 3);
	/* NOTREACHED */
	return 1;
}
#endif /* TEST_ERR */
#if TEST_EXPLICIT_BZERO
#include <string.h>

int
main(void)
{
	char foo[10];

	explicit_bzero(foo, sizeof(foo));
	return(0);
}
#endif /* TEST_EXPLICIT_BZERO */
#if TEST_FTS
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>

int
main(void)
{
	const char	*argv[2];
	FTS		*ftsp;
	FTSENT		*entry;

	argv[0] = ".";
	argv[1] = (char *)NULL;

	ftsp = fts_open((char * const *)argv,
	    FTS_PHYSICAL | FTS_NOCHDIR, NULL);

	if (ftsp == NULL)
		return 1;

	entry = fts_read(ftsp);

	if (entry == NULL)
		return 1;

	if (fts_set(ftsp, entry, FTS_SKIP) != 0) 
		return 1;

	if (fts_close(ftsp) != 0)
		return 1;

	return 0;
}
#endif /* TEST_FTS */
#if TEST_GETEXECNAME
#include <stdlib.h>

int
main(void)
{
	const char * progname;

	progname = getexecname();
	return progname == NULL;
}
#endif /* TEST_GETEXECNAME */
#if TEST_GETPROGNAME
#include <stdlib.h>

int
main(void)
{
	const char * progname;

	progname = getprogname();
	return progname == NULL;
}
#endif /* TEST_GETPROGNAME */
#if TEST_INFTIM
/*
 * Linux doesn't (always?) have this.
 */

#include <poll.h>
#include <stdio.h>

int
main(void)
{
	printf("INFTIM is defined to be %ld\n", (long)INFTIM);
	return 0;
}
#endif /* TEST_INFTIM */
#if TEST_LANDLOCK
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
	const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
	const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

int
main(void)
{
	uint64_t mask = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
	struct landlock_ruleset_attr rules = {
		.handled_access_fs = mask
	};
	int fd = landlock_create_ruleset(&rules, sizeof(rules), 0);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return 1;
	return landlock_restrict_self(fd, 0) ? 1 : 0;
}
#endif /* TEST_LANDLOCK */
#if TEST_LIB_SOCKET
#include <sys/socket.h>

int
main(void)
{
	int fds[2], c;

	c = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	return c == -1;
}
#endif /* TEST_LIB_SOCKET */
#if TEST_MD5
#include <sys/types.h>
#include <md5.h>

int main(void)
{
	MD5_CTX ctx;
	char result[MD5_DIGEST_STRING_LENGTH];

	MD5Init(&ctx);
	MD5Update(&ctx, (const unsigned char *)"abcd", 4);
	MD5End(&ctx, result);

	return 0;
}
#endif /* TEST_MD5 */
#if TEST_MEMMEM
#define _GNU_SOURCE
#include <string.h>

int
main(void)
{
	char *a = memmem("hello, world", strlen("hello, world"), "world", strlen("world"));
	return(NULL == a);
}
#endif /* TEST_MEMMEM */
#if TEST_MEMRCHR
#if defined(__linux__) || defined(__MINT__)
#define _GNU_SOURCE	/* See test-*.c what needs this. */
#endif
#include <string.h>

int
main(void)
{
	const char *buf = "abcdef";
	void *res;

	res = memrchr(buf, 'a', strlen(buf));
	return(NULL == res ? 1 : 0);
}
#endif /* TEST_MEMRCHR */
#if TEST_MEMSET_S
#include <string.h>

int main(void)
{
	char buf[10];
	memset_s(buf, 0, 'c', sizeof(buf));
	return 0;
}
#endif /* TEST_MEMSET_S */
#if TEST_MKFIFOAT
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
	mkfifoat(AT_FDCWD, "this/path/should/not/exist", 0600);
	return 0;
}
#endif /* TEST_MKFIFOAT */
#if TEST_MKNODAT
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
	mknodat(AT_FDCWD, "this/path/should/not/exist", S_IFIFO | 0600, 0);
	return 0;
}
#endif /* TEST_MKNODAT */
#if TEST_OSBYTEORDER_H
#include <libkern/OSByteOrder.h>

int
main(void)
{
	return !OSSwapHostToLittleInt32(23);
}
#endif /* TEST_OSBYTEORDER_H */
#if TEST_PATH_MAX
/*
 * POSIX allows PATH_MAX to not be defined, see
 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/sysconf.html;
 * the GNU Hurd is an example of a system not having it.
 *
 * Arguably, it would be better to test sysconf(_SC_PATH_MAX),
 * but since the individual *.c files include "config.h" before
 * <limits.h>, overriding an excessive value of PATH_MAX from
 * "config.h" is impossible anyway, so for now, the simplest
 * fix is to provide a value only on systems not having any.
 * So far, we encountered no system defining PATH_MAX to an
 * impractically large value, even though POSIX explicitly
 * allows that.
 *
 * The real fix would be to replace all static buffers of size
 * PATH_MAX by dynamically allocated buffers.  But that is
 * somewhat intrusive because it touches several files and
 * because it requires changing struct mlink in mandocdb.c.
 * So i'm postponing that for now.
 */

#include <limits.h>
#include <stdio.h>

int
main(void)
{
	printf("PATH_MAX is defined to be %ld\n", (long)PATH_MAX);
	return 0;
}
#endif /* TEST_PATH_MAX */
#if TEST_PLEDGE
#include <unistd.h>

int
main(void)
{
	return !!pledge("stdio", NULL);
}
#endif /* TEST_PLEDGE */
#if TEST_PROGRAM_INVOCATION_SHORT_NAME
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <errno.h>

int
main(void)
{

	return !program_invocation_short_name;
}
#endif /* TEST_PROGRAM_INVOCATION_SHORT_NAME */
#if TEST_READPASSPHRASE
#include <stddef.h>
#include <readpassphrase.h>

int
main(void)
{
	return !!readpassphrase("prompt: ", NULL, 0, 0);
}
#endif /* TEST_READPASSPHRASE */
#if TEST_REALLOCARRAY
#ifdef __NetBSD__
# define _OPENBSD_SOURCE
#endif
#include <stdlib.h>

int
main(void)
{
	return !reallocarray(NULL, 2, 2);
}
#endif /* TEST_REALLOCARRAY */
#if TEST_RECALLOCARRAY
#include <stdlib.h>

int
main(void)
{
	return !recallocarray(NULL, 0, 2, 2);
}
#endif /* TEST_RECALLOCARRAY */
#if TEST_SANDBOX_INIT
#include <sandbox.h>

int
main(void)
{
	char	*ep;
	int	 rc;

	rc = sandbox_init(kSBXProfileNoInternet, SANDBOX_NAMED, &ep);
	if (-1 == rc)
		sandbox_free_error(ep);
	return(-1 == rc);
}
#endif /* TEST_SANDBOX_INIT */
#if TEST_SCAN_SCALED
#include <util.h>

int
main(void)
{
	char *cinput = (char *)"1.5K", buf[FMT_SCALED_STRSIZE];
	long long ninput = 10483892, result;
	return scan_scaled(cinput, &result) == 0;
}
#endif /* TEST_SCAN_SCALED */
#if TEST_SECCOMP_FILTER
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <errno.h>

int
main(void)
{

	prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, 0);
	return(EFAULT == errno ? 0 : 1);
}
#endif /* TEST_SECCOMP_FILTER */
#if TEST_SETRESGID
#define _GNU_SOURCE /* linux */
#include <sys/types.h>
#include <unistd.h>

int
main(void)
{
	return setresgid(-1, -1, -1) == -1;
}
#endif /* TEST_SETRESGID */
#if TEST_SETRESUID
#define _GNU_SOURCE /* linux */
#include <sys/types.h>
#include <unistd.h>

int
main(void)
{
	return setresuid(-1, -1, -1) == -1;
}
#endif /* TEST_SETRESUID */
#if TEST_SHA2
#include <sys/types.h>
#include <sha2.h>

int main(void)
{
	SHA2_CTX ctx;
	char result[SHA256_DIGEST_STRING_LENGTH];

	SHA256Init(&ctx);
	SHA256Update(&ctx, (const unsigned char *)"abcd", 4);
	SHA256End(&ctx, result);

	return 0;
}
#endif /* TEST_SHA2 */
#if TEST_SOCK_NONBLOCK
/*
 * Linux doesn't (always?) have this.
 */

#include <sys/socket.h>

int
main(void)
{
	int fd[2];
	socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, fd);
	return 0;
}
#endif /* TEST_SOCK_NONBLOCK */
#if TEST_STATIC
int
main(void)
{
	return 0; /* not meant to do anything */
}
#endif /* TEST_STATIC */
#if TEST_STRLCAT
#include <string.h>

int
main(void)
{
	char buf[3] = "a";
	return ! (strlcat(buf, "b", sizeof(buf)) == 2 &&
	    buf[0] == 'a' && buf[1] == 'b' && buf[2] == '\0');
}
#endif /* TEST_STRLCAT */
#if TEST_STRLCPY
#include <string.h>

int
main(void)
{
	char buf[2] = "";
	return ! (strlcpy(buf, "a", sizeof(buf)) == 1 &&
	    buf[0] == 'a' && buf[1] == '\0');
}
#endif /* TEST_STRLCPY */
#if TEST_STRNDUP
#include <string.h>

int
main(void)
{
	const char *foo = "bar";
	char *baz;

	baz = strndup(foo, 1);
	return(0 != strcmp(baz, "b"));
}
#endif /* TEST_STRNDUP */
#if TEST_STRNLEN
#include <string.h>

int
main(void)
{
	const char *foo = "bar";
	size_t sz;

	sz = strnlen(foo, 1);
	return(1 != sz);
}
#endif /* TEST_STRNLEN */
#if TEST_STRTONUM
/*
 * Copyright (c) 2015 Ingo Schwarze <schwarze@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef __NetBSD__
# define _OPENBSD_SOURCE
#endif
#include <stdlib.h>

int
main(void)
{
	const char *errstr;

	if (strtonum("1", 0, 2, &errstr) != 1)
		return 1;
	if (errstr != NULL)
		return 2;
	if (strtonum("1x", 0, 2, &errstr) != 0)
		return 3;
	if (errstr == NULL)
		return 4;
	if (strtonum("2", 0, 1, &errstr) != 0)
		return 5;
	if (errstr == NULL)
		return 6;
	if (strtonum("0", 1, 2, &errstr) != 0)
		return 7;
	if (errstr == NULL)
		return 8;
	return 0;
}
#endif /* TEST_STRTONUM */
#if TEST_SYS_BYTEORDER_H
#include <sys/byteorder.h>

int
main(void)
{
	return !LE_32(23);
}
#endif /* TEST_SYS_BYTEORDER_H */
#if TEST_SYS_ENDIAN_H
#include <sys/endian.h>

int
main(void)
{
	return !htole32(23);
}
#endif /* TEST_SYS_ENDIAN_H */
#if TEST_SYS_MKDEV_H
#include <sys/types.h>
#include <sys/mkdev.h>

int
main(void)
{
	return !minor(0);
}
#endif /* TEST_SYS_MKDEV_H */
#if TEST_SYS_QUEUE
#include <sys/queue.h>
#include <stddef.h>

struct foo {
	int bar;
	TAILQ_ENTRY(foo) entries;
};

TAILQ_HEAD(fooq, foo);

int
main(void)
{
	struct fooq foo_q, bar_q;
	struct foo *p, *tmp;
	int i = 0;

	TAILQ_INIT(&foo_q);
	TAILQ_INIT(&bar_q);

	/*
	 * Use TAILQ_FOREACH_SAFE because some systems (e.g., Linux)
	 * have TAILQ_FOREACH but not the safe variant.
	 */

	TAILQ_FOREACH_SAFE(p, &foo_q, entries, tmp)
		p->bar = i++;

	/* Test for newer macros as well. */

	TAILQ_CONCAT(&foo_q, &bar_q, entries);
	return 0;
}
#endif /* TEST_SYS_QUEUE */
#if TEST_SYS_SYSMACROS_H
#include <sys/sysmacros.h>

int
main(void)
{
	return !minor(0);
}
#endif /* TEST_SYS_SYSMACROS_H */
#if TEST_SYS_TREE
#include <sys/tree.h>
#include <stdlib.h>

struct node {
	RB_ENTRY(node) entry;
	int i;
};

static int
intcmp(struct node *e1, struct node *e2)
{
	return (e1->i < e2->i ? -1 : e1->i > e2->i);
}

RB_HEAD(inttree, node) head = RB_INITIALIZER(&head);
RB_PROTOTYPE(inttree, node, entry, intcmp)
RB_GENERATE(inttree, node, entry, intcmp)

int testdata[] = {
	20, 16, 17, 13, 3, 6, 1, 8, 2, 4
};

int
main(void)
{
	size_t i;
	struct node *n;

	for (i = 0; i < sizeof(testdata) / sizeof(testdata[0]); i++) {
		if ((n = malloc(sizeof(struct node))) == NULL)
			return 1;
		n->i = testdata[i];
		RB_INSERT(inttree, &head, n);
	}

	return 0;
}

#endif /* TEST_SYS_TREE */
#if TEST_UNVEIL
#include <unistd.h>

int
main(void)
{
	return -1 != unveil(NULL, NULL);
}
#endif /* TEST_UNVEIL */
#if TEST_WAIT_ANY
#include <sys/wait.h>

int
main(void)
{
	int st;

	return waitpid(WAIT_ANY, &st, WNOHANG) != -1;
}
#endif /* TEST_WAIT_ANY */
