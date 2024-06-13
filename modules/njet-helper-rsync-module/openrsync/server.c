/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include "config.h"

#include <sys/stat.h>
#include <sys/socket.h>

#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#if HAVE_ERR
# include <err.h>
#endif

#include "extern.h"

static int
fcntl_nonblock(int fd)
{
	int	 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		ERR("fcntl: F_GETFL");
	else if (fcntl(fd, F_SETFL, fl|O_NONBLOCK) == -1)
		ERR("fcntl: F_SETFL");
	else
		return 1;

	return 0;
}

/*
 * The server (remote) side of the system.
 * This parses the arguments given it by the remote shell then moves
 * into receiver or sender mode depending upon those arguments.
 * Returns exit code 0 on success, 1 on failure, 2 on failure with
 * incompatible protocols.
 */
int
rsync_server(const struct opts *opts,  int fd)
{
	struct sess	 sess;
	int		 fdin = fd, tmp,
			 fdout = fd, rc = 1;
	char     buf[BUFSIZ];
	size_t   i, argc;
	char   **argv;

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	memset(&sess, 0, sizeof(struct sess));
	sess.opts = opts;

	/* Begin by making descriptors non-blocking. */

	if (!fcntl_nonblock(fdin) ||
	    !fcntl_nonblock(fdout)) {
		ERRX1("fcntl_nonblock");
		goto out;
	}

	/* Standard rsync preamble, server side. */

	sess.lver = RSYNC_PROTOCOL;
#if HAVE_ARC4RANDOM
	sess.seed = arc4random();
#else
	sess.seed = random();
#endif

	if (!io_read_int(&sess, fdin, &sess.rver)) {
		ERRX1("io_read_int");
		goto out;
	} else if (!io_write_int(&sess, fdout, sess.lver)) {
		ERRX1("io_write_int");
		goto out;
	} else if (!io_write_int(&sess, fdout, sess.seed)) {
		ERRX1("io_write_int");
		goto out;
	}

    // TODO 这里加入接收文件列表的操作
	if (!io_read_int(&sess, fdin, &tmp)) {
		ERRX1("io_read_int");
		goto out;
	}

	argc = (size_t) tmp;

	if ((argv = calloc(argc, sizeof(char *))) == NULL) {
		err(ERR_NOMEM, NULL);
	}

	for (i = 0 ;; i++) {
		if (!io_read_line(&sess, fdin, buf, BUFSIZ)) {
			ERRX1("io_read_line");
			goto out;
		}
		// fprintf(stderr, "read line %s \n", buf);
		if (strlen(buf) == 0) {
			break;
		}

		argv[i] = strdup(buf);
	}



	sess.mplex_writes = 1;

	if (sess.rver < sess.lver) {
		ERRX("remote protocol %d is older than our own %d: unsupported",
		    sess.rver, sess.lver);
		rc = 2;
		goto out;
	}

	LOG2("server detected client version %d, server version %d, seed %d",
	    sess.rver, sess.lver, sess.seed);

	if (sess.opts->sender) {
		LOG2("server starting sender");

		/*
		 * At this time, I always get a period as the first
		 * argument of the command line.
		 * Let's make it a requirement until I figure out when
		 * that differs.
		 * rsync [flags] "." <source> <...>
		 */

		// if (strcmp(argv[0], ".")) {
		// 	ERRX("first argument must be a standalone period");
		// 	goto out;
		// }
		// argv++;
		// argc--;
		if (argc == 0) {
			ERRX("must have arguments");
			goto out;
		}

		if (!rsync_sender(&sess, fdin, fdout, argc, argv)) {
			ERRX1("rsync_sender");
			goto out;
		}
	} else {
		LOG2("server starting receiver");

		/*
		 * I don't understand why this calling convention
		 * exists, but we must adhere to it.
		 * rsync [flags] "." <destination>
		 */

		if (argc != 2) {
			ERRX("server receiver mode requires two argument");
			goto out;
		} else if (strcmp(argv[0], ".")) {
			ERRX("first argument must be a standalone period");
			goto out;
		}

		if (!rsync_receiver(&sess, fdin, fdout, argv[1])) {
			ERRX1("rsync_receiver");
			goto out;
		}
	}

#if 0
	/* Probably the EOF. */
	if (io_read_check(&sess, fdin))
		WARNX("data remains in read pipe");
#endif

	rc = 0;
out:
	return rc;
}

/*
 * The server (remote) side of the system.
 * This parses the arguments given it by the remote shell then moves
 * into receiver or sender mode depending upon those arguments.
 * Returns exit code 0 on success, 1 on failure, 2 on failure with
 * incompatible protocols.
 */
int
rsync_server_daemon(const struct opts *opts, const char *bind_address, int port)
{
	fd_set deffds;
	int *sp, maxfd, i;

#ifdef HAVE_SIGACTION
	sigact.sa_flags = SA_NOCLDSTOP;
#endif




// 是否只持 ip4
int default_af_hint
#ifdef INET6
	= 0;		/* Any protocol */
#else
	= AF_INET;	/* Must use IPv4 */
# ifdef AF_INET6
#  undef AF_INET6
# endif
# define AF_INET6 AF_INET /* make -6 option a no-op */
#endif
#define RERR_SOCKETIO 10
    // TODO end

	/* open an incoming socket */
	sp = open_socket_in(SOCK_STREAM, port, bind_address, default_af_hint);
	if (sp == NULL)
		// exit_cleanup(RERR_SOCKETIO);
		_exit(RERR_SOCKETIO);

	/* ready to listen */
	FD_ZERO(&deffds);
	for (i = 0, maxfd = -1; sp[i] >= 0; i++) {
		// INTEGER	listen_backlog		5
		// http://nginx.org/en/docs/http/ngx_http_core_module.html#listen 
		// 这里说默认是 511
		if (listen(sp[i], 511) < 0) {
			// rsyserr(FERROR, errno, "listen() on socket failed");
			ERRX("listen() socket failed, errno %d", errno);

#ifdef INET6
			if (errno == EADDRINUSE && i > 0) {
				rprintf(FINFO, "Try using --ipv4 or --ipv6 to avoid this listen() error.\n");
			}
#endif
			// exit_cleanup(RERR_SOCKETIO);
			_exit(RERR_SOCKETIO);
		}
		FD_SET(sp[i], &deffds);
		if (maxfd < sp[i])
			maxfd = sp[i];
	}

	/* now accept incoming connections - forking a new process
	 * for each incoming connection */
	printf("start rsync daemon server \n");
	while (1) {
		fd_set fds;
		pid_t pid;
		int fd;
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof addr;

		/* close log file before the potentially very long select so
		 * file can be trimmed by another process instead of growing
		 * forever */
		// logfile_close();

#ifdef FD_COPY
		FD_COPY(&deffds, &fds);
#else
		fds = deffds;
#endif

		if (select(maxfd + 1, &fds, NULL, NULL, NULL) < 1)
			continue;

		for (i = 0, fd = -1; sp[i] >= 0; i++) {
			if (FD_ISSET(sp[i], &fds)) {
				fd = accept(sp[i], (struct sockaddr *)&addr, &addrlen);
				break;
			}
		}

		if (fd < 0)
			continue;

		// int ret;
		// for (i = 0; sp[i] >= 0; i++)
		// 	close(sp[i]);
		// ret = rsync_server(opts, fd); // 这里需要
		// close_all(); 现在这个函数 什么也没做

		// SIGACTION(SIGCHLD, sigchld_handler); 这个作用待确认

        // 这里涉及到了pid < 0的情况
		if ((pid = fork()) == 0) {
			int ret;
			for (i = 0; sp[i] >= 0; i++)
				close(sp[i]);
			ret = rsync_server(opts, fd); // 这里需要
			_exit(ret);
		} else if (pid < 0) {
			ERRX("could not create child server process");
			close(fd);
			sleep(1);
		} else {
			/* Parent doesn't need this fd anymore. */
			close(fd);
		}
	}

	return 0;
}
