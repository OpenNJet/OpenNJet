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

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_ERR
# include <err.h>
#endif

#include "extern.h"

/*
 * The rsync client runs on the operator's local machine.
 * It can either be in sender or receiver mode.
 * In the former, it synchronises local files from a remote sink.
 * In the latter, the remote sink synchronses to the local files.
 * Returns exit code 0 on success, 1 on failure, 2 on failure with
 * incompatible protocols.
 */
int
rsync_client(const struct opts *opts, int fd, const struct fargs *f)
{
	struct sess	 sess;
	int	    rc = 1;
	size_t  i;

	/* Standard rsync preamble, sender side. */

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	memset(&sess, 0, sizeof(struct sess));
	sess.opts = opts;
	sess.lver = RSYNC_PROTOCOL;

	if (!io_write_int(&sess, fd, sess.lver)) {
		ERRX1("io_write_int");
		goto out;
	} else if (!io_read_int(&sess, fd, &sess.rver)) {
		ERRX1("io_read_int");
		goto out;
	} else if (!io_read_int(&sess, fd, &sess.seed)) {
		ERRX1("io_read_int");
		goto out;
	}

	if (sess.rver < sess.lver) {
		ERRX("remote protocol %d is older than our own %d: unsupported",
		    sess.rver, sess.lver);
		rc = 2;
		goto out;
	}

	LOG2("client detected client version %d, server version %d, seed %d",
	    sess.lver, sess.rver, sess.seed);

	sess.mplex_reads = 1;

	/*
	 * Now we need to get our list of files.
	 * Senders (and locals) send; receivers receive.
	 */



	if (f->mode != FARGS_RECEIVER) {
		ERRX1("rsync client sender is unspported now");
		LOG2("client starting sender: %s",
		    f->host == NULL ? "(local)" : f->host);
		if (!rsync_sender(&sess, fd, fd, f->sourcesz,
		    f->sources)) {
			ERRX1("rsync_sender");
			goto out;
		}
	} else {

        /* send sources to server*/
		if (!io_write_int(&sess, fd, f->sourcesz)) {
			ERRX1("io_write_int");
			goto out;
		} 

		for (i = 0 ; i < f->sourcesz; i++)
			if (!io_write_line(&sess, fd, f->sources[i])) {
				ERRX1("io_write_line");
				goto out;
			}
		if (!io_write_byte(&sess, fd, '\n')) {
			ERRX1("io_write_line");
			goto out;
		}

		LOG2("client starting receiver: %s",
		    f->host == NULL ? "(local)" : f->host);
		if (!rsync_receiver(&sess, fd, fd, f->sink)) {
			ERRX1("rsync_receiver");
			goto out;
		}
	}

#if 0
	/* Probably the EOF. */
	if (io_read_check(&sess, fd)) {
		WARNX("data remains in read pipe");
	}
#endif

	rc = 0;
out:
	return rc;
}
