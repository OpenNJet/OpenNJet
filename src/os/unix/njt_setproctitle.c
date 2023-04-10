
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_SETPROCTITLE_USES_ENV)

/*
 * To change the process title in Linux and Solaris we have to set argv[1]
 * to NULL and to copy the title to the same place where the argv[0] points to.
 * However, argv[0] may be too small to hold a new title.  Fortunately, Linux
 * and Solaris store argv[] and environ[] one after another.  So we should
 * ensure that is the continuous memory and then we allocate the new memory
 * for environ[] and copy it.  After this we could use the memory starting
 * from argv[0] for our process title.
 *
 * The Solaris's standard /bin/ps does not show the changed process title.
 * You have to use "/usr/ucb/ps -w" instead.  Besides, the UCB ps does not
 * show a new title if its length less than the origin command line length.
 * To avoid it we append to a new title the origin command line in the
 * parenthesis.
 */

extern char **environ;

static char *njt_os_argv_last;

njt_int_t
njt_init_setproctitle(njt_log_t *log)
{
    u_char      *p;
    size_t       size;
    njt_uint_t   i;

    size = 0;

    for (i = 0; environ[i]; i++) {
        size += njt_strlen(environ[i]) + 1;
    }

    p = njt_alloc(size, log);
    if (p == NULL) {
        return NJT_ERROR;
    }

    njt_os_argv_last = njt_os_argv[0];

    for (i = 0; njt_os_argv[i]; i++) {
        if (njt_os_argv_last == njt_os_argv[i]) {
            njt_os_argv_last = njt_os_argv[i] + njt_strlen(njt_os_argv[i]) + 1;
        }
    }

    for (i = 0; environ[i]; i++) {
        if (njt_os_argv_last == environ[i]) {

            size = njt_strlen(environ[i]) + 1;
            njt_os_argv_last = environ[i] + size;

            njt_cpystrn(p, (u_char *) environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    njt_os_argv_last--;

    return NJT_OK;
}


void
njt_setproctitle(char *title)
{
    u_char     *p;

#if (NJT_SOLARIS)

    njt_int_t   i;
    size_t      size;

#endif

    njt_os_argv[1] = NULL;

    p = njt_cpystrn((u_char *) njt_os_argv[0], (u_char *) "njet: ",
                    njt_os_argv_last - njt_os_argv[0]);

    p = njt_cpystrn(p, (u_char *) title, njt_os_argv_last - (char *) p);

#if (NJT_SOLARIS)

    size = 0;

    for (i = 0; i < njt_argc; i++) {
        size += njt_strlen(njt_argv[i]) + 1;
    }

    if (size > (size_t) ((char *) p - njt_os_argv[0])) {

        /*
         * njt_setproctitle() is too rare operation so we use
         * the non-optimized copies
         */

        p = njt_cpystrn(p, (u_char *) " (", njt_os_argv_last - (char *) p);

        for (i = 0; i < njt_argc; i++) {
            p = njt_cpystrn(p, (u_char *) njt_argv[i],
                            njt_os_argv_last - (char *) p);
            p = njt_cpystrn(p, (u_char *) " ", njt_os_argv_last - (char *) p);
        }

        if (*(p - 1) == ' ') {
            *(p - 1) = ')';
        }
    }

#endif

    if (njt_os_argv_last - (char *) p) {
        njt_memset(p, NJT_SETPROCTITLE_PAD, njt_os_argv_last - (char *) p);
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                   "setproctitle: \"%s\"", njt_os_argv[0]);
}

#endif /* NJT_SETPROCTITLE_USES_ENV */
