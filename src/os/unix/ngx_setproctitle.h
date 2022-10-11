
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJET_SETPROCTITLE_H_INCLUDED_
#define _NJET_SETPROCTITLE_H_INCLUDED_


#if (NJET_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define ngx_init_setproctitle(log) NJET_OK
#define ngx_setproctitle(title)    setproctitle("%s", title)


#else /* !NJET_HAVE_SETPROCTITLE */

#if !defined NJET_SETPROCTITLE_USES_ENV

#if (NJET_SOLARIS)

#define NJET_SETPROCTITLE_USES_ENV  1
#define NJET_SETPROCTITLE_PAD       ' '

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#elif (NJET_LINUX) || (NJET_DARWIN)

#define NJET_SETPROCTITLE_USES_ENV  1
#define NJET_SETPROCTITLE_PAD       '\0'

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#else

#define ngx_init_setproctitle(log) NJET_OK
#define ngx_setproctitle(title)

#endif /* OSes */

#endif /* NJET_SETPROCTITLE_USES_ENV */

#endif /* NJET_HAVE_SETPROCTITLE */


#endif /* _NJET_SETPROCTITLE_H_INCLUDED_ */
