
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NJT_SETPROCTITLE_H_INCLUDED_
#define _NJT_SETPROCTITLE_H_INCLUDED_


#if (NJT_HAVE_SETPROCTITLE)

/* FreeBSD, NetBSD, OpenBSD */

#define ngx_init_setproctitle(log) NJT_OK
#define ngx_setproctitle(title)    setproctitle("%s", title)


#else /* !NJT_HAVE_SETPROCTITLE */

#if !defined NJT_SETPROCTITLE_USES_ENV

#if (NJT_SOLARIS)

#define NJT_SETPROCTITLE_USES_ENV  1
#define NJT_SETPROCTITLE_PAD       ' '

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#elif (NJT_LINUX) || (NJT_DARWIN)

#define NJT_SETPROCTITLE_USES_ENV  1
#define NJT_SETPROCTITLE_PAD       '\0'

ngx_int_t ngx_init_setproctitle(ngx_log_t *log);
void ngx_setproctitle(char *title);

#else

#define ngx_init_setproctitle(log) NJT_OK
#define ngx_setproctitle(title)

#endif /* OSes */

#endif /* NJT_SETPROCTITLE_USES_ENV */

#endif /* NJT_HAVE_SETPROCTITLE */


#endif /* _NJT_SETPROCTITLE_H_INCLUDED_ */
