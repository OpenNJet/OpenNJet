
/*
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NJT_SETAFFINITY_H_INCLUDED_
#define _NJT_SETAFFINITY_H_INCLUDED_


#if (NJT_HAVE_SCHED_SETAFFINITY || NJT_HAVE_CPUSET_SETAFFINITY)

#define NJT_HAVE_CPU_AFFINITY 1

#if (NJT_HAVE_SCHED_SETAFFINITY)

typedef cpu_set_t  ngx_cpuset_t;

#elif (NJT_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

typedef cpuset_t  ngx_cpuset_t;

#endif

void ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log);

#else

#define ngx_setaffinity(cpu_affinity, log)

typedef uint64_t  ngx_cpuset_t;

#endif


#endif /* _NJT_SETAFFINITY_H_INCLUDED_ */
