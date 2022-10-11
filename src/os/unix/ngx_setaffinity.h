
/*
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NJET_SETAFFINITY_H_INCLUDED_
#define _NJET_SETAFFINITY_H_INCLUDED_


#if (NJET_HAVE_SCHED_SETAFFINITY || NJET_HAVE_CPUSET_SETAFFINITY)

#define NJET_HAVE_CPU_AFFINITY 1

#if (NJET_HAVE_SCHED_SETAFFINITY)

typedef cpu_set_t  ngx_cpuset_t;

#elif (NJET_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

typedef cpuset_t  ngx_cpuset_t;

#endif

void ngx_setaffinity(ngx_cpuset_t *cpu_affinity, ngx_log_t *log);

#else

#define ngx_setaffinity(cpu_affinity, log)

typedef uint64_t  ngx_cpuset_t;

#endif


#endif /* _NJET_SETAFFINITY_H_INCLUDED_ */
