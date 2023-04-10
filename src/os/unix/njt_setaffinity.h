
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#ifndef _NJT_SETAFFINITY_H_INCLUDED_
#define _NJT_SETAFFINITY_H_INCLUDED_


#if (NJT_HAVE_SCHED_SETAFFINITY || NJT_HAVE_CPUSET_SETAFFINITY)

#define NJT_HAVE_CPU_AFFINITY 1

#if (NJT_HAVE_SCHED_SETAFFINITY)

typedef cpu_set_t  njt_cpuset_t;

#elif (NJT_HAVE_CPUSET_SETAFFINITY)

#include <sys/cpuset.h>

typedef cpuset_t  njt_cpuset_t;

#endif

void njt_setaffinity(njt_cpuset_t *cpu_affinity, njt_log_t *log);

#else

#define njt_setaffinity(cpu_affinity, log)

typedef uint64_t  njt_cpuset_t;

#endif


#endif /* _NJT_SETAFFINITY_H_INCLUDED_ */
