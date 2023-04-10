
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_RWLOCK_H_INCLUDED_
#define _NJT_RWLOCK_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>


void njt_rwlock_wlock(njt_atomic_t *lock);
void njt_rwlock_rlock(njt_atomic_t *lock);
void njt_rwlock_unlock(njt_atomic_t *lock);
void njt_rwlock_downgrade(njt_atomic_t *lock);


#endif /* _NJT_RWLOCK_H_INCLUDED_ */
