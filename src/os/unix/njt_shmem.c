
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#if (NJT_HAVE_MAP_ANON)

njt_int_t
njt_shm_alloc(njt_shm_t *shm)
{
    shm->addr = (u_char *) mmap(NULL, shm->size,
                                PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0);

    if (shm->addr == MAP_FAILED) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
        return NJT_ERROR;
    }

    return NJT_OK;
}


void
njt_shm_free(njt_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (NJT_HAVE_MAP_DEVZERO)

njt_int_t
njt_shm_alloc(njt_shm_t *shm)
{
    njt_fd_t  fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "open(\"/dev/zero\") failed");
        return NJT_ERROR;
    }

    shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE,
                                MAP_SHARED, fd, 0);

    if (shm->addr == MAP_FAILED) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
    }

    if (close(fd) == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "close(\"/dev/zero\") failed");
    }

    return (shm->addr == MAP_FAILED) ? NJT_ERROR : NJT_OK;
}


void
njt_shm_free(njt_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (NJT_HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>


njt_int_t
njt_shm_alloc(njt_shm_t *shm)
{
    int  id;

    id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "shmget(%uz) failed", shm->size);
        return NJT_ERROR;
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);

    shm->addr = shmat(id, NULL, 0);

    if (shm->addr == (void *) -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno, "shmat() failed");
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "shmctl(IPC_RMID) failed");
    }

    return (shm->addr == (void *) -1) ? NJT_ERROR : NJT_OK;
}


void
njt_shm_free(njt_shm_t *shm)
{
    if (shmdt(shm->addr) == -1) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "shmdt(%p) failed", shm->addr);
    }
}

#endif
