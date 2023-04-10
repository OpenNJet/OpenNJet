
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


/*
 * Base addresses selected by system for shared memory mappings are likely
 * to be different on Windows Vista and later versions due to address space
 * layout randomization.  This is however incompatible with storing absolute
 * addresses within the shared memory.
 *
 * To make it possible to store absolute addresses we create mappings
 * at the same address in all processes by starting mappings at predefined
 * addresses.  The addresses were selected somewhat randomly in order to
 * minimize the probability that some other library doing something similar
 * conflicts with us.  The addresses are from the following typically free
 * blocks:
 *
 * - 0x10000000 .. 0x70000000 (about 1.5 GB in total) on 32-bit platforms
 * - 0x000000007fff0000 .. 0x000007f68e8b0000 (about 8 TB) on 64-bit platforms
 *
 * Additionally, we allow to change the mapping address once it was detected
 * to be different from one originally used.  This is needed to support
 * reconfiguration.
 */


#ifdef _WIN64
#define NJT_SHMEM_BASE  0x0000047047e00000
#else
#define NJT_SHMEM_BASE  0x2efe0000
#endif


njt_uint_t  njt_allocation_granularity;


njt_int_t
njt_shm_alloc(njt_shm_t *shm)
{
    u_char         *name;
    uint64_t        size;
    static u_char  *base = (u_char *) NJT_SHMEM_BASE;

    name = njt_alloc(shm->name.len + 2 + NJT_INT32_LEN, shm->log);
    if (name == NULL) {
        return NJT_ERROR;
    }

    (void) njt_sprintf(name, "%V_%s%Z", &shm->name, njt_unique);

    njt_set_errno(0);

    size = shm->size;

    shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    (u_long) (size >> 32),
                                    (u_long) (size & 0xffffffff),
                                    (char *) name);

    if (shm->handle == NULL) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "CreateFileMapping(%uz, %s) failed",
                      shm->size, name);
        njt_free(name);

        return NJT_ERROR;
    }

    njt_free(name);

    if (njt_errno == ERROR_ALREADY_EXISTS) {
        shm->exists = 1;
    }

    shm->addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, base);

    if (shm->addr != NULL) {
        base += njt_align(size, njt_allocation_granularity);
        return NJT_OK;
    }

    njt_log_debug3(NJT_LOG_DEBUG_CORE, shm->log, njt_errno,
                   "MapViewOfFileEx(%uz, %p) of file mapping \"%V\" failed, "
                   "retry without a base address",
                   shm->size, base, &shm->name);

    /*
     * Order of shared memory zones may be different in the master process
     * and worker processes after reconfiguration.  As a result, the above
     * may fail due to a conflict with a previously created mapping remapped
     * to a different address.  Additionally, there may be a conflict with
     * some other uses of the memory.  In this case we retry without a base
     * address to let the system assign the address itself.
     */

    shm->addr = MapViewOfFile(shm->handle, FILE_MAP_WRITE, 0, 0, 0);

    if (shm->addr != NULL) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                  "MapViewOfFile(%uz) of file mapping \"%V\" failed",
                  shm->size, &shm->name);

    if (CloseHandle(shm->handle) == 0) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "CloseHandle() of file mapping \"%V\" failed",
                      &shm->name);
    }

    return NJT_ERROR;
}


njt_int_t
njt_shm_remap(njt_shm_t *shm, u_char *addr)
{
    if (UnmapViewOfFile(shm->addr) == 0) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "UnmapViewOfFile(%p) of file mapping \"%V\" failed",
                      shm->addr, &shm->name);
        return NJT_ERROR;
    }

    shm->addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, addr);

    if (shm->addr != NULL) {
        return NJT_OK;
    }

    njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                  "MapViewOfFileEx(%uz, %p) of file mapping \"%V\" failed",
                  shm->size, addr, &shm->name);

    return NJT_ERROR;
}


void
njt_shm_free(njt_shm_t *shm)
{
    if (UnmapViewOfFile(shm->addr) == 0) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "UnmapViewOfFile(%p) of file mapping \"%V\" failed",
                      shm->addr, &shm->name);
    }

    if (CloseHandle(shm->handle) == 0) {
        njt_log_error(NJT_LOG_ALERT, shm->log, njt_errno,
                      "CloseHandle() of file mapping \"%V\" failed",
                      &shm->name);
    }
}
