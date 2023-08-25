
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>

#define NJT_BPF_LOGBUF_SIZE  (16 * 1024)


static njt_inline int
njt_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}


void
njt_bpf_program_link(njt_bpf_program_t *program, const char *symbol, int fd)
{
    njt_uint_t        i;
    njt_bpf_reloc_t  *rl;

    rl = program->relocs;

    for (i = 0; i < program->nrelocs; i++) {
        if (njt_strcmp(rl[i].name, symbol) == 0) {
            program->ins[rl[i].offset].src_reg = 1;
            program->ins[rl[i].offset].imm = fd;
        }
    }
}


int
njt_bpf_load_program(njt_log_t *log, njt_bpf_program_t *program)
{
    int             fd;
    union bpf_attr  attr;
#if (NJT_DEBUG)
    char            buf[NJT_BPF_LOGBUF_SIZE];
#endif

    njt_memzero(&attr, sizeof(union bpf_attr));

    attr.license = (uintptr_t) program->license;
    attr.prog_type = program->type;
    attr.insns = (uintptr_t) program->ins;
    attr.insn_cnt = program->nins;

#if (NJT_DEBUG)
    /* for verifier errors */
    attr.log_buf = (uintptr_t) buf;
    attr.log_size = NJT_BPF_LOGBUF_SIZE;
    attr.log_level = 1;
#endif

    fd = njt_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "failed to load BPF program");

        njt_log_debug1(NJT_LOG_DEBUG_CORE, log, 0,
                       "bpf verifier: %s", buf);

        return -1;
    }

    return fd;
}


int
njt_bpf_map_create(njt_log_t *log, enum bpf_map_type type, int key_size,
    int value_size, int max_entries, uint32_t map_flags)
{
    int             fd;
    union bpf_attr  attr;

    njt_memzero(&attr, sizeof(union bpf_attr));

    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;

    fd = njt_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        njt_log_error(NJT_LOG_ALERT, log, njt_errno,
                      "failed to create BPF map");
        return NJT_ERROR;
    }

    return fd;
}


int
njt_bpf_map_update(int fd, const void *key, const void *value, uint64_t flags)
{
    union bpf_attr attr;

    njt_memzero(&attr, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;
    attr.flags = flags;

    return njt_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}


int
njt_bpf_map_delete(int fd, const void *key)
{
    union bpf_attr attr;

    njt_memzero(&attr, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;

    return njt_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}


int
njt_bpf_map_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr;

    njt_memzero(&attr, sizeof(union bpf_attr));

    attr.map_fd = fd;
    attr.key = (uintptr_t) key;
    attr.value = (uintptr_t) value;

    return njt_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}
