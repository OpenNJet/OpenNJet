
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#ifndef _NJT_BPF_H_INCLUDED_
#define _NJT_BPF_H_INCLUDED_


#include <njt_config.h>
#include <njt_core.h>

#include <linux/bpf.h>


typedef struct {
    char                *name;
    int                  offset;
} njt_bpf_reloc_t;

typedef struct {
    char                *license;
    enum bpf_prog_type   type;
    struct bpf_insn     *ins;
    size_t               nins;
    njt_bpf_reloc_t     *relocs;
    size_t               nrelocs;
} njt_bpf_program_t;


void njt_bpf_program_link(njt_bpf_program_t *program, const char *symbol,
    int fd);
int njt_bpf_load_program(njt_log_t *log, njt_bpf_program_t *program);

int njt_bpf_map_create(njt_log_t *log, enum bpf_map_type type, int key_size,
    int value_size, int max_entries, uint32_t map_flags);
int njt_bpf_map_update(int fd, const void *key, const void *value,
    uint64_t flags);
int njt_bpf_map_delete(int fd, const void *key);
int njt_bpf_map_lookup(int fd, const void *key, void *value);

#endif /* _NJT_BPF_H_INCLUDED_ */
