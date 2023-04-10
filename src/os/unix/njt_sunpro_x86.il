/
/ Copyright (C) Igor Sysoev
/ Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
/

/ njt_atomic_uint_t njt_atomic_cmp_set(njt_atomic_t *lock,
/     njt_atomic_uint_t old, njt_atomic_uint_t set);
/
/ the arguments are passed on stack (%esp), 4(%esp), 8(%esp)

        .inline njt_atomic_cmp_set,0
        movl      (%esp), %ecx
        movl      4(%esp), %eax
        movl      8(%esp), %edx
        lock
        cmpxchgl  %edx, (%ecx)
        setz      %al
        movzbl    %al, %eax
        .end


/ njt_atomic_int_t njt_atomic_fetch_add(njt_atomic_t *value,
/     njt_atomic_int_t add);
/
/ the arguments are passed on stack (%esp), 4(%esp)

        .inline njt_atomic_fetch_add,0
        movl      (%esp), %ecx
        movl      4(%esp), %eax
        lock
        xaddl     %eax, (%ecx)
        .end


/ njt_cpu_pause()
/
/ the "rep; nop" is used instead of "pause" to avoid the "[ PAUSE ]" hardware
/ capability added by linker because Solaris/i386 does not know about it:
/
/ ld.so.1: njet: fatal: hardware capability unsupported: 0x2000  [ PAUSE ]

        .inline njt_cpu_pause,0
        rep; nop
        .end
