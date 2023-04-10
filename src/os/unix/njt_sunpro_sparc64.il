/
/ Copyright (C) Igor Sysoev
/ Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
/


/  "casa   [%o2] 0x80, %o1, %o0"  and
/  "casxa  [%o2] 0x80, %o1, %o0"  do the following:
/
/       if ([%o2] == %o1) {
/           swap(%o0, [%o2]);
/       } else {
/           %o0 = [%o2];
/       }


/ njt_atomic_uint_t njt_casa(njt_atomic_uint_t set, njt_atomic_uint_t old,
/      njt_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline njt_casa,0
        casa    [%o2] 0x80, %o1, %o0
        .end


/ njt_atomic_uint_t njt_casxa(njt_atomic_uint_t set, njt_atomic_uint_t old,
/      njt_atomic_t *lock);
/
/ the arguments are passed in the %o0, %o1, %o2
/ the result is returned in the %o0

        .inline njt_casxa,0
        casxa   [%o2] 0x80, %o1, %o0
        .end
