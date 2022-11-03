

int64_t
ndk_atoi64 (u_char *line, size_t n)
{
    int64_t  value;

    if (n == 0ll) {
        return NJT_ERROR;
    }

    for (value = 0ll; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NJT_ERROR;
        }

        value = value * 10ll + (*line - '0');
    }

    if (value < 0ll) {
        return NJT_ERROR;
    }

    return value;
}


njt_int_t
ndk_strcntc (njt_str_t *s, char c)
{
    njt_int_t   n;
    size_t      i;
    u_char     *p;

    i = s->len;
    p = s->data;

    for (n=0; i; i--, p++) {

        if (*p == (u_char) c)
            n++;
    }

    return  n;
}


njt_int_t
ndk_strccnt (char *s, char c)
{
    njt_int_t   n;

    n = 0;

    while (*s != '\0') {

        if (*s == 'c')
            n++;

        s++;
    }

    return  n;
}



njt_array_t *
ndk_str_array_create (njt_pool_t *pool, char **s, njt_int_t n)
{
    njt_int_t        i;
    njt_str_t       *str;
    njt_array_t     *a;

    a = njt_array_create (pool, n, sizeof (njt_str_t));
    if (a == NULL)
        return  NULL;


    for (i=0; i<n; i++, s++) {

        str = njt_array_push (a);

        str->data = (u_char *) *s;
        str->len = strlen (*s);
    }

    return  a;
}



u_char *
ndk_vcatstrf (njt_pool_t *pool, njt_str_t *dest, const char *fmt, va_list args)
{
    size_t          len, l, el;
    int             argc;
    u_char         *p, *m, *e, c, c1, *cp;

    argc = strlen (fmt);

    njt_str_t      *s;
    ndk_estr_t     *sp, *sp2, ss [argc];
    u_char        cs [argc];

    sp = sp2 = ss;
    cp = cs;

    len = 0;

    /* TODO : maybe have 'e' at the beginning? */

    /* parse format to get strings */

    while (*fmt) {

        switch (*fmt) {

        case    'S'     :

            s = va_arg (args, njt_str_t *);

            sp->data = s->data;
            sp->len = s->len;
            sp->escaped = 0;

            len += sp->len;
            break;

        case    's'     :

            sp->data = va_arg (args, u_char *);
            sp->len = (size_t) njt_strlen (sp->data);
            sp->escaped = 0;

            len += sp->len;
            break;

        case    'l'     :

            sp->data = va_arg (args, u_char *);
            sp->len = (size_t) va_arg (args, int);
            sp->escaped = 0;

            len += sp->len;
            break;

        case    'L'     :

            sp->data = va_arg (args, u_char *);
            sp->len = va_arg (args, size_t);
            sp->escaped = 0;

            len += sp->len;
            break;

        case    'e' :

            p = va_arg (args, u_char *);

            sp->data = p;

            l = 0;
            el = 0;
            c = *p;

            while (c != '\0') {

                if (c == '\\') {
                    l += 2;
                    p += 2;
                } else {
                    l++;
                    p++;
                }

                el++; 
                c = *p;
            }

            sp->len = l;
            sp->escaped = 1;

            len += el;
            break;

        case    'E' :

            s = va_arg (args, njt_str_t *);

            sp->data = s->data;
            sp->len = s->len;

            p = sp->data;

            el = 0;
            e = p + sp->len;

            while (p < e) {

                c = *p;

                if (c == '\\') {
                    p += 2;
                } else {
                    p++;
                }

                el++;                    
            }

            sp->escaped = 1;

            len += el;
            break;

        case    'n' :

            sp->data = va_arg (args, u_char *);
            sp->len = (size_t) va_arg (args, int);

            p = sp->data;

            el = 0;
            e = p + sp->len;

            while (p < e) {

                c = *p;

                if (c == '\\') {
                    p += 2;
                } else {
                    p++;
                }

                el++;                    
            }

            sp->escaped = 1;

            len += el;
            break;

        case    'c' :

            *cp = (u_char) va_arg (args, int);

            sp->data = cp;
            sp->len = (size_t) 1;

            len++;
            cp++;

            break; 

        default         :

            ndk_log_alert (pool->log, 0, "catstrf () : format [%s] incorrect", fmt);

            return  NULL;

        }

        sp++;
        fmt++;
    }



    /* create space for string (assumes no NULL's in strings) */

    ndk_palloc_rn (p, pool, len + 1);

    dest->data = p;
    dest->len = len;

    /* copy other strings */

    if (len) {

        while (sp2 < sp) {

            if (sp2->escaped) {

                m = sp2->data;
                e = m + sp2->len;

                while (m < e) {

                    c = *m;

                    if (c == '\\') {

                        if (m == e - 1) {
                            *p = '\\';
                            p++;
                            break;
                        }

                        c1 = m[1];

                        switch (c1) {

                        case    'n' :
                            *p = '\n';
                            break;

                        case    't' :
                            *p = '\t';
                            break;

                        case    '0' :
                            *p = '\0';
                            break;

                        case    '\\' :
                            *p = '\\';
                            break;

                        case    's' :
                            *p = ' ';
                            break;

                        case    'b' :
                            *p = '\b';
                            break;

                        case    'r' :
                            *p = '\r';
                            break;

                        default :

                            *p = c1;
                            break;
                        }

                        m += 2;

                    } else {

                        *p = c;
                        m++;
                    }

                    p++;
                }

            } else {

                p = njt_cpymem (p, sp2->data, sp2->len);
            }

            sp2++;
        }
    }

    *p = '\0';

    return  dest->data;
}


u_char *
ndk_catstrf (njt_pool_t *pool, njt_str_t *dest, const char *fmt, ...)
{
    u_char       *p;
    va_list         args;

    va_start (args, fmt);
    p = ndk_vcatstrf (pool, dest, fmt, args);
    va_end (args);

    return  p;
}


njt_int_t
ndk_cmpstr (njt_str_t *s1, njt_str_t *s2)
{
    njt_int_t   rv;
    size_t      len1, len2;

    len1 = s1->len;
    len2 = s2->len;

    if (len1 == len2) {
        return  njt_strncmp (s1->data, s2->data, len1);
    }

    if (len1 > len2) {

        rv = njt_strncmp (s1->data, s2->data, len2);
        if (rv == 0)
            return  1;

        return  rv;
    }

    rv = njt_strncmp (s1->data, s2->data, len1);
    if (rv == 0)
        return  -1;

    return  rv;
}


u_char *
ndk_dupstr (njt_pool_t *pool, njt_str_t *dest, njt_str_t *src)
{
    u_char       *d;
    size_t       n;

    n = src->len;

    ndk_palloc_rn (d, pool, n + 1);
    ndk_strncpy (d, src->data, n);

    dest->data = d;
    dest->len = n;

    return  d;
}

/*
njt_keyval_t *
ndk_url_args_to_keyval_list (njt_pool_t *pool, njt_str_t *str)
{
    njt_keyval_t    *kv;
    njt_st
    
}
*/
