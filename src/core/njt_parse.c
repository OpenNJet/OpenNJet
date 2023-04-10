
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


ssize_t
njt_parse_size(njt_str_t *line)
{
    u_char   unit;
    size_t   len;
    ssize_t  size, scale, max;

    len = line->len;

    if (len == 0) {
        return NJT_ERROR;
    }

    unit = line->data[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = NJT_MAX_SIZE_T_VALUE / 1024;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = NJT_MAX_SIZE_T_VALUE / (1024 * 1024);
        scale = 1024 * 1024;
        break;

    default:
        max = NJT_MAX_SIZE_T_VALUE;
        scale = 1;
    }

    size = njt_atosz(line->data, len);
    if (size == NJT_ERROR || size > max) {
        return NJT_ERROR;
    }

    size *= scale;

    return size;
}


off_t
njt_parse_offset(njt_str_t *line)
{
    u_char  unit;
    off_t   offset, scale, max;
    size_t  len;

    len = line->len;

    if (len == 0) {
        return NJT_ERROR;
    }

    unit = line->data[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = NJT_MAX_OFF_T_VALUE / 1024;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = NJT_MAX_OFF_T_VALUE / (1024 * 1024);
        scale = 1024 * 1024;
        break;

    case 'G':
    case 'g':
        len--;
        max = NJT_MAX_OFF_T_VALUE / (1024 * 1024 * 1024);
        scale = 1024 * 1024 * 1024;
        break;

    default:
        max = NJT_MAX_OFF_T_VALUE;
        scale = 1;
    }

    offset = njt_atoof(line->data, len);
    if (offset == NJT_ERROR || offset > max) {
        return NJT_ERROR;
    }

    offset *= scale;

    return offset;
}


njt_int_t
njt_parse_time(njt_str_t *line, njt_uint_t is_sec)
{
    u_char      *p, *last;
    njt_int_t    value, total, scale;
    njt_int_t    max, cutoff, cutlim;
    njt_uint_t   valid;
    enum {
        st_start = 0,
        st_year,
        st_month,
        st_week,
        st_day,
        st_hour,
        st_min,
        st_sec,
        st_msec,
        st_last
    } step;

    valid = 0;
    value = 0;
    total = 0;
    cutoff = NJT_MAX_INT_T_VALUE / 10;
    cutlim = NJT_MAX_INT_T_VALUE % 10;
    step = is_sec ? st_start : st_month;

    p = line->data;
    last = p + line->len;

    while (p < last) {

        if (*p >= '0' && *p <= '9') {
            if (value >= cutoff && (value > cutoff || *p - '0' > cutlim)) {
                return NJT_ERROR;
            }

            value = value * 10 + (*p++ - '0');
            valid = 1;
            continue;
        }

        switch (*p++) {

        case 'y':
            if (step > st_start) {
                return NJT_ERROR;
            }
            step = st_year;
            max = NJT_MAX_INT_T_VALUE / (60 * 60 * 24 * 365);
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step >= st_month) {
                return NJT_ERROR;
            }
            step = st_month;
            max = NJT_MAX_INT_T_VALUE / (60 * 60 * 24 * 30);
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step >= st_week) {
                return NJT_ERROR;
            }
            step = st_week;
            max = NJT_MAX_INT_T_VALUE / (60 * 60 * 24 * 7);
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step >= st_day) {
                return NJT_ERROR;
            }
            step = st_day;
            max = NJT_MAX_INT_T_VALUE / (60 * 60 * 24);
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step >= st_hour) {
                return NJT_ERROR;
            }
            step = st_hour;
            max = NJT_MAX_INT_T_VALUE / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (p < last && *p == 's') {
                if (is_sec || step >= st_msec) {
                    return NJT_ERROR;
                }
                p++;
                step = st_msec;
                max = NJT_MAX_INT_T_VALUE;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return NJT_ERROR;
            }
            step = st_min;
            max = NJT_MAX_INT_T_VALUE / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return NJT_ERROR;
            }
            step = st_sec;
            max = NJT_MAX_INT_T_VALUE;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return NJT_ERROR;
            }
            step = st_last;
            max = NJT_MAX_INT_T_VALUE;
            scale = 1;
            break;

        default:
            return NJT_ERROR;
        }

        if (step != st_msec && !is_sec) {
            scale *= 1000;
            max /= 1000;
        }

        if (value > max) {
            return NJT_ERROR;
        }

        value *= scale;

        if (total > NJT_MAX_INT_T_VALUE - value) {
            return NJT_ERROR;
        }

        total += value;

        value = 0;

        while (p < last && *p == ' ') {
            p++;
        }
    }

    if (!valid) {
        return NJT_ERROR;
    }

    if (!is_sec) {
        if (value > NJT_MAX_INT_T_VALUE / 1000) {
            return NJT_ERROR;
        }

        value *= 1000;
    }

    if (total > NJT_MAX_INT_T_VALUE - value) {
        return NJT_ERROR;
    }

    return total + value;
}
