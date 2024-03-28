

#if 1
/* TODO : set ndk_hex_dump for older versions of NJet */
#define     ndk_hex_dump                    njt_hex_dump
#endif

typedef struct {
    size_t          len;
    u_char         *data;
    njt_flag_t      escaped;
} ndk_estr_t;

int64_t         ndk_atoi64                  (u_char *line, size_t n);

njt_int_t       ndk_strcntc                 (njt_str_t *s, char c);
njt_int_t       ndk_strccnt                 (char *s, char c);
njt_array_t *   ndk_str_array_create        (njt_pool_t *pool, char **s, njt_int_t n);
u_char *        ndk_catstrf                 (njt_pool_t *pool, njt_str_t *dest, const char *fmt, ...);
njt_int_t       ndk_cmpstr                  (njt_str_t *s1, njt_str_t *s2);
u_char *        ndk_dupstr                  (njt_pool_t *pool, njt_str_t *dest, njt_str_t *src);

static njt_inline void
ndk_strtoupper (u_char *p, size_t len)
{
    u_char *e = p + len;
    for ( ; p<e; p++) {
        *p = njt_toupper(*p);
    }
}


static njt_inline u_char *
ndk_strncpy (u_char *d, u_char *s, size_t n)
{
    return  (u_char *) strncpy ((char *) d, (char *) s, n);
}
