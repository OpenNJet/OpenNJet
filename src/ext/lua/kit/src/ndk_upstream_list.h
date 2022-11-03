
#if (NDK_UPSTREAM_LIST_CMDS)

/* TODO : use the generated commands */

{
    njt_string ("upstream_list"),
    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_CONF_2MORE,
    ndk_upstream_list,
    0,
    0,
    NULL
},

#else

typedef struct {
    njt_str_t       **elts;
    njt_uint_t        nelts;
    njt_str_t         name;
} ndk_upstream_list_t;


ndk_upstream_list_t *
ndk_get_upstream_list (ndk_http_main_conf_t *mcf, u_char *data, size_t len);

#endif
