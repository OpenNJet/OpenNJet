
/* TODO : finish this */

#define     NDK_HTTP_MAIN_CONF              NJT_HTTP_MAIN_CONF
#define     NDK_HTTP_SRV_CONF               NJT_HTTP_SRV_CONF
#define     NDK_HTTP_SIF_CONF               NJT_HTTP_SIF_CONF
#define     NDK_HTTP_LOC_CONF               NJT_HTTP_LOC_CONF
#define     NDK_HTTP_LIF_CONF               NJT_HTTP_LIF_CONF
#define     NDK_HTTP_UPS_CONF               NJT_HTTP_UPS_CONF
#define     NDK_MAIN_CONF                   NJT_MAIN_CONF
#define     NDK_ANY_CONF                    NJT_ANY_CONF


/* compound locations */

#define     NDK_HTTP_MAIN_SRV_CONF                  NDK_HTTP_MAIN_CONF|NDK_HTTP_SRV_CONF
#define     NDK_HTTP_MAIN_SIF_CONF                  NDK_HTTP_MAIN_CONF|NDK_HTTP_SRV_SIF_CONF
#define     NDK_HTTP_MAIN_LOC_CONF                  NDK_HTTP_MAIN_CONF|NDK_HTTP_LOC_CONF
#define     NDK_HTTP_MAIN_LIF_CONF                  NDK_HTTP_MAIN_CONF|NDK_HTTP_LOC_LIF_CONF

#define     NDK_HTTP_SRV_SIF_CONF                   NDK_HTTP_SRV_CONF|NDK_HTTP_SIF_CONF
#define     NDK_HTTP_SRV_LOC_CONF                   NDK_HTTP_SRV_CONF|NDK_HTTP_LOC_CONF
#define     NDK_HTTP_SRV_LOC_LIF_CONF               NDK_HTTP_SRV_CONF|NDK_HTTP_LOC_LIF_CONF
#define     NDK_HTTP_SRV_SIF_LOC_CONF               NDK_HTTP_SRV_SIF_CONF|NDK_HTTP_LOC_CONF
#define     NDK_HTTP_SRV_SIF_LOC_LIF_CONF           NDK_HTTP_SRV_SIF_CONF|NDK_HTTP_LOC_LIF_CONF

#define     NDK_HTTP_LOC_LIF_CONF                   NDK_HTTP_LOC_CONF|NDK_HTTP_LIF_CONF

#define     NDK_HTTP_MAIN_SRV_LOC_CONF              NDK_HTTP_MAIN_CONF|NDK_HTTP_SRV_LOC_CONF
#define     NDK_HTTP_MAIN_SRV_LIF_CONF              NDK_HTTP_MAIN_CONF|NDK_HTTP_SRV_LIF_CONF
#define     NDK_HTTP_MAIN_SIF_LOC_CONF              NDK_HTTP_MAIN_CONF|NDK_HTTP_SIF_LOC_CONF
#define     NDK_HTTP_MAIN_SRV_SIF_LOC_LIF_CONF      NDK_HTTP_SRV_SIF_LOC_LIF_CONF|NDK_MAIN_CONF
#define     NDK_HTTP_CONF                           NDK_HTTP_MAIN_SRV_SIF_LOC_LIF_CONF
#define     NDK_HTTP_ANY_CONF                       NDK_HTTP_CONF|NDK_HTTP_UPS_CONF


/* property offsets     NOTE : njt_module_main_conf_t etc should be defined in the module's .c file before the commands */

#define     NDK_HTTP_MAIN_CONF_PROP(p)      NJT_HTTP_MAIN_CONF_OFFSET, offsetof (ndk_module_main_conf_t, p)
#define     NDK_HTTP_SRV_CONF_PROP(p)       NJT_HTTP_SRV_CONF_OFFSET, offsetof (ndk_module_srv_conf_t, p)
#define     NDK_HTTP_LOC_CONF_PROP(p)       NJT_HTTP_LOC_CONF_OFFSET, offsetof (ndk_module_loc_conf_t, p)


