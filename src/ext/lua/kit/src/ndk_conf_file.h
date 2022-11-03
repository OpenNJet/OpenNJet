

/* conf set functions */

char *  ndk_conf_set_true_slot              (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_false_slot             (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_full_path_slot         (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_ptr_slot               (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_null_slot              (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_str_array_multi_slot   (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_keyval1_slot           (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_num_flag               (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_num64_slot             (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_sec_flag_slot          (njt_conf_t *cf, njt_command_t *cmd, void *conf);

njt_http_conf_ctx_t *   ndk_conf_create_http_location           (njt_conf_t *cf);
njt_http_conf_ctx_t *   njt_conf_create_http_named_location     (njt_conf_t *cf, njt_str_t *name);

njt_int_t               ndk_replace_command     (njt_command_t *new_cmd, njt_uint_t module_type);


/* values for conf_set_xxx_flag */

#define     NDK_CONF_SET_TRUE       -2
#define     NDK_CONF_SET_FALSE      -3


/* wrappers for utility macros */

#define     ndk_conf_set_bitmask_slot       njt_conf_set_bitmask_slot
#define     ndk_conf_set_bufs_slot          njt_conf_set_bufs_slot
#define     ndk_conf_set_enum_slot          njt_conf_set_enum_slot
#define     ndk_conf_set_flag_slot          njt_conf_set_flag_slot
#define     ndk_conf_set_keyval_slot        njt_conf_set_keyval_slot
#define     ndk_conf_set_msec_slot          njt_conf_set_msec_slot
#define     ndk_conf_set_num_slot           njt_conf_set_num_slot
#define     ndk_conf_set_off_slot           njt_conf_set_off_slot
#define     ndk_conf_set_sec_slot           njt_conf_set_sec_slot
#define     ndk_conf_set_size_slot          njt_conf_set_size_slot
#define     ndk_conf_set_str_slot           njt_conf_set_str_slot




