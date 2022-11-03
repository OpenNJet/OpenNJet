

typedef struct {
    njt_str_t                   key;
    njt_http_complex_value_t    value;
} ndk_http_complex_keyval_t;



/* create/compile functions */

njt_int_t      ndk_http_complex_value_compile        (njt_conf_t *cf, njt_http_complex_value_t *cv, njt_str_t *value);
njt_array_t *  ndk_http_complex_value_array_create   (njt_conf_t *cf, char **s, njt_int_t n);
njt_int_t      ndk_http_complex_value_array_compile  (njt_conf_t *cf, njt_array_t *a);


/* conf set slot functions */

char *  ndk_conf_set_http_complex_keyval_slot        (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_http_complex_value_slot         (njt_conf_t *cf, njt_command_t *cmd, void *conf);
char *  ndk_conf_set_http_complex_value_array_slot   (njt_conf_t *cf, njt_command_t *cmd, void *conf);
