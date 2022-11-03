

typedef struct {
    njt_array_t                    *a;
    njt_uint_t                      prefix;
} ndk_http_complex_path_t;

typedef struct {
    njt_http_complex_value_t        val;
    njt_flag_t                      dynamic;
} ndk_http_complex_path_elt_t;

typedef struct {
    njt_str_t                       val;
    njt_flag_t                      dynamic;
} ndk_http_complex_path_value_t;

typedef struct {
    ndk_http_complex_path_value_t  *elts;
    njt_uint_t                      nelts;
} ndk_http_complex_path_values_t;


extern  ndk_http_complex_path_value_t     ndk_empty_http_complex_path_value;


njt_array_t *   ndk_http_complex_path_create_compile     (njt_conf_t *cf, njt_str_t *path, njt_uint_t prefix);
njt_int_t       ndk_http_complex_path_value_compile      (njt_conf_t *cf, njt_http_complex_value_t *cv, 
                                                                    njt_str_t *value, njt_uint_t prefix);
char *          ndk_conf_set_http_complex_path_slot      (njt_conf_t *cf, njt_command_t *cmd, void *conf);
