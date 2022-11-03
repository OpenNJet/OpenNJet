

/* TODO : should remove this when not needed */



/* used for plugging into the rewrite module (taken from the rewrite module) */

typedef struct {
    njt_array_t  *codes;        /* uintptr_t */
    njt_uint_t    stack_size;
    njt_flag_t    log;
    njt_flag_t    uninitialized_variable_warn;
} ndk_http_rewrite_loc_conf_t;


extern  njt_module_t    njt_http_rewrite_module;
extern  uintptr_t       ndk_http_script_exit_code;

char *      ndk_http_rewrite_value      (njt_conf_t *cf, ndk_http_rewrite_loc_conf_t *lcf,
                                            njt_str_t *value);
njt_int_t   ndk_http_rewrite_var        (njt_http_request_t *r, 
                                            njt_http_variable_value_t *v, uintptr_t data);

#define     ndk_http_script_exit  (u_char *) &ndk_http_script_exit_code

