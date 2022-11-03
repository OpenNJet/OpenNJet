
/*
 * 2010 (C) Marcus Clyne
 */
 

#include    <ndk.h>


static njt_int_t    njt_http_set_var_concat2    (njt_http_request_t *r, njt_str_t *val, njt_http_variable_value_t *v);
static char *       njt_http_set_prepend_hello   (njt_conf_t *cf, njt_command_t *cmd, void *conf);


static  ndk_set_var_t      njt_http_var_set_concat2 = {
    NDK_SET_VAR_MULTI_VALUE,
    njt_http_set_var_concat2,
    2,
    NULL
};


static njt_command_t  njt_http_set_var_examples_commands[] = {
    {
        njt_string ("set_concat2"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE3,
        ndk_set_var_multi_value,
        0,
        0,
        &njt_http_var_set_concat2
    },
    {
        njt_string ("set_prepend_hello"),
        NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_SIF_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF|NJT_CONF_TAKE1,
        njt_http_set_prepend_hello,
        0,
        0,
        NULL
    },
    njt_null_command
};


njt_http_module_t     njt_http_set_var_examples_module_ctx = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
njt_module_t          njt_http_set_var_examples_module = {

    NJT_MODULE_V1,
    &njt_http_set_var_examples_module_ctx,  // module context
    njt_http_set_var_examples_commands,     // module directives
    NJT_HTTP_MODULE,                        // module type
    NULL,                                   // init master
    NULL,                                   // init module
    NULL,                                   // init process
    NULL,                                   // init thread
    NULL,                                   // exit thread
    NULL,                                   // exit process
    NULL,                                   // exit master
    NJT_MODULE_V1_PADDING
};


/*
    This function is called by both examples, takes two variable values and concatenates them
    to give a third string.
*/

static njt_int_t
njt_http_set_var_concat2 (njt_http_request_t *r, njt_str_t *val, njt_http_variable_value_t *v)
{
    size_t                      len;
    njt_http_variable_value_t   *v2;
    u_char                      *p;

    v2 = v + 1;

    len = v->len + v2->len;

	/*
	 * NDK provided abbreviation for the following code:
	 *
	 * p = njt_palloc (r->pool, len);
	 * if (p == NULL)
	 * 		return  NJT_ERROR;
	 *
	 * */
	ndk_palloc_re(p, r->pool, len);

    val->data = p;
    val->len = len;

    njt_memzero (p, len);

    p = njt_cpymem (p, v->data, v->len);
    njt_memcpy (p, v2->data, v2->len);

    return  NJT_OK;
}



/*  
    This function demonstrates using the 'core' function in a function that appends the word
    'hello_' to the beginning of a variable.

    set                 $var      world;
    set_prepend_hello    $var      $var;

    If the arguments used in the variable value filter do not all come directly from the conf
    file, or are not given in the order

    direcive    $var_name   val1 "val2 string $var" ...

    then the _core functions should be used inside the function that is called when the directive
    is read.
*/

static char *
njt_http_set_prepend_hello (njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t               s[2], *var_name;
    ndk_set_var_t      filter;

    var_name = cf->args->elts;
    var_name++;

    s[0].data = (u_char*) "hello_";
    s[0].len = 6;

    s[1] = *(var_name + 1);

    filter.type = NDK_SET_VAR_MULTI_VALUE;
    filter.func = njt_http_set_var_concat2;
    filter.size = 2;

    return  ndk_set_var_multi_value_core (cf, var_name, (njt_str_t *) s, &filter);
}

