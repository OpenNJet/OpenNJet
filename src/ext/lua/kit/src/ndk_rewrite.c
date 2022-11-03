

/* these have been taken from the rewrite module and http_script file
 * because those functions are defined as being static - a patch will
 * be provided later to un-define them as being static
 */


uintptr_t ndk_http_script_exit_code = (uintptr_t) NULL;


char *
ndk_http_rewrite_value (njt_conf_t *cf, ndk_http_rewrite_loc_conf_t *lcf,
    njt_str_t *value)
{
    njt_int_t                              n;
    njt_http_script_compile_t              sc;
    njt_http_script_value_code_t          *val;
    njt_http_script_complex_value_code_t  *complex;

    n = njt_http_script_variables_count(value);

    if (n == 0) {
        val = njt_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(njt_http_script_value_code_t));
        if (val == NULL) {
            return NJT_CONF_ERROR;
        }

        n = njt_atoi(value->data, value->len);

        if (n == NJT_ERROR) {
            n = 0;
        }

        val->code = njt_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return NJT_CONF_OK;
    }

    complex = njt_http_script_start_code(cf->pool, &lcf->codes,
                                 sizeof(njt_http_script_complex_value_code_t));
    if (complex == NULL) {
        return NJT_CONF_ERROR;
    }

    complex->code = njt_http_script_complex_value_code;
    complex->lengths = NULL;

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &lcf->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (njt_http_script_compile(&sc) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}


njt_int_t
ndk_http_rewrite_var (njt_http_request_t *r, njt_http_variable_value_t *v,
    uintptr_t data)
{
    njt_http_variable_t          *var;
    njt_http_core_main_conf_t    *cmcf;
    ndk_http_rewrite_loc_conf_t  *rlcf;

    rlcf = njt_http_get_module_loc_conf(r, njt_http_rewrite_module);

    if (rlcf->uninitialized_variable_warn == 0) {
        *v = njt_http_variable_null_value;
        return NJT_OK;
    }

    cmcf = njt_http_get_module_main_conf(r, njt_http_core_module);

    var = cmcf->variables.elts;

    /*
     * the njt_http_rewrite_module sets variables directly in r->variables,
     * and they should be handled by njt_http_get_indexed_variable(),
     * so the handler is called only if the variable is not initialized
     */

    njt_log_error(NJT_LOG_WARN, r->connection->log, 0,
                  "using uninitialized \"%V\" variable", &var[data].name);

    *v = njt_http_variable_null_value;

    return  NJT_OK;
}


