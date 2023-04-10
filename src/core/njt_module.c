
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>


#define NJT_MAX_DYNAMIC_MODULES  128


static njt_uint_t njt_module_index(njt_cycle_t *cycle);
static njt_uint_t njt_module_ctx_index(njt_cycle_t *cycle, njt_uint_t type,
    njt_uint_t index);


njt_uint_t         njt_max_module;
static njt_uint_t  njt_modules_n;


njt_int_t
njt_preinit_modules(void)
{
    njt_uint_t  i;

    for (i = 0; njt_modules[i]; i++) {
        njt_modules[i]->index = i;
        njt_modules[i]->name = njt_module_names[i];
    }

    njt_modules_n = i;
    njt_max_module = njt_modules_n + NJT_MAX_DYNAMIC_MODULES;

    return NJT_OK;
}


njt_int_t
njt_cycle_modules(njt_cycle_t *cycle)
{
    /*
     * create a list of modules to be used for this cycle,
     * copy static modules to it
     */

    cycle->modules = njt_pcalloc(cycle->pool, (njt_max_module + 1)
                                              * sizeof(njt_module_t *));
    if (cycle->modules == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(cycle->modules, njt_modules,
               njt_modules_n * sizeof(njt_module_t *));

    cycle->modules_n = njt_modules_n;

    return NJT_OK;
}


njt_int_t
njt_init_modules(njt_cycle_t *cycle)
{
    njt_uint_t  i;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_module) {
            if (cycle->modules[i]->init_module(cycle) != NJT_OK) {
                return NJT_ERROR;
            }
        }
    }

    return NJT_OK;
}


njt_int_t
njt_count_modules(njt_cycle_t *cycle, njt_uint_t type)
{
    njt_uint_t     i, next, max;
    njt_module_t  *module;

    next = 0;
    max = 0;

    /* count appropriate modules, set up their indices */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->type != type) {
            continue;
        }

        if (module->ctx_index != NJT_MODULE_UNSET_INDEX) {

            /* if ctx_index was assigned, preserve it */

            if (module->ctx_index > max) {
                max = module->ctx_index;
            }

            if (module->ctx_index == next) {
                next++;
            }

            continue;
        }

        /* search for some free index */

        module->ctx_index = njt_module_ctx_index(cycle, type, next);

        if (module->ctx_index > max) {
            max = module->ctx_index;
        }

        next = module->ctx_index + 1;
    }

    /*
     * make sure the number returned is big enough for previous
     * cycle as well, else there will be problems if the number
     * will be stored in a global variable (as it's used to be)
     * and we'll have to roll back to the previous cycle
     */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->type != type) {
                continue;
            }

            if (module->ctx_index > max) {
                max = module->ctx_index;
            }
        }
    }

    /* prevent loading of additional modules */

    cycle->modules_used = 1;

    return max + 1;
}


njt_int_t
njt_add_module(njt_conf_t *cf, njt_str_t *file, njt_module_t *module,
    char **order)
{
    void               *rv;
    njt_uint_t          i, m, before;
    njt_core_module_t  *core_module;

    if (cf->cycle->modules_n >= njt_max_module) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "too many modules loaded");
        return NJT_ERROR;
    }

    if (module->version != njet_version) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "module \"%V\" version %ui instead of %ui",
                           file, module->version, (njt_uint_t) njet_version);
        return NJT_ERROR;
    }

    if (njt_strcmp(module->signature, NJT_MODULE_SIGNATURE) != 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "module \"%V\" is not binary compatible",
                           file);
        return NJT_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (njt_strcmp(cf->cycle->modules[m]->name, module->name) == 0) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "module \"%s\" is already loaded",
                               module->name);
            return NJT_ERROR;
        }
    }

    /*
     * if the module wasn't previously loaded, assign an index
     */

    if (module->index == NJT_MODULE_UNSET_INDEX) {
        module->index = njt_module_index(cf->cycle);

        if (module->index >= njt_max_module) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "too many modules loaded");
            return NJT_ERROR;
        }
    }

    /*
     * put the module into the cycle->modules array
     */

    before = cf->cycle->modules_n;

    if (order) {
        for (i = 0; order[i]; i++) {
            if (njt_strcmp(order[i], module->name) == 0) {
                i++;
                break;
            }
        }

        for ( /* void */ ; order[i]; i++) {

#if 0
            njt_log_debug2(NJT_LOG_DEBUG_CORE, cf->log, 0,
                           "module: %s before %s",
                           module->name, order[i]);
#endif

            for (m = 0; m < before; m++) {
                if (njt_strcmp(cf->cycle->modules[m]->name, order[i]) == 0) {

                    njt_log_debug3(NJT_LOG_DEBUG_CORE, cf->log, 0,
                                   "module: %s before %s:%i",
                                   module->name, order[i], m);

                    before = m;
                    break;
                }
            }
        }
    }

    /* put the module before modules[before] */

    if (before != cf->cycle->modules_n) {
        njt_memmove(&cf->cycle->modules[before + 1],
                    &cf->cycle->modules[before],
                    (cf->cycle->modules_n - before) * sizeof(njt_module_t *));
    }

    cf->cycle->modules[before] = module;
    cf->cycle->modules_n++;

    if (module->type == NJT_CORE_MODULE) {

        /*
         * we are smart enough to initialize core modules;
         * other modules are expected to be loaded before
         * initialization - e.g., http modules must be loaded
         * before http{} block
         */

        core_module = module->ctx;

        if (core_module->create_conf) {
            rv = core_module->create_conf(cf->cycle);
            if (rv == NULL) {
                return NJT_ERROR;
            }

            cf->cycle->conf_ctx[module->index] = rv;
        }
    }

    return NJT_OK;
}


static njt_uint_t
njt_module_index(njt_cycle_t *cycle)
{
    njt_uint_t     i, index;
    njt_module_t  *module;

    index = 0;

again:

    /* find an unused index */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->index == index) {
            index++;
            goto again;
        }
    }

    /* check previous cycle */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->index == index) {
                index++;
                goto again;
            }
        }
    }

    return index;
}


static njt_uint_t
njt_module_ctx_index(njt_cycle_t *cycle, njt_uint_t type, njt_uint_t index)
{
    njt_uint_t     i;
    njt_module_t  *module;

again:

    /* find an unused ctx_index */

    for (i = 0; cycle->modules[i]; i++) {
        module = cycle->modules[i];

        if (module->type != type) {
            continue;
        }

        if (module->ctx_index == index) {
            index++;
            goto again;
        }
    }

    /* check previous cycle */

    if (cycle->old_cycle && cycle->old_cycle->modules) {

        for (i = 0; cycle->old_cycle->modules[i]; i++) {
            module = cycle->old_cycle->modules[i];

            if (module->type != type) {
                continue;
            }

            if (module->ctx_index == index) {
                index++;
                goto again;
            }
        }
    }

    return index;
}
