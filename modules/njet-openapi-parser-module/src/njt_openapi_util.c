
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
// #include <njt_http.h>

#include <jansson.h>
#include <sqlite3.h>

// njt_module_t njt_openapi_parser_module = {
//   NJT_MODULE_V1,
//   NULL,                              /* module context */
//   NULL,                              /* module directives */
//   NJT_HTTP_MODULE,                   /* module type */
//   NULL,                              /* init master */
//   NULL,                              /* init module */
//   NULL,                              /* init process */
//   NULL,                              /* init thread */
//   NULL,                              /* exit thread */
//   NULL,                              /* exit process */
//   NULL,                              /* exit master */
//   NJT_MODULE_V1_PADDING
// };

#define NJT_OPENAPI_SECURITY_SCHEME_UNSET       0
#define NJT_OPENAPI_SECURITY_SCHEME_APIKEY      1
#define NJT_OPENAPI_SECURITY_SCHEME_HTTP        2
#define NJT_OPENAPI_SECURITY_SCHEME_OAUTH2      3
#define NJT_OPENAPI_SECURITY_SCHEME_OPENID      4

typedef struct {
    njt_int_t              type;
    // OTHER field
} njt_openapi_security_scheme_t;

typedef struct {
    const char *title;
    const char *path;
    const char *method;
    const char *desc;
    njt_int_t   group_id;
} njt_openapi_api_item_t;


njt_int_t
njt_openapi_insert_db(njt_str_t *db_name, njt_array_t *sqls) {
    sqlite3    *db;
    int         rc;
    njt_uint_t   i;
    njt_str_t   sql;

    rc = sqlite3_open((char *)db_name->data, &db);
    if (rc != SQLITE_OK) {
        njt_log_error(NJT_LOG_CRIT, njt_cycle->log, 0, "cannot open database, %s", db_name->data);
        sqlite3_close(db);
        return NJT_ERROR;
    }

    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    for (i = 0; i < sqls->nelts; i++) {
        sql = ((njt_str_t *)sqls->elts)[i];
        rc = sqlite3_exec(db, (const char *)sql.data, NULL, NULL, NULL);
        // check rc ??
        if (rc != SQLITE_OK) {
            njt_log_error(NJT_LOG_CRIT, njt_cycle->log, 0, "exec sql error, sql: %s, msg: %s \n", sql.data, sqlite3_errmsg(db));
        }
    }    

    sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);

    sqlite3_close(db);

    return NJT_OK;
    

}



void
njt_openapi_parse_security_scheme(json_t *root, njt_openapi_security_scheme_t *sec_scheme) {
    json_t      *comp, *secschemes, *secscheme, *jtype, *jscheme;
    json_t      *security, *security_requirement, *items;
    const char  *key = NULL;
    const char  *type = NULL;
    const char  *scheme = NULL;
    njt_log_t   *log;
    size_t       index;

    log = njt_cycle->log;

    sec_scheme->type = NJT_OPENAPI_SECURITY_SCHEME_UNSET;

    security = json_object_get(root, "security");
    if (json_array_size(security) == 0) {
        return;
    }

    comp = json_object_get(root, "components");
    if (comp == NULL) {
        return;
    }

    secschemes = json_object_get(comp, "securitySchemes");
    if (secschemes == NULL) {
        return;
    }

    json_array_foreach(security, index, security_requirement) {
        json_object_foreach(security_requirement, key, items) {
            secscheme = json_object_get(secschemes, key);
            if (secscheme != NULL) {
                jtype = json_object_get(secscheme, "type");
                if (jtype != NULL) {
                    type = json_string_value(jtype);
                    if (strlen(type) == 4 && njt_strncmp(type, "http", 4) == 0) {
                        jscheme = json_object_get(secscheme, "scheme");

                        scheme = json_string_value(jscheme);
                        if (strlen(scheme) == 6 && njt_strncmp(scheme, "bearer", 6) == 0) {
                            sec_scheme->type = NJT_OPENAPI_SECURITY_SCHEME_HTTP;
                        } else {
                            njt_log_error(NJT_LOG_ALERT, log, 0, "only support bearer scheme in http security scheme now.");
                        }
                    } else {
                        njt_log_error(NJT_LOG_ALERT, log, 0, "only support http security scheme now.");
                    }
                    
                } else {
                    njt_log_error(NJT_LOG_ALERT, log, 0, "type must exist in security scheme object.");
                }
            } else {
                njt_log_error(NJT_LOG_ALERT, log, 0, "security requirement must exist in security scheme object.");
            }

        }
    }

}


void
njt_openapi_parse_security_scheme_local(json_t *root, 
    const char *sec_key, njt_openapi_security_scheme_t *sec_scheme)
{
    json_t      *comp, *secschemes, *secscheme, *jtype, *jscheme;
    const char  *type = NULL;
    const char  *scheme = NULL;
    njt_log_t   *log;

    log = njt_cycle->log;

    sec_scheme->type = NJT_OPENAPI_SECURITY_SCHEME_UNSET;

    comp = json_object_get(root, "components");
    if (comp == NULL) {
        return;
    }

    secschemes = json_object_get(comp, "securitySchemes");
    if (secschemes == NULL) {
        return;
    }

    secscheme = json_object_get(secschemes, sec_key);
    if (secscheme != NULL) {
        jtype = json_object_get(secscheme, "type");
        if (jtype != NULL) {
            type = json_string_value(jtype);
            if (strlen(type) == 4 && njt_strncmp(type, "http", 4) == 0) {
                jscheme = json_object_get(secscheme, "scheme");

                scheme = json_string_value(jscheme);
                if (strlen(scheme) == 6 && njt_strncmp(scheme, "bearer", 6) == 0) {
                    sec_scheme->type = NJT_OPENAPI_SECURITY_SCHEME_HTTP;
                } else {
                    njt_log_error(NJT_LOG_ALERT, log, 0, "only support bearer scheme in http security scheme now.");
                }
            } else {
                njt_log_error(NJT_LOG_ALERT, log, 0, "only support http security scheme now.");
            }
            
        } else {
            njt_log_error(NJT_LOG_ALERT, log, 0, "type must exist in security scheme object.");
        }
    } else {
        njt_log_error(NJT_LOG_ALERT, log, 0, "security requirement must exist in security scheme object.");
    }


}


njt_int_t
njt_openapi_push_sql(njt_openapi_api_item_t *item, njt_int_t in_api,
    njt_openapi_security_scheme_t *sec, njt_array_t *sqls) 
{
    u_char      buf[4095];
    u_char     *end;
    njt_str_t  *sql;
    njt_int_t   grant_mode = 0;
    njt_pool_t *pool;

    pool = sqls->pool;

    // todo add other grant mode
    if (sec->type != NJT_OPENAPI_SECURITY_SCHEME_UNSET) {
        grant_mode = 1;
    }

    if (in_api == 0) {

        end = njt_snprintf(buf, sizeof(buf) - 1,
            "DELETE FROM api_grant_mode WHERE api_id IN (SELECT api_id FROM api WHERE group_id=%d AND path=\"%s\" AND method=\"%s\");",
            item->group_id, item->path, item->method);

        sql = njt_array_push(sqls);
        if (sqls == NULL) {
            return NJT_ERROR;
        }

        sql->len = end - buf;
        sql->data = njt_palloc(pool, sql->len + 1);

        if (sql->data == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(sql->data, buf, sql->len);
        sql->data[sql->len] = 0;
        sql->len += 1;
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add sql: %V", &sql);
        // printf("add sql: %s \n", sql->data);



        end = njt_snprintf(buf, sizeof(buf) - 1,
            "INSERT OR IGNORE INTO api (name, group_id, path, method, desc, param_mode) VALUES(\"%s\", %d, \"%s\", \"%s\", \"%s\", 0);",
            item->title, item->group_id, item->path, item->method, item->desc);

        sql = njt_array_push(sqls);
        if (sqls == NULL) {
            return NJT_ERROR;
        }

        sql->len = end - buf;
        sql->data = njt_palloc(pool, sql->len + 1);

        if (sql->data == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(sql->data, buf, sql->len);
        sql->data[sql->len] = 0;
        sql->len += 1;
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add sql: %V", &sql);
        // printf("add sql: %s \n", sql->data);


        end = njt_snprintf(buf, sizeof(buf) - 1,
            "UPDATE api SET name=\"%s\", desc=\"%s\", param_mode=%d WHERE group_id=%d AND path=\"%s\" AND method=\"%s\";",
            item->title, item->desc, 0, item->group_id, item->path, item->method);

        sql = njt_array_push(sqls);
        if (sqls == NULL) {
            return NJT_ERROR;
        }

        sql->len = end - buf;
        sql->data = njt_palloc(pool, sql->len + 1);

        if (sql->data == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(sql->data, buf, sql->len);
        sql->data[sql->len] = 0;
        sql->len += 1;
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add sql: %V", &sql);
        // printf("add sql: %s \n", sql->data);

    }

    end = njt_snprintf(buf, sizeof(buf) - 1,
        "INSERT INTO api_grant_mode (grant_mode, api_id)  VALUES (%d, (SELECT api.id FROM api WHERE group_id=%d AND path=\"%s\" AND method=\"%s\"));",
        grant_mode, item->group_id, item->path, item->method);

    sql = njt_array_push(sqls);
    if (sqls == NULL) {
        return NJT_ERROR;
    }

    sql->len = end - buf;
    sql->data = njt_palloc(pool, sql->len + 1);

    if (sql->data == NULL) {
        return NJT_ERROR;
    }

    njt_memcpy(sql->data, buf, sql->len);
    sql->data[sql->len] = 0;
    sql->len += 1;


    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0, "add sql: %V", &sql);
    // printf("add sql: %s \n", sql->data);

    return NJT_OK;

}


njt_int_t
njt_openapi_parse_json(njt_str_t *json_str, njt_str_t *db_name, njt_int_t group_id) 
{
    njt_log_t                       *log;
    json_t                          *root;
    json_t                          *paths, *path, *method;
    json_t                          *summary, *description;
    json_t                          *security, *security_requirement, *items;
    json_t                          *info, *title;
    json_error_t                     err = {0};
    const char                      *s_key, *s_method, *sec_key; 
    njt_openapi_security_scheme_t    global_security_scheme = {0};
    njt_openapi_security_scheme_t    local_security_scheme = {0};
    njt_openapi_security_scheme_t    *cur_security_scheme;
    njt_int_t                        in_api;
    njt_array_t                     *sqls;
    njt_pool_t                      *dyn_pool;
    size_t                           index;
    njt_openapi_api_item_t           item;


    log = njt_cycle->log;

    log->action = "openapi parsing";
    root = json_loads((const char*)json_str->data, 0, &err);
    if (root == NULL) {
        njt_log_error(NJT_LOG_CRIT, log, 0, "parse openapi failed.");
        return NJT_ERROR;
    }

    info = json_object_get(root, "info");
    if (info == NULL) {
        njt_log_error(NJT_LOG_CRIT, log, 0, "info must exist in openapi struct");
        return NJT_ERROR;
    }

    title = json_object_get(info, "title");
    if (title == NULL) {
        njt_log_error(NJT_LOG_CRIT, log, 0, "title must exist in openapi info object");
        return NJT_ERROR;
    }
    item.title = json_string_value(title);
    item.group_id = group_id;

    paths = json_object_get(root, "paths");
    if (paths == NULL) {
        njt_log_error(NJT_LOG_CRIT, log, 0, "paths must exist in openapi struct");
        return NJT_ERROR;
    }

    njt_openapi_parse_security_scheme(root, &global_security_scheme);

    dyn_pool = njt_create_pool(NJT_CYCLE_POOL_SIZE, njt_cycle->log);
    sqls = njt_array_create(dyn_pool, 10, sizeof(njt_str_t));

    // ON CONFLICT DO UPDATE 这是 postgresql 支持的语法， sqlite我查是 INSERT OR REPLACE|ABORT|ROLLBACK|IGNORE|NULL

    json_object_foreach(paths, s_key, path) {

        item.path = s_key;

        json_object_foreach(path, s_method, method) {
            item.method = s_method;

            summary = json_object_get(method, "summary");

            if (summary != NULL) {
                item.desc = json_string_value(summary);
            } else {
                description = json_object_get(method, "description");
                if (description == NULL) {
                    item.desc = s_key;
                } else {
                    item.desc = json_string_value(description);
                }
            }

            cur_security_scheme = &global_security_scheme;

            security = json_object_get(method, "security");
            if (security != NULL) {
                if (json_array_size(security) == 0) {
                        local_security_scheme.type = NJT_OPENAPI_SECURITY_SCHEME_UNSET;
                        cur_security_scheme = &local_security_scheme;
                        if (njt_openapi_push_sql(&item, 0, cur_security_scheme, sqls) != NJT_OK)
                        {
                            goto failed;
                        }
                } else {
                        cur_security_scheme = &local_security_scheme;
                        in_api = 0;
                        
                        json_array_foreach(security, index, security_requirement) {
                            json_object_foreach(security_requirement, sec_key, items) {
                                njt_openapi_parse_security_scheme_local(root, sec_key, &local_security_scheme);
                                if (njt_openapi_push_sql(&item, in_api, cur_security_scheme, sqls) != NJT_OK)
                                {
                                    goto failed;
                                }
                                in_api = 1;
                            }
                        }
                }
            } else {
                if (njt_openapi_push_sql(&item, 0, cur_security_scheme, sqls) != NJT_OK)
                {
                    goto failed;
                }
            }
        }
    }

    // type :
    // APIKeySecurityScheme [apikey] -> name : string, in [header, query, cookie]
    // HTTPSecurityScheme   [http] -> schema: string
    // OAuth2SecurityScheme [oauth2] -> flow [ "implicit", "password", "clientCredentials", "authorizationCode"]
    // OpenIdConnectSecurityScheme [openIdConnect] -> openIdConnectUrl: string

    // for sql in sqls 
    // update sql with secure related fields
    njt_openapi_insert_db(db_name, sqls);

    njt_destroy_pool(dyn_pool);
    return NJT_OK;

failed:
    njt_destroy_pool(dyn_pool);
    return NJT_ERROR;
}


