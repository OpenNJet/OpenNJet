/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>

#define njt_resolver_node(n)                                                 \
    (njt_resolver_node_t *)                                                  \
    ((u_char *) (n) - offsetof(njt_resolver_node_t, node))

typedef struct {
    njt_http_upstream_server_t   *server;
    njt_http_upstream_srv_conf_t *upstream_conf;
    njt_str_t                     host;
    in_port_t                     port;
    njt_event_t                   timer;
    njt_uint_t                    count;
    uint32_t                      crc32;
	time_t                        valid;
	njt_http_upstream_rr_peer_t  *parent_node;
} njt_http_upstream_dynamic_server_conf_t;

typedef struct {
    njt_resolver_t               *resolver;
    njt_msec_t                    resolver_timeout;
    njt_list_t                   *dynamic_servers;
	njt_list_t                   dy_servers;
	njt_list_t                   cache_servers;
    njt_http_conf_ctx_t          *conf_ctx;
	njt_event_t                   timer;
	time_t                    valid;
	njt_shm_zone_t *shm_zone;
	njt_http_upstream_rr_peers_t *peers;
	//njt_http_upstream_srv_conf_t *upstream_conf;
} njt_http_upstream_dynamic_server_main_conf_t;

static njt_str_t njt_http_upstream_dynamic_server_null_route =
    njt_string("127.255.255.255");

static void *njt_http_upstream_dynamic_server_main_conf(njt_conf_t *cf);

static char *njt_http_upstream_dynamic_server_directive(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);

static char *njt_http_upstream_resolver_directive(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);
static char *njt_http_upstream_resolver_timeout_directive(njt_conf_t *cf,
        njt_command_t *cmd, void *conf);

static char *njt_http_upstream_dynamic_servers_merge_conf(njt_conf_t *cf,
        void *parent, void *child);
static njt_int_t njt_http_upstream_dynamic_servers_init_process(
    njt_cycle_t *cycle);
static void njt_http_upstream_dynamic_server_resolve(njt_event_t *ev);
static void njt_http_upstream_dynamic_server_resolve_handler(
    njt_resolver_ctx_t *ctx);
static njt_int_t njt_http_upstream_dynamic_server_init_zone(njt_shm_zone_t *shm_zone,
        void *data);
static void njt_http_upstream_check_dynamic_server(njt_event_t *ev);
static njt_int_t
njt_http_upstream_dynamic_servers_init(njt_conf_t *cf);
static void njt_http_upstream_dynamic_server_delete_server(
    njt_http_upstream_dynamic_server_conf_t *dynamic_server);
static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_parent_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,njt_str_t route,njt_int_t alloc_id);
static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_init_parent_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,njt_str_t route,njt_http_upstream_rr_peer_t *parent_node);
static char *
njt_http_upstream_state(njt_conf_t *cf, njt_command_t *cmd, void *conf);


extern njt_int_t
njt_http_upstream_init_hash(njt_conf_t *cf, njt_http_upstream_srv_conf_t *us);

extern njt_int_t
njt_http_upstream_init_ip_hash(njt_conf_t *cf, njt_http_upstream_srv_conf_t *us);

extern njt_int_t
njt_http_upstream_init_chash(njt_conf_t *cf, njt_http_upstream_srv_conf_t *us);

extern njt_int_t njt_http_upstream_init_random(njt_conf_t *cf,
    njt_http_upstream_srv_conf_t *us);

static char *njt_http_upstream_check(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf);

static njt_command_t njt_http_upstream_dynamic_servers_commands[] = {
    {
        njt_string("server"),
        NJT_HTTP_UPS_CONF | NJT_CONF_1MORE,
        njt_http_upstream_dynamic_server_directive,
        0,
        0,
        NULL
    },

    {
        njt_string("resolver"),
        NJT_HTTP_UPS_CONF | NJT_CONF_1MORE,
        njt_http_upstream_resolver_directive,
        0,
        0,
        NULL
    },

    {
        njt_string("resolver_timeout"),
        NJT_HTTP_UPS_CONF | NJT_CONF_TAKE1,
        njt_http_upstream_resolver_timeout_directive,
        0,
        0,
        NULL
    },
	{
        njt_string("state"),
        NJT_HTTP_UPS_CONF | NJT_CONF_TAKE1,
        njt_http_upstream_state,
        0,
        0,
        NULL
    },
	 {
        njt_string("health_check"),
        NJT_HTTP_UPS_CONF | NJT_CONF_1MORE,
        njt_http_upstream_check,
        0,
        0,
        NULL
    },
    njt_null_command
};

static njt_http_module_t njt_http_upstream_dynamic_servers_module_ctx = {
    NULL,                                         /* preconfiguration */
    njt_http_upstream_dynamic_servers_init,       /* postconfiguration */

    njt_http_upstream_dynamic_server_main_conf,   /* create main configuration */
    NULL,                                         /* init main configuration */

    NULL,                                         /* create server configuration */
    njt_http_upstream_dynamic_servers_merge_conf, /* merge server configuration */

    NULL,                                         /* create location configuration */
    NULL                                          /* merge location configuration */
};

njt_module_t njt_http_upstream_dynamic_servers_module = {
    NJT_MODULE_V1,
    &njt_http_upstream_dynamic_servers_module_ctx,  /* module context */
    njt_http_upstream_dynamic_servers_commands,     /* module directives */
    NJT_HTTP_MODULE,                                /* module type */
    NULL,                                           /* init master */
    NULL,                                           /* init module */
    njt_http_upstream_dynamic_servers_init_process, /* init process */
    NULL,                                           /* init thread */
    NULL,                                           /* exit thread */
    NULL,                                           /* exit process */
    NULL,                                           /* exit master */
    NJT_MODULE_V1_PADDING
};

static njt_int_t
njt_http_upstream_dynamic_servers_init(njt_conf_t *cf)
{
	
	 njt_uint_t                      i,j;
	 njt_http_upstream_dynamic_server_conf_t       *dynamic_server;
	 njt_http_upstream_main_conf_t  *umcf;
	 njt_list_part_t *part;
	 njt_http_upstream_srv_conf_t   *uscf, **uscfp;
	 //njt_flag_t                     have_dyserver;
	 njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;



	 udsmcf = njt_http_conf_get_module_main_conf(cf,
             njt_http_upstream_dynamic_servers_module);

     umcf = njt_http_conf_get_module_main_conf(cf, njt_http_upstream_module);
     uscfp = umcf->upstreams.elts;
	

	for (i = 0; i < umcf->upstreams.nelts; i++)
	{
		uscf = uscfp[i];
		part = &udsmcf->dynamic_servers->part;
		dynamic_server  = part->elts;
		if (uscf->shm_zone != NULL) {
			if(uscf->resolver == NULL) {
					uscf->resolver = udsmcf->resolver;
					uscf->resolver_timeout = udsmcf->resolver_timeout;
					uscf->valid = udsmcf->valid;
			}
		}
		
		 for (j = 0; ; j++) {
			if(j >= part->nelts) {
				if(part->next == NULL)
					break;
				part = part->next;
				dynamic_server = part->elts;
				j = 0;
			}
			if(dynamic_server && dynamic_server->upstream_conf == uscf) {
				 if (uscf->shm_zone == NULL) {
					njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
									   "in upstream \"%V\" resolve must coexist with a shared memory zone",
									   &uscf->host);
					return NJT_ERROR;

				}
				if(uscf->resolver == NULL) {
					uscf->resolver = udsmcf->resolver;
					uscf->resolver_timeout = udsmcf->resolver_timeout;
					uscf->valid = udsmcf->valid;
				}
				if(uscf->resolver == NULL) {
						njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
								   "no resolver defined to resolve names at run time in upstream \"%V\"",&uscf->host);
						return NJT_ERROR;
				}
				  
			}
		 }

	}
		
    return NJT_OK;
}

static njt_err_t
njt_create_sate_file(u_char *dir, njt_uid_t user,njt_uid_t group,njt_uint_t access, njt_cycle_t  *cycle)
{
    u_char     *p, ch;
    njt_err_t   err;
	njt_fd_t          fd;
    err = 0;

#if (NJT_WIN32)
    p = dir + 3;
#else
    p = dir + 1;
#endif

    for ( /* void */ ; *p; p++) {
        ch = *p;

        if (ch != '/') {
            continue;
        }

        *p = '\0';

        if (njt_create_dir(dir, access) == NJT_FILE_ERROR) {
            err = njt_errno;

            switch (err) {
            case NJT_EEXIST:
                 err = NJT_EEXIST;
				 break;
            case NJT_EACCES:
                break;

            default:
                return err;
            }
        }
		if(err == 0) {
			if (chown((const char *)dir,user,getgid()) == -1) {
				njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "chmod() \"%s\" failed", dir);
			}
		}
		err = 0;
        *p = '/';
    }
	fd = njt_open_file(dir, NJT_FILE_CREATE_OR_OPEN | NJT_FILE_RDWR, NJT_FILE_OPEN,  0666);
    if (fd == NJT_INVALID_FILE) {
		njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "njt_open_file() \"%s\" failed", dir);
		err = njt_errno;
        return err;
    }
	if (fchown(fd,user,group) == -1) {
				njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "fchown() \"%s\" failed", dir);
			}
    if (njt_close_file(fd) == NJT_FILE_ERROR) {
        njt_log_error(NJT_LOG_EMERG, cycle->log, njt_errno,
                                  "njt_close_file() \"%s\" failed", dir);
    }

	return err;
  
}

static char *
njt_http_upstream_state(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_str_t   *value, file;
    njt_http_upstream_srv_conf_t      *uscf;
    //njt_fd_t          fd;
	njt_core_conf_t  *ccf;
    value = cf->args->elts;
    file = value[1];

	ccf = (njt_core_conf_t *) njt_get_conf(cf->cycle->conf_ctx,
                                                   njt_core_module);
    njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "state %V", &file);

    if (njt_conf_full_name(cf->cycle, &file, 1) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    if (strpbrk((char *) file.data, "*?[") != NULL) {
        njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0,
                       "the name of file %s contains *?[ chars", file.data);
        return "file name contains *?[ chars";
    }

    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);

    if (uscf->state_file.data != NULL || uscf->state_file.len != 0) {
        return "\"state\" directive is duplicate";
    }
    uscf->state_file = file;

    if (uscf->servers->nelts > 0) {
        return "\"state\" directive is incompatible with \"server\"";
    }

    njt_log_debug1(NJT_LOG_DEBUG_CORE, cf->log, 0, "include %s", file.data);
	if(ccf) {
		njt_create_sate_file(file.data,ccf->user,ccf->group,0755,cf->cycle);
	}

   
    return njt_conf_parse(cf, &file);
}

static char *njt_http_upstream_resolver_timeout_directive(njt_conf_t *cf,
        njt_command_t *cmd, void *conf)
{

	 njt_http_upstream_srv_conf_t  *udsmcf;
    njt_str_t  *value;
	
	udsmcf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
    value = cf->args->elts;
    udsmcf->resolver_timeout = njt_parse_time(&value[1], 0);
    if (udsmcf->resolver_timeout == (njt_msec_t) NJT_ERROR) {
        return "invalid value";
    }

    return NJT_CONF_OK;
}

static char *njt_http_upstream_resolver_directive(njt_conf_t *cf,
        njt_command_t *cmd, void *conf)
{
    njt_http_upstream_srv_conf_t  *udsmcf;
    njt_str_t  *value;
	njt_str_t                   s;
	 njt_uint_t                  i;
	udsmcf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);



    value = cf->args->elts;
	udsmcf->resolver_timeout = 10;
    udsmcf->resolver = njt_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (udsmcf->resolver == NULL) {
        return NJT_CONF_ERROR;
    }
	
	for (i = 2; i < cf->args->nelts; i++)
	{
		if (njt_strncmp(value[i].data, "valid=", 6) == 0) {
            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            udsmcf->valid = njt_parse_time(&s, 1);

            if (udsmcf->valid == (time_t) NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

	}

    return NJT_CONF_OK;
}

/*Overwrite the njet "server" directive based on its
 implementation of "njt_http_upstream_server" from
 src/http/njt_http_upstream.c (njet version 1.7.7), and should be kept in
 sync with njet's source code. Customizations noted in comments.
 This make possible use the same syntax of njet comercial version.*/

static char *njt_http_upstream_dynamic_server_directive(njt_conf_t *cf,
        njt_command_t *cmd, void *conf)
{
    /* BEGIN CUSTOMIZATION: differs from default "server" implementation*/
    njt_http_upstream_srv_conf_t                  *uscf;
    njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    njt_http_upstream_dynamic_server_conf_t       *dynamic_server = NULL;
    /* END CUSTOMIZATION*/

    time_t                       fail_timeout;
    njt_str_t                   *value, s;
    njt_url_t                    u;
    njt_int_t                    weight, max_conns, max_fails,slow_start;
    njt_uint_t                   i;
    njt_http_upstream_server_t  *us;
    njt_uint_t                   no_resolve = 0;
	

    /* BEGIN CUSTOMIZATION: differs from default "server" implementation */
    uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
    udsmcf = njt_http_conf_get_module_main_conf(cf,
             njt_http_upstream_dynamic_servers_module);
    /* END CUSTOMIZATION*/
	
	if (uscf->state_file.data != NULL && (uscf->state_file.len != cf->conf_file->file.name.len ||  njt_strncmp(uscf->state_file.data, cf->conf_file->file.name.data, uscf->state_file.len) != 0)) {
         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"server\" directive is incompatible with \"state\"");
        return NJT_CONF_ERROR;
    }

    us = njt_array_push(uscf->servers);
    if (us == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(us, sizeof(njt_http_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;
    slow_start = 0;
    njt_memzero(&u, sizeof(njt_url_t));
    u.url = value[1];
    u.default_port = 80;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = njt_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NJT_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = njt_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NJT_ERROR) {
                goto invalid;
            }

            continue;
        }
		if (njt_strncmp(value[i].data, "slow_start=", 11) == 0) {

			s.len = value[i].len - 11;
            s.data = &value[i].data[11];
			slow_start = njt_parse_time(&s, 1);
            //slow_start = njt_atoi(&value[i].data[11], value[i].len - 11);
			/*
            if (slow_start == NJT_ERROR) {
				slow_start = njt_atoi(&value[i].data[11], value[i].len - 12);
				if (slow_start == NJT_ERROR) {
                   goto invalid;
				}
				switch (value[i].data[value[i].len - 1]) {
				case 's':
					break;
				case 'm':
					slow_start *= 60;
					break;
				case 'h':
					slow_start *= 60 * 60;
					break;
				case 'd':
					slow_start *= 60 * 60 * 24 * 1;
					break;
				case 'M':
					slow_start *= 60 * 60 * 24 * 30;
					break;
				case 'y':
					slow_start *= 60 * 60 * 24 * 365;
					break;
				default:
					 goto invalid;
				}
            }*/
			 if (!(uscf->flags & NJT_HTTP_UPSTREAM_SLOW_START)) {
                goto not_supported;
            }
            continue;
        }

        if (njt_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = njt_parse_time(&s, 1);

            if (fail_timeout == (time_t) NJT_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (njt_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (njt_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & NJT_HTTP_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        /* BEGIN CUSTOMIZATION: differs from default "server" implementationa*/
        if (njt_strcmp(value[i].data, "resolve") == 0) {
            /* Determine if the server given is an IP address or a hostname by running
               through njt_parse_url with no_resolve enabled. Only if a hostname is given
               will we add this to the list of dynamic servers that we will resolve again.*/

	    us->dynamic = 1;  //zyg
            //u.no_resolve = 1;
            no_resolve = 1;
            njt_parse_url(cf->pool, &u);
            //if (!u.addrs || !u.addrs[0].sockaddr) {
                dynamic_server = njt_list_push(&udsmcf->dy_servers);
                if (dynamic_server == NULL) {
                    return NJT_CONF_ERROR;
                }

                njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));
                dynamic_server->server = us;
                dynamic_server->upstream_conf = uscf;

                dynamic_server->host = u.host;
                dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
           // }

            continue;
        }
	if (njt_strncmp(value[i].data, "route=", 6) == 0) {

	     if (value[i].len <= sizeof("route=") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a value should be provided to "
                                   "\"route\" parameter.");
                return NJT_CONF_ERROR;
            }
            /* set route parameter */
            us->route.len = value[i].len - sizeof("route=") + 1;
            us->route.data = value[i].data + sizeof("route=") - 1;
			if(us->route.len > 32) {
				 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "route is longer than 32");
				return NJT_CONF_ERROR;
			}
            continue;
        }
    
        /* END CUSTOMIZATION */

        goto invalid;
    }

    /* BEGIN CUSTOMIZATION: differs from default "server" implementation*/
    if (no_resolve == 0 && njt_parse_url(cf->pool, &u) != NJT_OK) {
        if (u.err && !no_resolve) {
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                               " %s in upstream \"%V\"", u.err, &u.url);
            return NJT_CONF_ERROR;
        }

        /* If the domain fails to resolve on start up, mark this server as down,
         and assign a static IP that should never route. This is to account for
         various things inside njet that seem to expect a server to always have
         at least 1 IP.*/
        //us->down = 1;
		
        u.url = njt_http_upstream_dynamic_server_null_route;
        u.default_port = u.port;
        u.no_resolve = 1;

        if (njt_parse_url(cf->pool, &u) != NJT_OK) {
            if (u.err && !no_resolve) {
                njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                                   " %s in upstream \"%V\"", u.err, &u.url);
            }
            return NJT_CONF_ERROR;
        }
        //us->fake = 1;
    }
    /* END CUSTOMIZATION */
	
	us->max_conns = max_conns;
	us->name = u.url;
	us->addrs = u.addrs;
	us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;
	us->slow_start = slow_start;

    return NJT_CONF_OK;

invalid:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NJT_CONF_ERROR;

not_supported:

    njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return NJT_CONF_ERROR;
}

static njt_int_t njt_http_upstream_dynamic_server_init_zone(njt_shm_zone_t *shm_zone,
        void *data)
{

	//njt_http_upstream_api_loc_conf_t *olduclcf = data;
    njt_slab_pool_t *shpool;
    njt_http_upstream_rr_peers_t *peers;
	njt_http_upstream_dynamic_server_main_conf_t *uclcf;
	


	if (data) {
        shm_zone->data = data;
        return NJT_OK;
    }
	shpool = (njt_slab_pool_t *)shm_zone->shm.addr;
	uclcf = shm_zone->data;

	 if (shm_zone->shm.exists) {
   
        peers = shpool->data;
		uclcf->peers = peers;
        return NJT_OK;
    }


    /* setup our shm zone */
	peers = njt_slab_alloc(shpool, sizeof(njt_http_upstream_rr_peers_t));
	if(peers) {
		peers->number = 0;
		peers->peer = NULL;
		peers->shpool = shpool;
		shpool->data = peers;
		uclcf->peers = peers;
	} else {
		 return NJT_ERROR;
	}
    //peers->shpool = shpool;

    return NJT_OK;

}

static void *njt_http_upstream_dynamic_server_main_conf(njt_conf_t *cf)
{
	ssize_t size; 
	njt_str_t zone = njt_string("api_dy_server");
	size = (ssize_t)(10 * njt_pagesize);

    njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
	
    udsmcf = njt_pcalloc(cf->pool,
                         sizeof(njt_http_upstream_dynamic_server_main_conf_t));
    if (udsmcf == NULL) {
        return NULL;
    }

    if (njt_list_init(&udsmcf->cache_servers, cf->pool, 1,
                       sizeof(njt_http_upstream_dynamic_server_conf_t)) != NJT_OK) {
        return NULL;
    }
	 if (njt_list_init(&udsmcf->dy_servers, cf->pool, 1,
                       sizeof(njt_http_upstream_dynamic_server_conf_t)) != NJT_OK) {
        return NULL;
    }
	udsmcf->dynamic_servers = &udsmcf->dy_servers;
    udsmcf->resolver_timeout = NJT_CONF_UNSET_MSEC;

	if(udsmcf->shm_zone == NULL) {
		udsmcf->shm_zone = njt_shared_memory_add(cf, &zone, size, &njt_http_upstream_module);
		 if (udsmcf->shm_zone == NULL) {
            njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                               "api shared memory zone error!");
            return NULL;

        }
		udsmcf->shm_zone->data = udsmcf;
		udsmcf->shm_zone->init = njt_http_upstream_dynamic_server_init_zone;
		udsmcf->shm_zone->noreuse = 1; 
	}

    return udsmcf;
}

static char *njt_http_upstream_dynamic_servers_merge_conf(njt_conf_t *cf,
        void *parent, void *child)
{
    /* If any dynamic servers are present, verify that a "resolver" is setup as
     the http level.*/
    njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    //njt_http_upstream_srv_conf_t                  *uscf;
    njt_http_core_loc_conf_t                      *core_loc_conf;
   // njt_http_upstream_dynamic_server_conf_t       *dynamic_servers;
	//ssize_t size; 
	//njt_str_t zone = njt_string("api_dy_server");
	//size = (ssize_t)(10 * njt_pagesize);

	

    udsmcf = njt_http_conf_get_module_main_conf(cf,
             njt_http_upstream_dynamic_servers_module);

    //dynamic_servers = (njt_http_upstream_dynamic_server_conf_t *)
     //                 udsmcf->dynamic_servers->part.elts;

	core_loc_conf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
	udsmcf->valid = 0;
	if (udsmcf->resolver == NULL) {
		/*
		if (udsmcf->dynamic_servers->part.nelts > 0 ) {
			njt_conf_log_error(NJT_LOG_ERR, cf, 0,
							   "resolver must be defined at the 'http' level of the config");
			return NJT_CONF_ERROR;
		}*/
		if(core_loc_conf->resolver != NULL && core_loc_conf->resolver->connections.nelts != 0) {
			udsmcf->resolver = core_loc_conf->resolver;
			if(core_loc_conf->resolver){
				udsmcf->valid = core_loc_conf->resolver->valid;
			}
		}
	}
	if(udsmcf->valid == 0) {
		udsmcf->valid = 20;
	}
/*
    if (udsmcf->dynamic_servers->part.nelts > 0) {

        uscf = dynamic_servers[0].upstream_conf;
    

        if (uscf->shm_zone == NULL) {
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                               "in upstream \"%V\" resolve must coexist with a shared memory zone",
                               &uscf->host);
            return NJT_CONF_ERROR;

        }
        
    } 

	if(udsmcf->resolver != NULL && udsmcf->resolver->connections.nelts >0 &&  udsmcf->shm_zone == NULL) {
		uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
		udsmcf->shm_zone = njt_shared_memory_add(cf, &zone, size, &njt_http_upstream_module);
		 if (udsmcf->shm_zone == NULL) {
            njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                               "in upstream \"%V\" resolve must coexist with a  api shared memory zone",
                               &uscf->host);
            return NJT_CONF_ERROR;

        }
		udsmcf->shm_zone->data = udsmcf;
		udsmcf->shm_zone->init = njt_http_upstream_dynamic_server_init_zone;
		udsmcf->shm_zone->noreuse = 1; 
		udsmcf->upstream_conf = uscf;
	}*/


	udsmcf->conf_ctx = cf->ctx;

     njt_conf_merge_msec_value(udsmcf->resolver_timeout,
                                  core_loc_conf->resolver_timeout, 30000);


    

    return NJT_CONF_OK;
}

static njt_int_t njt_http_upstream_dynamic_servers_cache_server(njt_cycle_t *cycle)
{
	njt_uint_t                                    i;
	njt_flag_t                                    have;
	njt_http_upstream_rr_peers_t                  *peers ;
	njt_http_upstream_main_conf_t                 *umcf;
	njt_http_upstream_srv_conf_t                  **uscfp;
	njt_http_upstream_srv_conf_t                  *uscf;
	//njt_http_upstream_srv_conf_t                  *upstream_conf;
	njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
	njt_url_t                    u;
	njt_http_upstream_dynamic_server_conf_t       *dynamic_server = NULL;
	njt_http_upstream_server_t  *us;
	njt_http_upstream_rr_peer_t                   *peer;
		
	umcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_upstream_module);
	udsmcf = njt_http_cycle_get_module_main_conf(cycle,
             njt_http_upstream_dynamic_servers_module);
	
	have = 0;
	if(umcf == NULL || udsmcf == NULL)
		return have;

	uscfp = umcf->upstreams.elts;
	
	 for (i = 0; i < umcf->upstreams.nelts; i++)
		{
			uscf = uscfp[i];
			peers = uscf->peer.data;
			if(peers->parent_node != NULL) {
				
				 njt_http_upstream_rr_peers_wlock(peers);
				for (peer = peers->parent_node; peer ; peer = peer->next) {
					
					if(peer->parent_id == -1)
						continue;
					have = 1;
					dynamic_server = njt_list_push(&udsmcf->cache_servers);
					njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));
					
					njt_memzero(&u, sizeof(njt_url_t));
					
					us = njt_array_push(uscf->servers);
					njt_memzero(us, sizeof(njt_http_upstream_server_t));
					
					us->name.data = njt_pcalloc(cycle->pool,peer->server.len);
					if(us->name.data == NULL)
						continue;
					us->name.len = peer->server.len;
					us->route.data = njt_pcalloc(cycle->pool,peer->route.len);
					if(us->route.data == NULL)
						continue;
					us->route.len = peer->route.len;
					
					 njt_memcpy(us->name.data,peer->server.data,peer->server.len);
					 njt_memcpy(us->route.data,peer->route.data,peer->route.len);
					 
					
	
					 u.url = us->name;
					 u.default_port = 80;
					 u.no_resolve = 1;
					 njt_parse_url(cycle->pool, &u);
					 
					us->backup = peer->set_backup;
					us->down = peer->down;
					us->addrs = NULL;
					us->naddrs = 0;
					us->weight = peer->weight;
					us->max_conns = peer->max_conns;
					us->max_fails = peer->max_fails;
					us->fail_timeout = peer->fail_timeout;
					us->slow_start = peer->slow_start;
				
					
					
					
					dynamic_server->server = us;
					dynamic_server->upstream_conf = uscf;
					
					 dynamic_server->parent_node = peer;
				
					dynamic_server->host = u.host;
					dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
				}
				njt_http_upstream_rr_peers_unlock(peers);
			}
		}
		if(have) {
			udsmcf->dynamic_servers = &udsmcf->cache_servers;
		}
		return have;

}
static njt_int_t njt_http_upstream_dynamic_servers_init_process(
    njt_cycle_t *cycle)
{
    njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    njt_http_upstream_dynamic_server_conf_t       *dynamic_server;
    njt_uint_t i;
	njt_list_part_t *part;
    njt_event_t *timer = NULL;
    njt_uint_t refresh_in;
	

    if ((njt_process != NJT_PROCESS_WORKER && njt_process != NJT_PROCESS_SINGLE) || njt_worker != 0) {
        /*only works in the worker 0 prcess.*/
        return NJT_OK;
    }

	njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                      "start upstream-dynamic-servers module flag=%p!",cycle->old_cycle);
	
	njt_http_upstream_dynamic_servers_cache_server(cycle);
    udsmcf = njt_http_cycle_get_module_main_conf(cycle,
             njt_http_upstream_dynamic_servers_module);

	if(udsmcf == NULL)
		return NJT_OK;
	part = &udsmcf->dynamic_servers->part;
    dynamic_server = (njt_http_upstream_dynamic_server_conf_t       *)part->elts;

    for (i = 0; ; i++) {
		if(i >= part->nelts) {
			if(part->next == NULL)
				break;
			part = part->next;
			dynamic_server = part->elts;
			i = 0;
		}
		//dynamic_server[i].parent_id = -1;
		dynamic_server[i].valid = dynamic_server[i].upstream_conf->valid;
        timer = &dynamic_server[i].timer;
        timer->handler = njt_http_upstream_dynamic_server_resolve;
        timer->log = cycle->log;
        timer->data = &dynamic_server[i];
		timer->cancelable = 1;
        refresh_in = njt_random() % 1000;
        njt_log_debug(NJT_LOG_DEBUG_CORE, cycle->log, 0,
                      "upstream-dynamic-servers: Initial DNS refresh of '%V' in %ims",
                      &dynamic_server[i].host, refresh_in);
        njt_add_timer(timer, refresh_in);
    }
	
		timer = &udsmcf->timer;
		timer->handler = njt_http_upstream_check_dynamic_server;
        timer->log = cycle->log;
		timer->data = cycle;
		timer->cancelable = 1;
        refresh_in = njt_random() % 1000;
        njt_add_timer(timer, refresh_in);
	
    return NJT_OK;
}

static void njt_http_upstream_modify_dynamic_server(njt_http_upstream_srv_conf_t *upstream_conf,
                             njt_http_upstream_rr_peer_t *peer) 
{
	njt_uint_t i;
	njt_http_upstream_dynamic_server_conf_t       *dynamic_server, *p;
	njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
	njt_http_upstream_rr_peers_t                  *peers;
	njt_slab_pool_t              *pool;
	njt_list_part_t *part;

	 udsmcf = njt_http_cycle_get_module_main_conf(njt_cycle,
             njt_http_upstream_dynamic_servers_module);
	 if(udsmcf == NULL) {
	   return;
	 }
	
	  part = &udsmcf->dynamic_servers->part;
	  dynamic_server = (njt_http_upstream_dynamic_server_conf_t       *)part->elts;

	 for (i = 0; ; i++) {
		if(i >= part->nelts) {
			if(part->next == NULL)
				break;
			part = part->next;
			dynamic_server = part->elts;
			i = 0;
		}
		p = &dynamic_server[i];
		 if(p->upstream_conf == upstream_conf && peer->parent_id == (njt_int_t)p->parent_node->id) {

				    peers = upstream_conf->peer.data;

					njt_http_upstream_rr_peers_wlock(peers);
					pool = peers->shpool;
					if(peer->route.len > 0) {
						if(p->parent_node->route.len < peer->route.len) {
							njt_slab_free_locked(pool,p->parent_node->route.data);
						}
						p->parent_node->route.data = njt_slab_calloc_locked(pool,peer->route.len);
						p->parent_node->route.len = peer->route.len;
						if(p->parent_node->route.data == NULL) {
							njt_http_upstream_rr_peers_unlock(peers);
							break;
						}
					}
					njt_memcpy(p->parent_node->route.data, peer->route.data, peer->route.len);
					if(peer->weight > 0)
						p->parent_node->weight = peer->weight;
					if(peer->max_fails != (njt_uint_t)-1)
						p->parent_node->max_fails = peer->max_fails;
					if(peer->fail_timeout > 0)
						p->parent_node->fail_timeout = peer->fail_timeout;
					if(peer->max_conns != (njt_uint_t)-1)
						p->parent_node->max_conns = peer->max_conns;
					if(peer->slow_start != (njt_uint_t)-1)
						p->parent_node->slow_start = peer->slow_start;
					if(peer->down != (njt_uint_t)-1){
						p->parent_node->down = peer->down;
					}

					njt_http_upstream_rr_peers_unlock(peers);
					break;
				
				
		 }
	 }

}

static void njt_http_upstream_free_dynamic_server(njt_http_upstream_srv_conf_t *upstream_conf,
                             njt_str_t server,njt_int_t id) 
{

	njt_uint_t i;
	njt_http_upstream_dynamic_server_conf_t       *dynamic_server, *p;
	njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
	njt_list_part_t *part;
	 udsmcf = njt_http_cycle_get_module_main_conf(njt_cycle,
             njt_http_upstream_dynamic_servers_module);
	 if(udsmcf == NULL) {
		return;
	 }
	 part = &udsmcf->dynamic_servers->part;
	 dynamic_server = (njt_http_upstream_dynamic_server_conf_t       *)part->elts;

	  //dynamic_server = udsmcf->dynamic_servers.elts;

	 for (i = 0; ; i++) {
		if(i >= part->nelts) {
			if(part->next == NULL)
				break;
			part = part->next;
			dynamic_server = part->elts;
			i = 0;
		}
		 p = &dynamic_server[i];
		 if(p->upstream_conf == upstream_conf && id == (njt_int_t)p->parent_node->id) {
				
				
				if (p->timer.timer_set) {
					njt_del_timer(&p->timer);
				}
				njt_http_upstream_dynamic_server_delete_server(p);
				if(p->server->name.len > 0) {
					njt_pfree(njt_cycle->pool,p->server->name.data);
					p->server->name.len = 0;
					p->server->name.data = 0;
				}
				if(p->server->route.len > 0) {
					njt_pfree(njt_cycle->pool,p->server->route.data);
					p->server->route.len = 0;
					p->server->route.data = 0;
				}
				p->upstream_conf  = NULL;
				p->parent_node->id = -1; 
				p->parent_node->parent_id = -1; 
				break;
				
		 }

	 }
}

static njt_http_upstream_dynamic_server_conf_t * njt_http_upstream_allocate_dynamic_server() {
	njt_uint_t i;
	njt_http_upstream_dynamic_server_conf_t       *dynamic_server;
	njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
	njt_list_part_t *part;
	 udsmcf = njt_http_cycle_get_module_main_conf(njt_cycle,
             njt_http_upstream_dynamic_servers_module);
	  if(udsmcf == NULL) {
		return NULL;
	  }
	  part = &udsmcf->dynamic_servers->part;
	  dynamic_server = (njt_http_upstream_dynamic_server_conf_t       *)part->elts;
	
	   for (i = 0; ; i++) {
		if(i >= part->nelts) {
			if(part->next == NULL)
				break;
			part = part->next;
			dynamic_server = part->elts;
			i = 0;
		}
		 if(dynamic_server[i].upstream_conf == NULL) {
			 return &dynamic_server[i];
		 }
	   }
	
	  dynamic_server = (njt_http_upstream_dynamic_server_conf_t       *)njt_list_push(udsmcf->dynamic_servers);
	  if(dynamic_server != NULL) {
		njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));
		dynamic_server->server = NULL;
	  }
	  
	  return dynamic_server;

}
static void njt_http_upstream_check_dynamic_server(njt_event_t *ev)
{
	njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
	njt_http_upstream_srv_conf_t                  *upstream_conf;
	njt_http_upstream_rr_peer_t                   *peer,*pre;
	njt_http_upstream_rr_peers_t                  *peers ;
	njt_http_upstream_server_t                    *us;
	njt_url_t                                     u;
	njt_uint_t                                    i;
	njt_event_t *timer;
	njt_http_upstream_rr_peer_t                   *parent_node;
	njt_http_upstream_main_conf_t                 *umcf;
	njt_http_upstream_srv_conf_t                  **uscfp;
	njt_http_upstream_dynamic_server_conf_t       *dynamic_server = NULL;
	njt_http_upstream_srv_conf_t                  *uscf;
	njt_uint_t                                    refresh_in;
	 udsmcf = njt_http_cycle_get_module_main_conf(njt_cycle,
             njt_http_upstream_dynamic_servers_module);
	if(udsmcf == NULL){
	   return;
	}
	 //upstream_conf = ev->data;
     //peers = upstream_conf->peer.data;
	 if(udsmcf->peers != NULL) {
	 peers = udsmcf->peers;
	 pre = NULL;
	 njt_http_upstream_rr_peers_wlock(peers);
	 for (peer = peers->peer; peer;  peer = peer->next) {
		 if(pre != NULL) {
			 njt_http_upstream_free_peer_memory(peers->shpool,pre);
			 pre = NULL;
		 }
				upstream_conf = NULL;
				if(peer->name.len > 0) {  //zone name !!!!!!!!!!
					umcf = njt_http_cycle_get_module_main_conf(njt_cycle, njt_http_upstream_module);
					uscfp = umcf->upstreams.elts;
					 for (i = 0; i < umcf->upstreams.nelts; i++)
						{
							uscf = uscfp[i];
							if (uscf->host.len == peer->name.len && njt_strncmp(uscf->host.data, peer->name.data, peer->name.len) == 0) {
								upstream_conf = uscf;
								break;
							}
						}

				}
				if(upstream_conf == NULL) {
					pre = peer;
					continue; //
				}
				 njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                      "get a domain message id=%d,parent_id=%d,name=%V,zone=%V!",peer->id,peer->parent_id,&peer->server,&peer->name);
				if(peer->parent_id == (njt_int_t)peer->id && peer->server.data == 0) {  //patch
					njt_http_upstream_modify_dynamic_server(upstream_conf,peer);
					pre = peer;
					continue; //
				}
				else if(peer->parent_id != (njt_int_t)peer->id) {  //delete
					njt_http_upstream_free_dynamic_server(upstream_conf,peer->server,peer->id);
					pre = peer;
					continue; //
				} else {
					dynamic_server = njt_http_upstream_allocate_dynamic_server(); // njt_array_push(&udsmcf->dynamic_servers);
					if (dynamic_server == NULL) {
						pre = peer;
						continue;
					}
					
					if(dynamic_server->server == NULL) {  //new allocte, or reuse
						us = njt_array_push(upstream_conf->servers);  
					} else {
						us = dynamic_server->server;
					}
					if(us == NULL) {
						pre = peer;
						continue; //
					}
					us->name.data = njt_pcalloc(njt_cycle->pool,peer->server.len);
					us->name.len = peer->server.len;
					if(us->name.data == NULL) {
						break;
					}
					us->route.data = njt_pcalloc(njt_cycle->pool,peer->route.len);
					us->route.len = peer->route.len;
					if(us->route.data == NULL) {
						pre = peer;
						continue;
					}
					njt_memcpy(us->name.data, peer->server.data, peer->server.len);
					njt_memcpy(us->route.data, peer->route.data, peer->route.len);

					njt_memzero(&u, sizeof(njt_url_t));
					u.url = us->name;
					u.default_port = 80;
					u.no_resolve = 1;
					u.naddrs = 0;
					u.addrs = NULL;
					njt_parse_url(njt_cycle->pool, &u);

					us->addrs = NULL;// u.addrs;
					us->naddrs =  0; //u.naddrs;
					us->weight = peer->weight;
					us->max_fails = peer->max_fails;
					us->fail_timeout = peer->fail_timeout;
					us->max_conns = peer->max_conns;
					us->slow_start = peer->slow_start;
					us->backup = peer->set_backup;
					us->down = peer->down;
					
					parent_node = dynamic_server->parent_node;
					if(parent_node == NULL) { //reuse
						parent_node = njt_http_upstream_zone_copy_parent_peer(upstream_conf->peer.data,&us->name,us->route,0);
					} else {
						parent_node = njt_http_upstream_zone_init_parent_peer(upstream_conf->peer.data,&us->name,us->route,parent_node);
					}
					if(parent_node == NULL) {
						pre = peer;
                        continue;
					}
					parent_node->id = peer->parent_id;
					parent_node->parent_id = peer->parent_id;

					
					njt_memzero(dynamic_server, sizeof(njt_http_upstream_dynamic_server_conf_t));
					dynamic_server->server = us;
					
					dynamic_server->upstream_conf = upstream_conf;
					dynamic_server->host = u.host;
					dynamic_server->port = (in_port_t)(u.no_port ? u.default_port : u.port);
					dynamic_server->parent_node = parent_node;
					
					
					
					dynamic_server->parent_node->fail_timeout = us->fail_timeout;
					dynamic_server->parent_node->max_conns = us->max_conns;
					dynamic_server->parent_node->max_fails = us->max_fails;
					dynamic_server->parent_node->slow_start = us->slow_start;
					dynamic_server->parent_node->weight = us->weight;
					dynamic_server->parent_node->down = us->down;
					//dynamic_server->parent_node->set_down = us->down;
					dynamic_server->parent_node->set_backup = us->backup;
					dynamic_server->parent_node->hc_down = peer->hc_down;
				
					timer = &dynamic_server->timer;
					if(timer->handler == NULL) {
						
						timer->handler = njt_http_upstream_dynamic_server_resolve;
						timer->log = njt_cycle->log;
						timer->data = dynamic_server;
						timer->cancelable = 1;
						refresh_in = njt_random() % 1000;
						njt_http_upstream_dynamic_server_resolve(timer);
						//njt_add_timer(timer, refresh_in);
					}
				}
			


			pre = peer;
	  }
	   if(pre != NULL) {
			  njt_http_upstream_free_peer_memory(peers->shpool,pre);
		 }
	  peers->peer = NULL;
	  peers->number = 0;
	  njt_http_upstream_rr_peers_unlock(peers);
	 }
	 refresh_in = njt_random() % 1000;
	 njt_add_timer(&udsmcf->timer, refresh_in);
}

static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_init_parent_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,njt_str_t route,njt_http_upstream_rr_peer_t *parent_node)
{
	//njt_http_upstream_rr_peer_t        *tail_peer;   
    njt_slab_pool_t              *pool;
    njt_http_upstream_rr_peer_t  *dst;
  

    pool = peers->shpool;
    if (pool == NULL) {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);

		dst = parent_node;
		if(dst->server.data) {
			njt_slab_free_locked(pool,dst->server.data);
		} 
		dst->server.len = server->len;
		dst->server.data = njt_slab_calloc_locked(pool,dst->server.len);
		if(dst->server.data == NULL) {
					 goto failed;
			 }
		 njt_memcpy(dst->server.data,server->data,server->len);
		
		if(dst->route.data) {
			njt_slab_free_locked(pool,dst->route.data);
		}

        dst->route.len = route.len;
        if(dst->route.len > 0) {
                dst->route.data = njt_slab_alloc_locked(pool, dst->route.len);
                if (dst->route.data == NULL) {
                        goto failed;
                }
                njt_memcpy(dst->route.data, route.data, route.len);
        }
	
	
    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}

static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_parent_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,njt_str_t route,njt_int_t alloc_id)
{
	//njt_http_upstream_rr_peer_t        *tail_peer;   
    njt_slab_pool_t              *pool;
    njt_http_upstream_rr_peer_t  *dst;
  

    pool = peers->shpool;
    if (pool == NULL) {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);
    dst = njt_slab_calloc_locked(pool, sizeof(njt_http_upstream_rr_peer_t));
    if (dst == NULL) {
        njt_shmtx_unlock(&pool->mutex);
        return NULL;
    }

		dst->server.len = server->len;
		dst->server.data = njt_slab_calloc_locked(pool,dst->server.len);
		if(dst->server.data == NULL) {
					 goto failed;
			 }
		 njt_memcpy(dst->server.data,server->data,server->len);
		
        dst->route.len = route.len;
        if(dst->route.len > 0) {
                dst->route.data = njt_slab_alloc_locked(pool, dst->route.len);
                if (dst->route.data == NULL) {
                        goto failed;
                }
                njt_memcpy(dst->route.data, route.data, route.len);
        }
		if(alloc_id == 1) {
			dst->id = peers->next_order ++;
		}
		dst->next = NULL;
		if(peers->parent_node == NULL) {
			peers->parent_node = dst;
		} else {
			dst->next = peers->parent_node;
			peers->parent_node = dst;
			//for(tail_peer = peers->parent_node;tail_peer->next != NULL; tail_peer = tail_peer->next);
			//tail_peer->next = dst;
		}
    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
	njt_http_upstream_free_peer_memory(pool,dst);
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}


/*
static void *
njt_http_upstream_dynamic_server_set_status(njt_http_upstream_dynamic_server_conf_t *dynamic_server)
{
	njt_http_upstream_rr_peer_t        *tail_peer;   
    njt_slab_pool_t              *pool;
    njt_http_upstream_rr_peer_t  *dst;
    u_char                                                 *last,*port;
	njt_http_upstream_srv_conf_t *upstream_conf;
	njt_http_upstream_rr_peers_t                  *peers ;


    upstream_conf = dynamic_server->upstream_conf;
	peers = upstream_conf->peer.data;

	njt_http_upstream_rr_peers_wlock(peers);
	if(peers->parent_node == NULL) {
			return;
		} else {
			for(tail_peer = peers->parent_node;tail_peer->next != NULL; tail_peer = tail_peer->next);
			 if(tail_peer == dynamic_server->parent_node) {
				 tail_peer ->parent_node = NULL;
				 break;
			 }
		}
	njt_http_upstream_rr_peers_unlock(peers);
}
*/

static void njt_http_upstream_dynamic_server_resolve(njt_event_t *ev)
{

   // njt_http_upstream_dynamic_server_main_conf_t  *udsmcf;
    njt_http_upstream_dynamic_server_conf_t *dynamic_server;
    njt_resolver_ctx_t *ctx;
	njt_http_upstream_srv_conf_t *upstream_conf;
	njt_http_upstream_rr_peers_t                  *peers ;
	//njt_http_upstream_rr_peer_t                   *parent_peer;
	njt_http_upstream_server_t  *us;


    dynamic_server = ev->data;
	upstream_conf = dynamic_server->upstream_conf;
	if(upstream_conf->resolver == NULL) {
		njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver null for '%V'",
                      &dynamic_server->host);
		return;
	}

	peers = upstream_conf->peer.data;
	us = dynamic_server->server;
	if(dynamic_server->parent_node == NULL) {
		 dynamic_server->parent_node = njt_http_upstream_zone_copy_parent_peer(peers,&us->name,us->route,0);
		 if(dynamic_server->parent_node == NULL) {
				njt_log_error(NJT_LOG_ALERT, ev->log, 0,
						  "allocate njt_http_upstream_zone_copy_parent_peer error for '%V'",
						  &dynamic_server->host);
				return;
				
		 } 
		 dynamic_server->parent_node->id = us->parent_id;
		 dynamic_server->parent_node->parent_id = us->parent_id;
		 
		dynamic_server->parent_node->fail_timeout = us->fail_timeout;
		dynamic_server->parent_node->max_conns = us->max_conns;
		dynamic_server->parent_node->max_fails = us->max_fails;
		dynamic_server->parent_node->slow_start = us->slow_start;
		dynamic_server->parent_node->weight = us->weight;
		dynamic_server->parent_node->down = us->down;
		dynamic_server->parent_node->set_backup = us->backup;
		//dynamic_server->parent_node->set_down = us->down;
		dynamic_server->parent_node->hc_down = (upstream_conf->hc_type == 0 ?0:2);  //(upstream_conf->hc_type == 0 ?0:2)
		
	}
	
	 
		 
       
    ctx = njt_resolve_start(upstream_conf->resolver, NULL);
    if (ctx == NULL) {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: resolver start error for '%V'",
                      &dynamic_server->host);
        return;
    }

    if (ctx == NJT_NO_RESOLVER) {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: no resolver defined to resolve '%V'",
                      &dynamic_server->host);
        return;
    }

    ctx->name = dynamic_server->host;
    ctx->handler = njt_http_upstream_dynamic_server_resolve_handler;
    ctx->data = dynamic_server;
    ctx->timeout = upstream_conf->resolver_timeout;

    njt_log_debug(NJT_LOG_DEBUG_CORE, ev->log, 0,
                  "upstream-dynamic-servers: Resolving '%V'", &ctx->name);
    if (njt_resolve_name(ctx) != NJT_OK) {
        njt_log_error(NJT_LOG_ALERT, ev->log, 0,
                      "upstream-dynamic-servers: njt_resolve_name failed for '%V'", &ctx->name);

        njt_add_timer(&dynamic_server->timer, 1000);
    }
}

static njt_http_upstream_rr_peer_t *
njt_http_upstream_zone_copy_peer(njt_http_upstream_rr_peers_t *peers,
                                 njt_str_t *server,
                                 njt_str_t *host, in_port_t port, struct sockaddr *sockaddr, socklen_t socklen,njt_str_t route)
{
    //size_t                        plen;
    njt_slab_pool_t              *pool;
    njt_http_upstream_rr_peer_t  *dst;

    pool = peers->shpool;
    if (pool == NULL) {
        return NULL;
    }

    njt_shmtx_lock(&pool->mutex);
    dst = njt_slab_calloc_locked(pool, sizeof(njt_http_upstream_rr_peer_t));
    if (dst == NULL) {
        njt_shmtx_unlock(&pool->mutex);
        return NULL;
    }

    dst->socklen  = socklen;
    dst->sockaddr = NULL;
    dst->name.data = NULL;
    dst->server.data = NULL;
	
    if (server == NULL) {
		/*
        if (port > 1 && port < 10) {
            plen = 1;
        } else if (port < 100) {
            plen = 2;
        } else if (port < 1000) {
            plen = 3;
        } else if (port < 10000) {
            plen = 4;
        } else {
            plen = 5;
        }
        dst->server.len = host->len + 1 + plen;
		*/
		dst->server.len = host->len;

    } else {
        dst->server.len = server->len;
    }

    dst->sockaddr = njt_slab_calloc_locked(pool, sizeof(njt_sockaddr_t));
    if (dst->sockaddr == NULL) {
        goto failed;
    }

    dst->name.data = njt_slab_calloc_locked(pool, NJT_SOCKADDR_STRLEN);
    if (dst->name.data == NULL) {
        goto failed;
    }


    njt_memcpy(dst->sockaddr, sockaddr, socklen);
    njt_inet_set_port(dst->sockaddr, port);
    dst->name.len = njt_sock_ntop(dst->sockaddr, socklen, dst->name.data,
                                  NJT_SOCKADDR_STRLEN, 1);
	dst->route.len = route.len; 
	if(dst->route.len > 0) { 
		dst->route.data = njt_slab_alloc_locked(pool, dst->route.len);
		if (dst->route.data == NULL) {
			goto failed;
		}
		njt_memcpy(dst->route.data, route.data, route.len);
	}
    dst->server.data = njt_slab_alloc_locked(pool, dst->server.len);
    if (dst->server.data == NULL) {
        goto failed;
    }

    if (server == NULL) {
        njt_memcpy(dst->server.data, host->data, host->len);
        //njt_sprintf(dst->server.data + host->len, ":%d", port);

    } else {
        njt_memcpy(dst->server.data, server->data, server->len);
    }
    njt_shmtx_unlock(&pool->mutex);
    return dst;

failed:
	njt_http_upstream_free_peer_memory(pool,dst);
    njt_shmtx_unlock(&pool->mutex);

    return NULL;
}

static njt_int_t
njt_http_resolve_cmp_nodes(const void *one, const void *two)
{
    return njt_memcmp(one, two, sizeof(struct sockaddr));
}


static void njt_http_upstream_dynamic_server_resolve_handler(
    njt_resolver_ctx_t *ctx)
{
    njt_http_upstream_dynamic_server_conf_t       *dynamic_server;
    njt_http_upstream_srv_conf_t                  *us;
    njt_uint_t                                    i, naddrs;
    struct sockaddr                               *sockaddr;
    uint32_t                                      refresh_in;
    time_t                                        fail_timeout;
    njt_int_t                                     weight, max_conns, max_fails,slow_start,down,hc_down;
    njt_str_t                                     name;
    in_port_t                                     port;
    njt_http_upstream_rr_peer_t                   *peer, *next, *prev,*tail_peer;
    njt_http_upstream_rr_peers_t                  *peers,*peers_data;
    uint32_t                                      crc32;
    njt_int_t									   rc = NJT_OK;
    njt_msec_t now_time;;
    if (njt_quit || njt_exiting || njt_terminate) {
        njt_log_debug(NJT_LOG_DEBUG_CORE, njt_cycle->log, 0,
                      "upstream-dynamic-servers: worker is about to exit, do not set the timer again");
        return;
    }

    njt_log_debug(NJT_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                  "upstream-dynamic-servers: Finished resolving '%V'", &ctx->name);

    dynamic_server = ctx->data;

    naddrs = ctx->naddrs;
    if (ctx->naddrs == 0 || ctx->addrs == NULL || ctx->state) {
		
        njt_log_debug(NJT_LOG_DEBUG_CORE, ctx->resolver->log, 0,
                      "naddrs and dns state %d %d.", ctx->naddrs, ctx->state);
        /*reset the recorded data*/

        dynamic_server->count = 0;
        dynamic_server->crc32 = 0;
        if (dynamic_server->count != 0 || dynamic_server->crc32 != 0) {
            /*Try to delete all the peers of the resolver name*/
            goto operation;
        }

        goto end;
    }

    /* check if the result changed or not*/
    sockaddr = njt_calloc(ctx->naddrs * sizeof(struct sockaddr),
                          ctx->resolver->log);
    if (sockaddr == NULL) {
        goto end;
    }

    for (i = 0; i < naddrs; i++) {

        switch (ctx->addrs[i].sockaddr->sa_family) {
        case AF_INET6:
            ((struct sockaddr_in6 *)ctx->addrs[i].sockaddr)->sin6_port = htons((u_short)
                    dynamic_server->port);
            break;

        default:
            ((struct sockaddr_in *)ctx->addrs[i].sockaddr)->sin_port = htons((u_short)
                    dynamic_server->port);
        }

        njt_memcpy(&sockaddr[i], ctx->addrs[i].sockaddr, sizeof(struct sockaddr));
    }

    /*calculate the crc*/
    njt_sort((void *)sockaddr, ctx->naddrs, sizeof(struct sockaddr),
             njt_http_resolve_cmp_nodes);
    njt_crc32_init(crc32);
    for (i = 0 ; i < naddrs; i ++) {
        njt_crc32_update(&crc32, (u_char *)&sockaddr[i], sizeof(struct sockaddr));
    }
    njt_crc32_final(crc32);
    njt_free(sockaddr);

        /*further compare the value*/
        if (dynamic_server->count == naddrs && dynamic_server->crc32 == crc32) {
            //njt_log_error(NJT_LOG_ALERT, ctx->resolver->log, 0,
              //            "upstream-dynamic-servers: DNS result isn't changed '%V'", &ctx->name);
            goto end;
        } else {
            njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,
                          "upstream-dynamic-servers: DNS result is changed '%V' num=%d", &ctx->name,naddrs);
        }

    dynamic_server->count = naddrs;
    dynamic_server->crc32 = crc32;

operation:
	
    us = dynamic_server->upstream_conf;
    peers = us->peer.data;

    /*resolve must coexist with share memory*/
    if (peers->shpool) {
        /*Try to copy the peers to the shared memory zone*/
		rc = NJT_OK;
        fail_timeout = dynamic_server->parent_node->fail_timeout;
        weight = dynamic_server->parent_node->weight;
        max_conns = dynamic_server->parent_node->max_conns;
        max_fails = dynamic_server->parent_node->max_fails;
	slow_start = dynamic_server->parent_node->slow_start;
	down = dynamic_server->parent_node->down;
        name = ctx->name;
        port = dynamic_server->port;
	    hc_down = dynamic_server->parent_node->hc_down;

        if(us->mandatory == 1) {  //zyg use upstream  hc_type
          hc_down = 2;
        }

		peers_data = (dynamic_server->server->backup > 0?peers->next:peers);

        njt_http_upstream_rr_peers_wlock(peers);
        for (peer = peers_data->peer, prev = NULL; peer;  peer = next) {
			
            next = peer->next;
            if (njt_strncmp(peer->server.data, name.data, name.len) != 0
                || njt_inet_get_port(peer->sockaddr) != port) {
                prev = peer;
                continue;
            }
			rc = NJT_OK;
		 
			if (peer->parent_id != (njt_int_t)dynamic_server->parent_node->id) {
			   prev = peer;
			   continue;
			}
			
          
			//if(peer->parent_node == NULL) {
			//	peer->parent_node = dynamic_server->parent_node;
			//}
            for (i = 0; i < naddrs; ++i) {
                /*The IP does not change. keep this peer.*/
                if (njt_cmp_sockaddr(peer->sockaddr, peer->socklen, ctx->addrs[i].sockaddr,
                                     ctx->addrs[i].socklen, 1) == 0) {
                    prev = peer;
                    goto skip_del;
                }
            }

            if (prev == NULL) {
                peers_data->peer = next;
            } else {
                prev->next = next;
            }

            peers_data->number--;
	    if(peer->down == 0 && peers_data->tries > 0){
		peers_data->tries--;
	    }
            peers_data->total_weight -= weight;
            /*The IP is not exists, down or free this peer.*/
            if (peer->conns > 0) {
                peer->down = 1;
                peer->del_pending = 1;
            } else {
                njt_shmtx_lock(&peers_data->shpool->mutex);
                njt_http_upstream_free_peer_memory(peers_data->shpool, peer);
                njt_shmtx_unlock(&peers_data->shpool->mutex);
            }
skip_del:
            continue;
        }
		if( rc != NJT_ERROR && dynamic_server->parent_node->parent_id != -1) {


			now_time = njt_time();			
			for (i = 0; i < naddrs; ++i) {
				for (peer = peers_data->peer; peer; peer = peer->next) {
					/* The IP have exists. update the expire.*/
					if (njt_cmp_sockaddr(peer->sockaddr, peer->socklen, ctx->addrs[i].sockaddr,
										 ctx->addrs[i].socklen, 1) == 0 && peer->parent_id == (njt_int_t)dynamic_server->parent_node->id) {
						goto skip_add;
					}
				}

				peer = njt_http_upstream_zone_copy_peer(peers, NULL, &dynamic_server->parent_node->server, port,
														ctx->addrs[i].sockaddr, ctx->addrs[i].socklen,dynamic_server->parent_node->route);
				if (peer == NULL) {
					continue;
				}
				peer->fail_timeout = fail_timeout;
				peer->max_conns = max_conns;
				peer->max_fails = max_fails;
				peer->slow_start = slow_start;
				//peer->dynamic = 1;
				peer->id = peers->next_order ++;
				peer->weight = weight;
				peer->effective_weight = weight;
				peer->rr_effective_weight = weight *NJT_WEIGHT_POWER;
				peer->current_weight   = 0;
				peer->rr_current_weight   = 0;
				peer->down = down;
				//peer->set_down = down;
				peer->hc_down = hc_down;
				peer->hc_upstart = now_time;
				peer->next = NULL;
				//peer->parent_node = dynamic_server->parent_node;
				peer->parent_id = dynamic_server->parent_node->id;
				peers_data->number++;
				if(peer->down == 0 ){
             			   peers_data->tries++;
            			}
				peers_data->total_weight += weight;
				//peers_data->empty = (peers_data->number == 0);
				if(peers_data->peer == NULL) {
					peers_data->peer = peer;
				} else {
					for(tail_peer = peers_data->peer;tail_peer->next != NULL; tail_peer = tail_peer->next);
					tail_peer->next = peer;
				}
				

				
skip_add:
				continue;
			}
		} 

        peers_data->single = (peers_data->number <= 1);
	peers->single = (peers->number + peers->next->number <= 1);
    	peers->update_id++;	
        njt_http_upstream_rr_peers_unlock(peers);
    }

end:


    refresh_in = 1000;
    if (ctx->valid) {
        refresh_in = ctx->valid - njt_time();
        refresh_in  *= 1000;
        refresh_in = refresh_in > 1000 ? refresh_in : 1000;
		if(dynamic_server->valid != 0) {
			refresh_in = dynamic_server->valid * 1000;
		}
		
    }
	if( rc != NJT_ERROR) {
		njt_add_timer(&dynamic_server->timer, refresh_in);
	} else {
		//njt_http_upstream_free_dynamic_server(dynamic_server->upstream_conf,dynamic_server->server->name,dynamic_server->parent_node->id);
		
	}
    njt_resolve_name_done(ctx);

    return;
}


static void njt_http_upstream_dynamic_server_delete_server(
    njt_http_upstream_dynamic_server_conf_t *dynamic_server)
{
	
    njt_http_upstream_srv_conf_t                  *us;
    njt_str_t                                     name;
    njt_http_upstream_rr_peer_t                   *peer, *next, *prev;
    njt_http_upstream_rr_peers_t                  *peers;
    us = dynamic_server->upstream_conf;
	name = dynamic_server->server->name;
    peers = us->peer.data;

    /*resolve must coexist with share memory*/
    if (peers->shpool) {
        njt_http_upstream_rr_peers_wlock(peers);
        for (peer = peers->peer, prev = NULL; peer;  peer = next) {
			
            next = peer->next;
            if (njt_strncmp(peer->server.data, name.data, name.len) != 0) {
                prev = peer;
                continue;
            }
		
			if (peer->parent_id != (njt_int_t)dynamic_server->parent_node->id) {
			   prev = peer;
			   continue;
			}

            if (prev == NULL) {
                peers->peer = next;
            } else {
                prev->next = next;
            }

            peers->number--;
	    if(peer->down == 0 && peers->tries > 0){
		peers->tries--;
	    }
            peers->total_weight -= dynamic_server->server->weight;
            /*The IP is not exists, down or free this peer.*/
            if (peer->conns > 0) {
                peer->down = 1;
                peer->del_pending = 1;
            } else {
                njt_shmtx_lock(&peers->shpool->mutex);
                njt_http_upstream_free_peer_memory(peers->shpool, peer);
                njt_shmtx_unlock(&peers->shpool->mutex);
            }
        }
        peers->single = (peers->number + peers->next->number <= 1);
    	peers->update_id++;	
        njt_http_upstream_rr_peers_unlock(peers);
    }
    return;
}

static char *njt_http_upstream_check(njt_conf_t *cf, njt_command_t *cmd,
                                   void *conf)
{
    njt_uint_t                         i;
    njt_http_upstream_srv_conf_t                  *uscf;
    njt_str_t                   *value;

	uscf = njt_http_conf_get_module_srv_conf(cf, njt_http_upstream_module);
	if(uscf == NULL){
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "no find njt_http_upstream_module!");
		return NJT_CONF_ERROR;
	}
	uscf->hc_type = 0;
	value = cf->args->elts;
	for (i = 1; i < cf->args->nelts; i++) {
		if (njt_strncmp(value[i].data, "mandatory", 9) == 0) {
		    uscf->mandatory = 1;
		    continue;
		}
		if (njt_strncmp(value[i].data, "persistent", 10) == 0) {
		    uscf->persistent = 1;
		    continue;
		}
		 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid parameter: %V", &value[i]);
		return NJT_CONF_ERROR;
	}
	if(uscf->persistent == 1 && uscf->mandatory != 1) {
		njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "persistent need mandatory seted !");
	}
	if(uscf->persistent == 1 && uscf->mandatory == 1){
		uscf->hc_type = 2;
	} else  if(uscf->mandatory == 1) {
		uscf->hc_type = 1;
	}
  return NJT_CONF_OK;
}
