/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njt_stream.h>
#include <sys/socket.h>
#include <linux/netfilter_ipv4.h>




static njt_int_t njt_stream_proto_dest_variable(njt_stream_session_t *s,njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_proto_ip_variable(njt_stream_session_t *s,njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_proto_port_variable(njt_stream_session_t *s,njt_stream_variable_value_t *v, uintptr_t data);
static njt_int_t njt_stream_proto_add_variables(njt_conf_t *cf);
static njt_int_t njt_stream_proto_init(njt_conf_t *cf);
static void *njt_stream_proto_create_srv_conf(njt_conf_t *cf);
static char *njt_stream_proto_merge_srv_conf(njt_conf_t *cf, void *parent, void *child);
static njt_int_t njt_stream_preread_proto_variable(njt_stream_session_t *s,  //
    njt_variable_value_t *v, uintptr_t data);
static njt_int_t
njt_stream_preread_parse_record(njt_stream_proto_ctx_t *ctx,
    u_char *pos, u_char *last);
static njt_int_t njt_stream_nginmesh_dest_handler(njt_stream_session_t *s);
static njt_int_t
njt_stream_preread_proto_handler(njt_stream_session_t *s);



/**
 * This module provide callback to istio for http traffic
 *
 */
static njt_command_t njt_stream_proto_commands[] = {

    {
      njt_string("njtmesh_dest"),
      NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_FLAG,
      njt_conf_set_flag_slot,     // do custom config
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proto_srv_conf_t, enabled),
      NULL
    },
    {
      njt_string("njtmesh_port_mode"),
      NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_TAKE2,
      njt_conf_set_keyval_slot,     // do custom config
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proto_srv_conf_t,proto_ports),
      NULL
    },
	 {
      njt_string("preread_proto"),
      NJT_STREAM_MAIN_CONF | NJT_STREAM_SRV_CONF | NJT_CONF_FLAG,
      njt_conf_set_flag_slot,     // do custom config
      NJT_STREAM_SRV_CONF_OFFSET,
      offsetof(njt_stream_proto_srv_conf_t, proto_enabled),
      NULL
    },
    njt_null_command /* command termination */
};




/* The module context. */
static njt_stream_module_t njt_stream_proto_module_ctx = {
    njt_stream_proto_add_variables, /* preconfiguration */
    njt_stream_proto_init, /* postconfiguration */
    NULL,
    NULL, /* init main configuration */
    njt_stream_proto_create_srv_conf, /* create server configuration */
    njt_stream_proto_merge_srv_conf /* merge server configuration */

};

/* Module definition. */
njt_module_t njt_stream_proto_module = {
    NJT_MODULE_V1,
    &njt_stream_proto_module_ctx, /* module context */
    njt_stream_proto_commands, /* module directives */
    NJT_STREAM_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NJT_MODULE_V1_PADDING
};

// list of variables to add
static njt_stream_variable_t  njt_stream_proto_vars[] = {

    { njt_string("njtmesh_dest"), NULL,
      njt_stream_proto_dest_variable, 0, 0, 0 },
    { njt_string("njtmesh_ip"), NULL,
      njt_stream_proto_ip_variable, 0, 0, 0 },
    { njt_string("njtmesh_port"), NULL,
      njt_stream_proto_port_variable, 0, 0, 0 },
    { njt_string("preread_proto"), NULL,
      njt_stream_preread_proto_variable, 0, 0, 0 },
    njt_stream_null_variable
};



static void *njt_stream_proto_create_srv_conf(njt_conf_t *cf)
{
    njt_stream_proto_srv_conf_t  *conf;

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "nginmeshdest create serv config");

    conf = njt_pcalloc(cf->pool, sizeof(njt_stream_proto_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NJT_CONF_UNSET;
    conf->proto_ports = NJT_CONF_UNSET_PTR;
    return conf;
}


static char *njt_stream_proto_merge_srv_conf(njt_conf_t *cf, void *parent, void *child)
{

    njt_log_debug(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "nginmeshdest merge serv config");

    njt_stream_proto_srv_conf_t *prev = parent;
    njt_stream_proto_srv_conf_t *conf = child;

    njt_conf_merge_value(conf->enabled, prev->enabled, 0);
    njt_conf_merge_ptr_value(conf->proto_ports,
                              prev->proto_ports, NULL);
    return NJT_CONF_OK;
}


 njt_int_t njt_stream_handler(njt_stream_session_t *s)
{
	njt_connection_t                    *c;
	njt_stream_proto_ctx_t           *ctx;
	 njt_stream_proto_srv_conf_t  *sscf;
	 njt_int_t  rc = NJT_DECLINED;
	 njt_int_t  rc_http = NJT_DECLINED;
	 njt_http_request_t  r;
	 u_char          *pos;

	 c = s->connection;

	 sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_module);
	 if(sscf == NULL) {
		 return NJT_DECLINED;
	 }

	if (!sscf->enabled) {
        return NJT_DECLINED;
    }
	if (c->type != SOCK_STREAM) {
        return NJT_DECLINED;
    }
	ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);
	if(ctx && ctx->complete == 1) {
		return NJT_OK;
	}
    if (c->buffer == NULL) {
        return NJT_AGAIN;
    }
	
    if (ctx == NULL) {
        ctx = njt_pcalloc(c->pool, sizeof(njt_stream_proto_ctx_t));
        if (ctx == NULL) {
            return NJT_ERROR;
        }

        njt_stream_set_ctx(s, ctx, njt_stream_proto_module);
        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = c->buffer->pos;
	ctx->complete = 0;
	njt_stream_nginmesh_dest_handler(s);
    }
	if(ctx->complete == 1){
		return NJT_OK;
	}
	rc = njt_stream_preread_proto_handler(s);
	if(rc == NJT_OK) {
		ctx->complete = 1;
		 ctx->ssl = 1;
		return NJT_OK;
	} else if (rc == NJT_DECLINED) {
		
		njt_memzero(&r,sizeof(njt_http_request_t));
		r.header_in = s->connection->buffer;
		pos = s->connection->buffer->pos;

		 rc_http = njt_http_parse_request_line(&r,r.header_in);
		 s->connection->buffer->pos = pos;
		  if(rc_http == NJT_OK) {
			  ctx->complete = 1;
			   ctx->ssl = 0;
			  njt_str_set(&ctx->proto,"http");
			  return NJT_OK;
		  } 
	}
	if(rc == NJT_AGAIN || rc_http == NJT_AGAIN) {
		return NJT_AGAIN;
	}
	ctx->ssl = 2;
	ctx->complete = 1;
	return NJT_OK;
}

static njt_int_t njt_stream_nginmesh_dest_handler(njt_stream_session_t *s)
{

    struct sockaddr_storage             org_src_addr;
    socklen_t                           org_src_addr_len;
    njt_connection_t                    *c;
    njt_stream_proto_ctx_t           *ctx;
    char *paddr;
    njt_uint_t port,nelts,i;
    u_char *p;
    njt_keyval_t      *kv;
    njt_stream_proto_srv_conf_t  *sscf;
    struct sockaddr_in *addr_in;
    njt_int_t  rc = NJT_OK;
	

    c = s->connection;
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);
    sscf = njt_stream_get_module_srv_conf(s, njt_stream_proto_module);	
	njt_memzero(&org_src_addr, sizeof(struct sockaddr));
	 org_src_addr_len =  sizeof(struct sockaddr);
	if(getsockopt ( c->fd, SOL_IP, SO_ORIGINAL_DST, &org_src_addr,&org_src_addr_len) == -1) {
	   int n = errno;
	   printf("%d",n);
	} else {
		njt_log_debug1(NJT_LOG_DEBUG_STREAM, s->connection->log,0, "ip address length %d",org_src_addr_len);
		if(org_src_addr.ss_family == AF_INET )  {
		   addr_in = (struct sockaddr_in *)&org_src_addr;
		   paddr = inet_ntoa(addr_in->sin_addr);
		   port = ntohs(addr_in->sin_port);
		   ctx->dest.data = njt_pnalloc(ctx->pool,46);
		   if(ctx->dest.data != NULL) {
			ctx->dest.len = 46;
		   	njt_memzero(ctx->dest.data,ctx->dest.len);
			ctx->dest_ip.data = ctx->dest.data;
			p  = njt_sprintf(ctx->dest.data,"%s",paddr);
			ctx->dest_ip.len = p - ctx->dest.data;
			ctx->dest_port.data = p + 1;

			p  = njt_sprintf(p,":%d",port);
			ctx->dest.len = p - ctx->dest.data;
			ctx->dest_port.len = p - ctx->dest_port.data;
			njt_str_set(&ctx->port_mode,"none");
			 if(sscf->proto_ports != NULL) {
			 	kv = sscf->proto_ports->elts;
				 nelts = sscf->proto_ports->nelts;	
				 for (i = 0; i < nelts; i++) {
				   if(kv[i].key.len == ctx->dest_port.len && njt_strncmp(kv[i].key.data,ctx->dest_port.data,kv[i].key.len) == 0) {
					ctx->port_mode = kv[i].value;
					break;
				   }		   
				 }
			 } 
		   }
		}
	}
	 njt_log_debug(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                   "assignment njtmesh_dest: %V",&ctx->dest);

	return rc;

}

// assign variable from ctx
static njt_int_t njt_stream_preread_proto_variable(njt_stream_session_t *s,  //
    njt_variable_value_t *v, uintptr_t data)
{
   njt_str_t                      version;
    njt_stream_proto_ctx_t  *ctx;
	njt_connection_t            *c;
	njt_stream_proto_srv_conf_t  *conf;

	conf = njt_stream_get_module_srv_conf(s, njt_stream_proto_module);


	c = s->connection;
    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    /* SSL_get_version() format */

    njt_str_null(&version);

    switch (ctx->version[0]) {
    case 0:
        switch (ctx->version[1]) {
        case 2:
            njt_str_set(&version, "SSLv2");
            break;
        }
        break;
    case 3:
        switch (ctx->version[1]) {
        case 0:
            njt_str_set(&version, "SSLv3");
            break;
        case 1:
            njt_str_set(&version, "TLSv1");
            break;
        case 2:
            njt_str_set(&version, "TLSv1.1");
            break;
        case 3:
            njt_str_set(&version, "TLSv1.2");
            break;
        case 4:
            njt_str_set(&version, "TLSv1.3");
            break;
        }
    }
	if(!conf->proto_enabled && version.len != 0) {
			 njt_str_set(&version, "https");
	 }

	if(version.len == 0) {
		version = ctx->proto;
	} 
	if(version.len == 0 && c->type == SOCK_STREAM) {
		 njt_str_set(&version, "tcp");
	}
	if(version.len == 0 && c->type == SOCK_DGRAM) {
		 njt_str_set(&version, "udp");
	}
	
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = version.len;
    v->data = version.data;

    return NJT_OK;
}


// assign variable from ctx
static njt_int_t njt_stream_proto_dest_variable(njt_stream_session_t *s,  //
    njt_variable_value_t *v, uintptr_t data)
{
    njt_stream_proto_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->dest.len;
    v->data = ctx->dest.data;

    njt_log_debug(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                   "get variable njtmesh_dest: %V",&ctx->dest);

    return NJT_OK;
}

static njt_int_t njt_stream_proto_ip_variable(njt_stream_session_t *s,  //
    njt_variable_value_t *v, uintptr_t data)
{
    njt_stream_proto_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->dest_ip.len;
    v->data = ctx->dest_ip.data;

    njt_log_debug(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                   "get variable njtmesh_dest: %V",&ctx->dest);

    return NJT_OK;
}

static njt_int_t njt_stream_proto_port_variable(njt_stream_session_t *s,  //
    njt_variable_value_t *v, uintptr_t data)
{
    njt_stream_proto_ctx_t  *ctx;

    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return NJT_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->dest_port.len;
    v->data = ctx->dest_port.data;

    njt_log_debug(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                   "get variable njtmesh_dest_port: %V",&ctx->dest);

    return NJT_OK;
}
static njt_int_t njt_stream_proto_add_variables(njt_conf_t *cf)
{
    njt_stream_variable_t  *var, *v;


    for (v = njt_stream_proto_vars; v->name.len; v++) {
        njt_log_debug2(NJT_LOG_DEBUG_EVENT, njt_cycle->log, 0, "ngin mesh var initialized: %*s",v->name.len,v->name.data);
        var = njt_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NJT_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NJT_OK;
}


static njt_int_t
njt_stream_preread_proto_handler(njt_stream_session_t *s)
{
    u_char                             *last, *p;
    size_t                              len;
    njt_int_t                           rc;
    njt_connection_t                   *c;
    njt_stream_proto_ctx_t       *ctx;
 

    c = s->connection;

    njt_log_debug0(NJT_LOG_DEBUG_STREAM, c->log, 0, "ssl preread handler");


    ctx = njt_stream_get_module_ctx(s, njt_stream_proto_module);
    p = ctx->pos;
    last = c->buffer->last;

    while (last - p >= 5) {

        if ((p[0] & 0x80) && p[2] == 1 && (p[3] == 0 || p[3] == 3)) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: version 2 ClientHello");
            ctx->version[0] = p[3];
            ctx->version[1] = p[4];
            return NJT_OK;
        }

        if (p[0] != 0x16) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: not a handshake");
            //njt_stream_set_ctx(s, NULL, njt_stream_proto_module);
            return NJT_DECLINED;
        }

        if (p[1] != 3) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: unsupported SSL version");
            //njt_stream_set_ctx(s, NULL, njt_stream_proto_module);
            return NJT_DECLINED;
        }

        len = (p[3] << 8) + p[4];

        /* read the whole record before parsing */
        if ((size_t) (last - p) < len + 5) {
            break;
        }

        p += 5;

        rc = njt_stream_preread_parse_record(ctx, p, p + len);

        if (rc == NJT_DECLINED) {
            //njt_stream_set_ctx(s, NULL, njt_stream_proto_module);
            return NJT_DECLINED;
        }

        if (rc != NJT_AGAIN) {
            return rc;
        }

        p += len;
    }

    ctx->pos = p;

    return NJT_AGAIN;
}




static njt_int_t
njt_stream_preread_parse_record(njt_stream_proto_ctx_t *ctx,
    u_char *pos, u_char *last)
{
    size_t   left, n, size, ext;
    u_char  *dst, *p;

    enum {
        sw_start = 0,
        sw_header,          /* handshake msg_type, length */
        sw_version,         /* client_version */
        sw_random,          /* random */
        sw_sid_len,         /* session_id length */
        sw_sid,             /* session_id */
        sw_cs_len,          /* cipher_suites length */
        sw_cs,              /* cipher_suites */
        sw_cm_len,          /* compression_methods length */
        sw_cm,              /* compression_methods */
        sw_ext,             /* extension */
        sw_ext_header,      /* extension_type, extension_data length */
        sw_sni_len,         /* SNI length */
        sw_sni_host_head,   /* SNI name_type, host_name length */
        sw_sni_host,        /* SNI host_name */
        sw_alpn_len,        /* ALPN length */
        sw_alpn_proto_len,  /* ALPN protocol_name length */
        sw_alpn_proto_data, /* ALPN protocol_name */
        sw_supver_len       /* supported_versions length */
    } state;

    njt_log_debug2(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                   "ssl preread: state %ui left %z", ctx->state, ctx->left);

    state = ctx->state;
    size = ctx->size;
    left = ctx->left;
    ext = ctx->ext;
    dst = ctx->dst;
    p = ctx->buf;

    for ( ;; ) {
        n = njt_min((size_t) (last - pos), size);

        if (dst) {
            dst = njt_cpymem(dst, pos, n);
        }

        pos += n;
        size -= n;
        left -= n;

        if (size != 0) {
            break;
        }

        switch (state) {

        case sw_start:
            state = sw_header;
            dst = p;
            size = 4;
            left = size;
            break;

        case sw_header:
            if (p[0] != 1) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: not a client hello");
                return NJT_DECLINED;
            }

            state = sw_version;
            dst = ctx->version;
            size = 2;
            left = (p[1] << 16) + (p[2] << 8) + p[3];
            break;

        case sw_version:
            state = sw_random;
            dst = NULL;
            size = 32;
            break;

        case sw_random:
            state = sw_sid_len;
            dst = p;
            size = 1;
            break;

        case sw_sid_len:
            state = sw_sid;
            dst = NULL;
            size = p[0];
            break;

        case sw_sid:
            state = sw_cs_len;
            dst = p;
            size = 2;
            break;

        case sw_cs_len:
            state = sw_cs;
            dst = NULL;
            size = (p[0] << 8) + p[1];
            break;

        case sw_cs:
            state = sw_cm_len;
            dst = p;
            size = 1;
            break;

        case sw_cm_len:
            state = sw_cm;
            dst = NULL;
            size = p[0];
            break;

        case sw_cm:
            if (left == 0) {
                /* no extensions */
                return NJT_OK;
            }

            state = sw_ext;
            dst = p;
            size = 2;
            break;

        case sw_ext:
            if (left == 0) {
                return NJT_OK;
            }

            state = sw_ext_header;
            dst = p;
            size = 4;
            break;

        case sw_ext_header:
            if (p[0] == 0 && p[1] == 0 && ctx->host.data == NULL) {
                /* SNI extension */
                state = sw_sni_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 16 && ctx->alpn.data == NULL) {
                /* ALPN extension */
                state = sw_alpn_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 43) {
                /* supported_versions extension */
                state = sw_supver_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = (p[2] << 8) + p[3];
            break;

        case sw_sni_len:
            ext = (p[0] << 8) + p[1];
            state = sw_sni_host_head;
            dst = p;
            size = 3;
            break;

        case sw_sni_host_head:
            if (p[0] != 0) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI hostname type is not DNS");
                return NJT_DECLINED;
            }

            size = (p[1] << 8) + p[2];

            if (ext < 3 + size) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: SNI format error");
                return NJT_DECLINED;
            }
            ext -= 3 + size;

            ctx->host.data = njt_pnalloc(ctx->pool, size);
            if (ctx->host.data == NULL) {
                return NJT_ERROR;
            }

            state = sw_sni_host;
            dst = ctx->host.data;
            break;

        case sw_sni_host:
            ctx->host.len = (p[1] << 8) + p[2];

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: SNI hostname \"%V\"", &ctx->host);

            state = sw_ext;
            dst = NULL;
            size = ext;
            break;

        case sw_alpn_len:
            ext = (p[0] << 8) + p[1];

            ctx->alpn.data = njt_pnalloc(ctx->pool, ext);
            if (ctx->alpn.data == NULL) {
                return NJT_ERROR;
            }

            state = sw_alpn_proto_len;
            dst = p;
            size = 1;
            break;

        case sw_alpn_proto_len:
            size = p[0];

            if (size == 0) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: ALPN empty protocol");
                return NJT_DECLINED;
            }

            if (ext < 1 + size) {
                njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                               "ssl preread: ALPN format error");
                return NJT_DECLINED;
            }
            ext -= 1 + size;

            state = sw_alpn_proto_data;
            dst = ctx->alpn.data + ctx->alpn.len;
            break;

        case sw_alpn_proto_data:
            ctx->alpn.len += p[0];

            njt_log_debug1(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: ALPN protocols \"%V\"", &ctx->alpn);

            if (ext && ctx != NULL && ctx->alpn.data != NULL) {
                ctx->alpn.data[ctx->alpn.len++] = ',';

                state = sw_alpn_proto_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = 0;
            break;

        case sw_supver_len:
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: supported_versions");

            /* set TLSv1.3 */
            ctx->version[0] = 3;
            ctx->version[1] = 4;

            state = sw_ext;
            dst = NULL;
            size = p[0];
            break;
        }

        if (left < size) {
            njt_log_debug0(NJT_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: failed to parse handshake");
            return NJT_DECLINED;
        }
    }

    ctx->state = state;
    ctx->size = size;
    ctx->left = left;
    ctx->ext = ext;
    ctx->dst = dst;

    return NJT_AGAIN;
}


// add handler to pre-access
// otherwise, handler can't be add as part of config handler if proxy handler is involved.

static njt_int_t njt_stream_proto_init(njt_conf_t *cf)
{
    njt_stream_handler_pt        *h;
    njt_stream_core_main_conf_t  *cmcf;


    njt_log_debug(NJT_LOG_DEBUG_EVENT,  njt_cycle->log, 0, "ngin mesh init invoked");


    cmcf = njt_stream_conf_get_module_main_conf(cf, njt_stream_core_module);

    h = njt_array_push(&cmcf->phases[NJT_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_stream_handler;

    return NJT_OK;
}

