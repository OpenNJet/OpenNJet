/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */
#include "njt_http_sticky_route.h"

static njt_int_t route_expires(char *str, size_t size, time_t t);

/* Convert the maxage of cookie into HTTP-date timestamp */
static njt_int_t route_expires(char *str, size_t size, time_t t)
{

    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                     };
    char *wdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    struct tm e;

    if (t == MAX_EXPIRES_TIME) {
        return snprintf(str, size, MAX_EXPIRES_STR);
    }
    t += time(NULL);

    gmtime_r(&t, &e);
    return snprintf(str, size, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                    wdays[e.tm_wday], e.tm_mday, months[e.tm_mon],
                    e.tm_year + 1900, e.tm_hour, e.tm_min, e.tm_sec);
}

char *njt_http_sticky_route_setup(njt_conf_t *cf, njt_http_sticky_conf_t *scf,
                                   njt_str_t *value)
{

    njt_str_t temp;
    njt_uint_t i;
    /* set cookie attributes */
    /* srv_id */
    scf->route_cf->route_name.len = value[1].len;
    scf->route_cf->route_name.data = value[1].data;
    /* init expire date */
    scf->route_cf->expires = NJT_CONF_UNSET;
	scf->route_cf->cookie = NJT_CONF_UNSET;
	scf->route_cf->uri = NJT_CONF_UNSET;

    /* iterate over remaining arguments */
    for (i = 2; i < cf->args->nelts; ++i) {
        /* check expires parameter */
        if ((u_char *)njt_strstr(value[i].data, "expires=") == value[i].data) {
            /* check whether expire time is defined */
            if (value[i].len <= sizeof("expires=") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a value should be provided to"
                                   " \"expires\" parameter.");
                return NJT_CONF_ERROR;
            }

            /* The special value "max" will cause the cookie to
               expire on “31 Dec 2037 23:55:55 GMT” */
            if (njt_strcmp(value[i].data, "expires=max") == 0) {
                scf->route_cf->expires = MAX_EXPIRES_TIME;
                continue;
            }

            /* set expires parameter */
            temp.len = value[i].len - sizeof("expires=") + 1;
            temp.data = value[i].data + sizeof("expires=") - 1;

            /* convert to time */
            scf->route_cf->expires = njt_parse_time(&temp, 1);
            if (scf->route_cf->expires == NJT_ERROR || scf->route_cf->expires < 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\" for "
                                   "parameter \"expire\"",
                                   &temp);
                return NJT_CONF_ERROR;
            }
            continue;
        }

        /* check domain parameter */
        if ((u_char *)njt_strstr(value[i].data, "domain=") == value[i].data) {
            /* check whether domain is defined */
            if (value[i].len <= sizeof("domain=") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a value should be provided to "
                                   "\"domain\" parameter.");
                return NJT_CONF_ERROR;
            }
            /* set domain parameter */
            scf->route_cf->domain.len = value[i].len - sizeof("domain=") + 1;
            scf->route_cf->domain.data = value[i].data + sizeof("domain=") - 1;
            continue;
        }

        /* check path parameter */
        if ((u_char *)njt_strstr(value[i].data, "path=") == value[i].data) {
            /* check whether path is defined */
            if (value[i].len <= sizeof("path=") - 1) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a value should be provided to \"path\" parameter.");
                return NJT_CONF_ERROR;
            }
            /* set path parameter */
            scf->route_cf->path.len = value[i].len - sizeof("path=") + 1;
            scf->route_cf->path.data = value[i].data + sizeof("path=") - 1;
            continue;
        }

        /* check samesite parameter */
        if ((u_char *)njt_strstr(value[i].data, "samesite=") == value[i].data) {
            /* check whether samesite is defined properly*/
            if (njt_strcmp(value[i].data, "samesite=strict") != 0 &&
                njt_strcmp(value[i].data, "samesite=lax") != 0 &&
                njt_strcmp(value[i].data, "samesite=none") != 0) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "a value (strict, lax, or none) should "
                                   "be provided to \"samesite\" parameter");
                return NJT_CONF_ERROR;
            }
            /* set samesite parameter */
            scf->route_cf->samesite.len = value[i].len - sizeof("samesite=") + 1;
            scf->route_cf->samesite.data = value[i].data + sizeof("samesite=") - 1;
            /* first letter should be uppercase */
            scf->route_cf->samesite.data[0] =
                njt_toupper(scf->route_cf->samesite.data[0]);
            continue;
        }

        /* check httponly parameter */
        if (njt_strcmp(value[i].data, "httponly") == 0) {
            scf->route_cf->httponly = 1;
            continue;
        }

        /* check secure parameter */
        if (njt_strcmp(value[i].data, "secure") == 0) {
            scf->route_cf->secure = 1;
            continue;
        }
		/* check route cookid parameter */
		 if ((u_char *)njt_strstr(value[i].data, "$") == value[i].data && scf->route_cf->cookie == NJT_CONF_UNSET) {
		 //scf->route_cf->cookie = 1;
		 //njt_str_t      variable = njt_string("route_cookie");
		 njt_str_t      variable;

		 variable.data = value[i].data+1;
		 variable.len = value[i].len - 1;
		 if(variable.len <= 0) {
			 return NJT_CONF_ERROR;
		 }
		 scf->route_cf->cookie  = njt_http_get_variable_index(cf, &variable);
		
		continue;
		}
		/* check route uri parameter */
		 if ((u_char *)njt_strstr(value[i].data, "$") == value[i].data && scf->route_cf->uri == NJT_CONF_UNSET) {
			//njt_str_t      variable = njt_string("route_uri");
			 njt_str_t      variable;

			 variable.data = value[i].data+1;
			 variable.len = value[i].len - 1;
			 if(variable.len <= 0) {
				 return NJT_CONF_ERROR;
			 }
		    scf->route_cf->uri  = njt_http_get_variable_index(cf, &variable);
		
		continue;
		}

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[i]);
        return NJT_CONF_ERROR;
    }

    return NJT_CONF_OK;
}

njt_int_t njt_http_sticky_route_get_peer(njt_peer_connection_t *pc,
        njt_http_sticky_peer_data_t *sp)
{

    njt_int_t ret;
    njt_http_sticky_conf_t *conf = sp->conf;
    njt_http_upstream_rr_peer_data_t *rrp = 0;
    njt_http_request_t *r = sp->request;
    njt_str_t route = njt_string("");
    //time_t   now;
    u_char   ch;
    njt_int_t   rc;
    njt_int_t   len,i;
	njt_http_variable_value_t *v = NULL;
    njt_http_upstream_rr_peer_t *peer = NULL;
    njt_http_upstream_rr_peer_t *selected = NULL;

	if(conf->route_cf->cookie > 0) {
		v = njt_http_get_indexed_variable(r, conf->route_cf->cookie);
		if (v == NULL || v->not_found) {
            //goto round_robin;
        } else {
			route.data = v->data;
			route.len = v->len;
		}
		 njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                      "zyg: cookie value is %s,len=%d", v->data,v->len);
	}
	if(conf->route_cf->uri > 0 && (v == NULL || v->not_found || v->len == 0)) {
		v = njt_http_get_indexed_variable(r, conf->route_cf->uri);
		if (v == NULL || v->not_found) {
            goto round_robin;
        } else {
			route.data = v->data;
			route.len = v->len;
		}
		 njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                      "zyg: uri value is %s,len=%d", v->data,v->len);
	}
	/*
	if(route.len == 0) {
		njt_log_error(NJT_LOG_DEBUG, pc->log, 0, "Enter njt_http_sticky_route_get_peer");
		if (njt_http_parse_multi_header_lines(&r->headers_in.cookies,
											  &conf->route_cf->route_name,
											  &route) != NJT_DECLINED) {
			njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
						  "zyg: cookie value is %V", &route);
		}
	}*/
    rrp = &sp->rrp;
    if(rrp == NULL) {
	return NJT_ERROR;
    }
    njt_http_upstream_rr_peers_rlock(rrp->peers);

    if (sp->tries > 1 || rrp->peers->single || route.len == 0) {
        goto round_robin;
    }

    /*TODO optimze the performance by calculating the checksum in advance.*/
    //now = njt_time();

    pc->cached = 0;
    pc->connection = NULL;

    for (peer = rrp->peers->peer; peer; peer = peer->next) {
	/*
        if (peer->down) {
            continue;
        }

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout) {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }*/
	if(njt_http_upstream_pre_handle_peer(peer) == NJT_ERROR)
		continue;
	rc = NJT_OK;
        //njt_http_sticky_md5(sp->request->pool, peer->sockaddr, &sp->md5);
		sp->md5.data = peer->route.data;
		sp->md5.len = peer->route.len;
	if(conf->route_cf->path.len > 0) {
	   rc = NJT_DECLINED;
	   njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                          "conf cookie path:%V.", &conf->route_cf->path);
	   if(conf->route_cf->path.len == r->uri.len && njt_strncmp(conf->route_cf->path.data, r->uri.data,r->uri.len) == 0) {
		rc = NJT_OK;
	   } else   {
		len = (r->uri.len > conf->route_cf->path.len ?conf->route_cf->path.len:r->uri.len);
		 for(i=0; i < len; i++) {
			 if(conf->route_cf->path.data[i] != r->uri.data[i])
				break;
		 }
		 if(i == len) {
			ch = (r->uri.len > conf->route_cf->path.len ?r->uri.data[i]:conf->route_cf->path.data[i]);
			if(ch == '/') {
			    rc = NJT_OK;
			}
		  } 
	   }
	  
	  
	}
        if (rc == NJT_OK && sp->md5.len == route.len && njt_strncmp(sp->md5.data, route.data,route.len) == 0) {
            njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                          "Sticky Cookie: peer %V got selected.", &sp->md5);
            selected = peer;
            break;
        }
    }
#if 0
    while (peer != NULL) {
        //njt_http_sticky_md5(sp->request->pool, peer->sockaddr, &sp->md5);
		sp->md5.data = peer->route.data;
		sp->md5.len = peer->route.len;
        if (sp->md5.len == route.len && njt_strncmp(sp->md5.data, route.data, route.len) == 0) {
            /*TODO  more sanity checks here*/
            if (!peer->down && !(peer->max_conns && peer->conns >= peer->max_conns)) {
                njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                              "Sticky Cookie: peer %V got selected.", &sp->md5);
                selected = peer;
            }
            break;
        }

        peer = peer->next;
    }
#endif

    if (selected == NULL) {
        goto round_robin;
    }
    selected->selected_time = ((njt_timeofday())->sec)*1000 + (njt_uint_t)((njt_timeofday())->msec);
    sp->rrp.current = selected;

    pc->sockaddr = selected->sockaddr;
    pc->socklen = selected->socklen;
    pc->name = &selected->name;

    selected->conns++;
    selected->requests++;

    njt_http_upstream_rr_peers_unlock(rrp->peers);

    //njt_http_sticky_md5(sp->request->pool, pc->sockaddr, &sp->md5);
	sp->md5.data = selected->route.data;
	sp->md5.len = selected->route.len;
    //njt_http_sticky_set_route_cookie(sp->request, conf->route_cf, &sp->md5);
    return NJT_OK;

round_robin:
    njt_http_upstream_rr_peers_unlock(rrp->peers);
    ret = njt_http_upstream_get_round_robin_peer(pc, rrp);

    if (ret == NJT_OK) {
        njt_http_sticky_md5(sp->request->pool, pc->sockaddr, &sp->md5);
		//sp->md5.data = rrp->current->route.data;
		//sp->md5.len = rrp->current->route.len;
        //njt_http_sticky_set_route_cookie(sp->request, conf->route_cf, &sp->md5);
        njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                      "Round Robin: peer %V got selected.", &sp->md5);
    } else {
        njt_log_error(NJT_LOG_DEBUG, pc->log, 0,
                      "Round Robin: no peer is selected.");
    }

    return ret;
}

njt_int_t njt_http_sticky_set_route_cookie(njt_http_request_t *r,
                                     njt_http_sticky_route_conf_t *route_conf,
                                     njt_str_t *md5)
{

    /* Set-Cookie: <srv_id>=...; Expires=...; Domain=...; Path=...*/
    u_char *cookie, *p;
    size_t len;
    char http_date[50];
    int http_date_len = 0;
    njt_table_elt_t *set_cookie, *elt;
    njt_list_part_t *part;
    njt_uint_t      i;


    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                  "zhaoqin: Enter njt_http_sticky_set_route_cookie \"%V\" ",md5);

    /* Calculate the length */
    /* name=value */
    len = route_conf->route_name.len + 1 + md5->len;

    /* convert expire time to http date string */
    if (route_conf->expires != NJT_CONF_UNSET) {
        http_date_len =
            route_expires(http_date, sizeof(http_date), route_conf->expires);
        len += sizeof("; Expires=") - 1 + http_date_len;
    }
    if (route_conf->domain.len > 0) {
        len += sizeof("; Domain=") - 1 + route_conf->domain.len;
    }
    if (route_conf->samesite.len > 0) {
        len += sizeof("; SameSite=") - 1 + route_conf->samesite.len;
    }
    if (route_conf->path.len > 0) {
        len += sizeof("; Path=") - 1 + route_conf->path.len;
    }
    if (route_conf->secure) {
        len += sizeof("; Secure");
    }
    if (route_conf->httponly) {
        len += sizeof("; HttpOnly");
    }

    cookie = njt_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NJT_ERROR;
    }

    /* Start compose the cookie */
    /* srv_id and its value */
    p = njt_copy(cookie, route_conf->route_name.data,
                 route_conf->route_name.len);
    *p++ = '=';
    p = njt_copy(p, md5->data, md5->len);

    /* expires */
    if (route_conf->expires != NJT_CONF_UNSET) {
        p = njt_copy(p, "; Expires=", sizeof("; Expires=") - 1);
        p = njt_copy(p, http_date, http_date_len);
    }

    /* domain */
    if (route_conf->domain.len > 0) {
        p = njt_copy(p, "; Domain=", sizeof("; Domain=") - 1);
        p = njt_copy(p, route_conf->domain.data, route_conf->domain.len);
    }

    /* path */
    if (route_conf->path.len > 0) {
        p = njt_copy(p, "; Path=", sizeof("; Path=") - 1);
        p = njt_copy(p, route_conf->path.data, route_conf->path.len);
    }

    /* samesite */
    if (route_conf->samesite.len > 0) {
        p = njt_copy(p, "; SameSite=", sizeof("; SameSite=") - 1);
        p = njt_copy(p, route_conf->samesite.data, route_conf->samesite.len);
    }

    /* secure */
    if (route_conf->secure) {
        p = njt_copy(p, "; Secure", sizeof("; Secure") - 1);
    }

    /* httponly */
    if (route_conf->httponly) {
        p = njt_copy(p, "; HttpOnly", sizeof("; HttpOnly") - 1);
    }

    part = &r->headers_out.headers.part;
    elt = part->elts;
    set_cookie = NULL;

    for (i = 0;; i++) {
        if (part->nelts > 1 || i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            elt = part->elts;
            i = 0;
        }
        /* ... */
        if (njt_strncmp(elt->value.data, route_conf->route_name.data,
                        route_conf->route_name.len) == 0) {
            set_cookie = elt;
            break;
        }
    }

    /* found a Set-Cookie header with the same name: replace it */
    if (set_cookie != NULL) {
        set_cookie->value.len = p - cookie;
        set_cookie->value.data = cookie;
        return NJT_OK;
    }

    set_cookie = njt_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NJT_ERROR;
    }

    set_cookie->hash = 1;
    njt_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    njt_log_error(NJT_LOG_DEBUG, r->connection->log, 0,
                  "Cookie has been set to: \"%V\"", &set_cookie->value);

    return NJT_OK;
}
