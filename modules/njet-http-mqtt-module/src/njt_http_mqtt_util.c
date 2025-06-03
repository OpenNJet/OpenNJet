/*
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */

#include <njet.h>
#include "njt_http_mqtt_util.h"


/*
 * All functions in this file are copied directly from njt_http_upstream.c,
 * beacuse they are declared as static there.
 */


void
njt_http_mqtt_upstream_finalize_request(njt_http_request_t *r,
    njt_http_upstream_t *u, njt_int_t rc)
{
    njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    if(rc == NJT_OK || rc == NJT_HTTP_OK){
        /* flag for keepalive */
        u->headers_in.status_n = NJT_HTTP_OK;
    }else{
        r->headers_out.status = rc;
    }

    if (u->cleanup) {
        *u->cleanup = NULL;
    }

    if (u->resolved && u->resolved->ctx) {
        njt_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }


    if (u->state && u->state->response_time) {
        u->state->response_time = njt_current_msec - u->state->response_time;

        if (u->pipe) {
            u->state->response_length = u->pipe->read_length;
        }
    }

    if (u->finalize_request) {
        u->finalize_request(r, rc);
    }

    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

    if (u->peer.connection) {

#if 0 /* we don't support SSL at this time, was: (NJT_HTTP_SSL) */

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {

            /*
             * We send the "close notify" shutdown alert to the upstream only
             * and do not wait its "close notify" shutdown alert.
             * It is acceptable according to the TLS standard.
             */

            u->peer.connection->ssl->no_wait_shutdown = 1;

            (void) njt_ssl_shutdown(u->peer.connection);
        }
#endif

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            njt_destroy_pool(u->peer.connection->pool);
        }

        njt_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe) {
        u->pipe->upstream = NULL;
    }

    if (u->pipe && u->pipe->temp_file) {
        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->header_sent
        && (rc == NJT_ERROR || rc >= NJT_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (rc == NJT_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    rc = njt_http_send_special(r, NJT_HTTP_LAST);
    njt_http_finalize_request(r, rc);

    // if (rc == 0) {
    //     rc = njt_http_send_special(r, NJT_HTTP_LAST);
    //     njt_http_finalize_request(r, rc);
    // }else{

    //     njt_http_mqtt_request_output(r, rc, njt_str_t *msg);
    // }
}


njt_int_t
njt_http_mqtt_upstream_test_connect(njt_connection_t *c)
{
    int        err;
    socklen_t  len;


#if (NJT_HAVE_KQUEUE)

    if (njt_event_flags & NJT_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof) {
            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, c->write->kq_errno,
                       "kevent() reported that connect() failed");

            njt_log_error(NJT_LOG_ERR, njt_cycle->log, 0, "returning NJT_ERROR");
            return NJT_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1)
        {
            err = njt_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) njt_connection_error(c, err, "connect() failed");

            return NJT_ERROR;
        }
    }

    return NJT_OK;
}

// void
// njt_http_mqtt_upstream_next(njt_http_request_t *r,
//     njt_http_upstream_t *u, njt_int_t ft_type)
// {
//     njt_uint_t  status, state;

//     njt_log_error(NJT_LOG_ERR, r->connection->log,0, "entering njt_http_mqtt_upstream_next");

//     njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
//                    "http next upstream, %xi", ft_type);

// #if 0
//     njt_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
// #endif

//     if (ft_type == NJT_HTTP_UPSTREAM_FT_HTTP_404) {
//         state = NJT_PEER_NEXT;
//     } else {
//         state = NJT_PEER_FAILED;
//     }

//     if (ft_type != NJT_HTTP_UPSTREAM_FT_NOLIVE) {
//         u->peer.free(&u->peer, u->peer.data, state);
//     }

//     if (ft_type == NJT_HTTP_UPSTREAM_FT_TIMEOUT) {
//         njt_log_error(NJT_LOG_ERR, r->connection->log, NJT_ETIMEDOUT,
//                       "upstream timed out");
//     }

//     if (u->peer.cached && ft_type == NJT_HTTP_UPSTREAM_FT_ERROR) {
//         status = 0;

//     } else {
//         switch(ft_type) {

//         case NJT_HTTP_UPSTREAM_FT_TIMEOUT:
//             status = NJT_HTTP_GATEWAY_TIME_OUT;
//             break;

//         case NJT_HTTP_UPSTREAM_FT_HTTP_500:
//             status = NJT_HTTP_INTERNAL_SERVER_ERROR;
//             break;

//         case NJT_HTTP_UPSTREAM_FT_HTTP_404:
//             status = NJT_HTTP_NOT_FOUND;
//             break;

//         /*
//          * NJT_HTTP_UPSTREAM_FT_BUSY_LOCK and NJT_HTTP_UPSTREAM_FT_MAX_WAITING
//          * never reach here
//          */

//         default:
//             status = NJT_HTTP_BAD_GATEWAY;
//         }
//     }

//     if (r->connection->error) {
//         njt_http_mqtt_upstream_finalize_request(r, u,
//                                                NJT_HTTP_CLIENT_CLOSED_REQUEST);

//         return;
//     }

//     if (status) {
//         u->state->status = status;

//         if (u->peer.tries == 0 || !(u->conf->next_upstream & ft_type)) {
//             njt_http_mqtt_upstream_finalize_request(r, u, status);

//             return;
//         }
//     }

//     if (u->peer.connection) {
//         njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
//                        "close http upstream connection: %d",
//                        u->peer.connection->fd);

// #if 0 /* we don't support SSL at this time, was: (NJT_HTTP_SSL) */

//         if (u->peer.connection->ssl) {
//             u->peer.connection->ssl->no_wait_shutdown = 1;
//             u->peer.connection->ssl->no_send_shutdown = 1;

//             (void) njt_ssl_shutdown(u->peer.connection);
//         }
// #endif

//         if (u->peer.connection->pool) {
//             njt_destroy_pool(u->peer.connection->pool);
//         }

//         njt_close_connection(u->peer.connection);
//     }

// #if 0
//     if (u->conf->busy_lock && !u->busy_locked) {
//         njt_http_upstream_busy_lock(p);
//         return;
//     }
// #endif

//     /* TODO: njt_http_upstream_connect(r, u); */
//     if (status == 0) {
//         status = NJT_HTTP_INTERNAL_SERVER_ERROR;
//     }

//     return njt_http_mqtt_upstream_finalize_request(r, u, status);
// }

