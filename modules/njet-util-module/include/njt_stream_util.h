#ifndef NJET_MAIN_NJT_STREAM_UTIL_H
#define NJET_MAIN_NJT_STREAM_UTIL_H

#include <njt_core.h>
#include <njt_stream.h>

typedef struct njt_stream_upstream_peer_change_s
{
   njt_str_t  upstream_name;
   njt_uint_t peer_id;
   njt_str_t  ip_port;
} njt_stream_upstream_peer_change_t;

njt_stream_core_srv_conf_t *njt_stream_get_srv_by_port(njt_cycle_t *cycle, njt_str_t *addr_port,njt_str_t *server_name);
njt_int_t njt_stream_get_listens_by_server(njt_array_t *array, njt_stream_core_srv_conf_t  *cscf);

njt_stream_upstream_srv_conf_t* njt_stream_util_find_upstream(njt_cycle_t *cycle,njt_str_t *name);
njt_int_t njt_stream_upstream_del(njt_cycle_t  *cycle,njt_stream_upstream_srv_conf_t *upstream);
njt_int_t njt_stream_upstream_peer_change_register(njt_stream_upstream_srv_conf_t *upstream,njt_stream_upstream_server_change_handler_t ups_srv_handlers);
njt_int_t njt_stream_upstream_peer_set_notice(njt_stream_upstream_srv_conf_t *upstream);
njt_int_t njt_stream_upstream_peer_send_broadcast(njt_stream_upstream_srv_conf_t *upstream,njt_str_t type,njt_stream_upstream_rr_peer_t *peer);
#endif //NJET_MAIN_NJT_STREAM_UTIL_H