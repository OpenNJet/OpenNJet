#ifndef NJET_MAIN_NJT_STREAM_UTIL_H
#define NJET_MAIN_NJT_STREAM_UTIL_H

#include <njt_core.h>
#include <njt_stream.h>

njt_stream_core_srv_conf_t *njt_stream_get_srv_by_port(njt_cycle_t *cycle, njt_str_t *addr_port,njt_str_t *server_name);
njt_int_t njt_stream_get_listens_by_server(njt_array_t *array, njt_stream_core_srv_conf_t  *cscf);

njt_stream_upstream_srv_conf_t* njt_stream_util_find_upstream(njt_cycle_t *cycle,njt_str_t *name);
njt_int_t njt_stream_upstream_del(njt_cycle_t  *cycle,njt_stream_upstream_srv_conf_t *upstream);
njt_int_t njt_stream_upstream_peer_change_register(njt_stream_upstream_srv_conf_t *upstream,njt_stream_upstream_add_server_pt add_handler,njt_stream_upstream_update_server_pt update_handler,njt_stream_upstream_del_server_pt del_handler,njt_stream_upstream_save_server_pt save_handler);
#endif //NJET_MAIN_NJT_STREAM_UTIL_H