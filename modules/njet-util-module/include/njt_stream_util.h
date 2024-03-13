#ifndef NJET_MAIN_NJT_STREAM_UTIL_H
#define NJET_MAIN_NJT_STREAM_UTIL_H

#include <njt_core.h>
#include <njt_stream.h>

njt_stream_core_srv_conf_t *njt_stream_get_srv_by_port(njt_cycle_t *cycle, njt_str_t *addr_port);
njt_int_t njt_stream_get_listens_by_server(njt_array_t *array, njt_stream_core_srv_conf_t  *cscf);


#endif //NJET_MAIN_NJT_STREAM_UTIL_H