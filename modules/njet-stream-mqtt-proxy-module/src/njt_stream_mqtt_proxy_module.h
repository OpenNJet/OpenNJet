#ifndef _NJT_STREAM_MQTT_PROXY_H_INCLUDED_
#define _NJT_STREAM_MQTT_PROXY_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_stream.h>

#define NJT_HAVE_SET_ALPN  1

#define NJT_STREAM_MQTT_PROXY_STATIC_MAX_TOPIC_LEN  255

typedef struct {
    njt_addr_t                      *addr;
    njt_stream_complex_value_t      *value;
#if (NJT_HAVE_TRANSPARENT_PROXY)
    njt_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} njt_stream_upstream_local_t;

typedef struct {
    njt_msec_t                       connect_timeout;
    njt_msec_t                       timeout;
    njt_msec_t                       next_upstream_timeout;
    size_t                           buffer_size;
    njt_stream_complex_value_t      *upload_rate;
    njt_stream_complex_value_t      *download_rate;
    njt_uint_t                       requests;
    njt_uint_t                       responses;
    njt_uint_t                       next_upstream_tries;
    njt_flag_t                       next_upstream;
    njt_flag_t                       proxy_protocol;
    njt_flag_t                       half_close;
    njt_stream_upstream_local_t     *local;
    njt_flag_t                       socket_keepalive;

#if (NJT_STREAM_SSL)
    njt_flag_t                       ssl_enable;
    njt_flag_t                       ssl_session_reuse;
    njt_uint_t                       ssl_protocols;
    njt_str_t                        ssl_ciphers;
    njt_stream_complex_value_t      *ssl_name;
    njt_flag_t                       ssl_server_name;

    njt_flag_t                       ssl_verify;
    njt_uint_t                       ssl_verify_depth;
    njt_str_t                        ssl_trusted_certificate;
    njt_str_t                        ssl_crl;

#if (NJT_STREAM_MULTICERT)
    njt_array_t                     *ssl_certificates;
    njt_array_t                     *ssl_certificate_keys;

    njt_array_t                     *ssl_certificate_values;
    njt_array_t                     *ssl_certificate_key_values;
#else
    njt_stream_complex_value_t      *ssl_certificate;
    njt_stream_complex_value_t      *ssl_certificate_key;
#endif

    njt_array_t                     *ssl_passwords;
    njt_array_t                     *ssl_conf_commands;
    njt_ssl_t                       *ssl;

#if (NJT_HAVE_NTLS)
    njt_flag_t                       ssl_ntls;
#endif

#if (NJT_HAVE_SET_ALPN)
    njt_str_t                        proxy_ssl_alpn;
#endif

#endif

    njt_stream_upstream_srv_conf_t  *upstream;
    njt_stream_complex_value_t      *upstream_value;
} njt_stream_mqtt_proxy_srv_conf_t;


//recv pkt state
typedef enum{
    NJT_STREAM_MQTT_PROXY_PKT_WAIT_TYPE = 0,
    NJT_STREAM_MQTT_PROXY_PKT_WAIT_LEN,
    NJT_STREAM_MQTT_PROXY_PKT_WAIT_DATA           //wait pkt full data
}njt_stream_mqtt_proxy_pkt_state;


//pkt type
typedef enum{
    STREAM_MQTT_PROXY_MQTT_TYPE_RESERVE_MIN=0u,
    STREAM_MQTT_PROXY_MQTT_TYPE_CONNECT=1u,
    STREAM_MQTT_PROXY_MQTT_TYPE_CONNACK=2u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PUBLISH=3u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PUBACK=4u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PUBREC=5u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PUBREL=6u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PUBCOMP=7u,
    STREAM_MQTT_PROXY_MQTT_TYPE_SUBSCRIBE=8u,
    STREAM_MQTT_PROXY_MQTT_TYPE_SUBACK=9u,
    STREAM_MQTT_PROXY_MQTT_TYPE_UNSUBSCRIBE=10u,
    STREAM_MQTT_PROXY_MQTT_TYPE_UNSUBACK=11u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PINGREQ=12u,
    STREAM_MQTT_PROXY_MQTT_TYPE_PINGRESP=13u,
    STREAM_MQTT_PROXY_MQTT_TYPE_DISCONNECT=14u,
    STREAM_MQTT_PROXY_MQTT_TYPE_RESERVE_MAX
}STREAM_MQTT_PROXY_MQTT_TYPE;


//connection close type, just used for connection to upstream, whether read or write
typedef enum{
    STREAM_MQTT_PROXY_MQTT_CONNACK_ACCEPTED = 0u,
    STREAM_MQTT_PROXY_MQTT_CONNACK_REFUSED_PROTOCOL_VERSION = 1u,
    STREAM_MQTT_PROXY_MQTT_CONNACK_REFUSED_IDENTIFIER_REJECTED = 2u,
    STREAM_MQTT_PROXY_MQTT_CONNACK_REFUSED_SERVER_UNAVAILABLE = 3u,
    STREAM_MQTT_PROXY_MQTT_CONNACK_REFUSED_BAD_USER_NAME_OR_PASSWORD = 4u,
    STREAM_MQTT_PROXY_MQTT_CONNACK_REFUSED_NOT_AUTHORIZED = 5u
}STREAM_MQTT_PROXY_MQTT_CONNECTION_TYPE;



//connection close type, just used for connection to upstream, whether read or write
typedef enum{
    STREAM_MQTT_PROXY_MQTT_RECONNECTE_SEND_CONN = 0u,
    STREAM_MQTT_PROXY_MQTT_RECONNECTE_RECV_CONNACK = 1u,
    STREAM_MQTT_PROXY_MQTT_RECONNECTE_SEND_SUBSCRIBE = 2u,
    STREAM_MQTT_PROXY_MQTT_RECONNECTE_RECV_SUBACK = 3u,
    STREAM_MQTT_PROXY_MQTT_RECONNECTE_OK = 4u
}STREAM_MQTT_PROXY_MQTT_RECONNECTE_STATE;


#define NJT_STREAM_MQTT_PROXY_MQTT_RESERVED_FLAG  0x01
#define NJT_STREAM_MQTT_PROXY_MQTT_CLEAN_SESSION_FLAG  0x02
#define NJT_STREAM_MQTT_PROXY_MQTT_WILL_FLAG      0x04
#define NJT_STREAM_MQTT_PROXY_MQTT_USERNAME_FLAG  0x80

typedef struct {
    u_char                           head_buf[5];    //type is 1byte and max 4 bytes len
    njt_uint_t                       head_len;       //record head_buf len
    njt_uint_t                       shift;          //used for calc data len

    njt_stream_mqtt_proxy_pkt_state  pkt_state;

    njt_str_t                        pkt_data;       //cache full data, head + data
    njt_uint_t                       max_buffer_len;      //max buffer len

    njt_flag_t                       wait_send;      //pkt data wait send to upstream or downstream

    STREAM_MQTT_PROXY_MQTT_TYPE      cur_pkt_type;       //when wait data , has use
    size_t                           cur_pkt_head_len;
    size_t                           cur_pkt_data_len;   //real data len
    size_t                           cur_pkt_left_data_len;    //cache left need read data len

} njt_stream_mqtt_proxy_pkt_info_t;


typedef struct {
    njt_str_t                        topic;
    u_char                           qos;
} njt_stream_mqtt_proxy_sub_topics_item_t;


typedef struct {
    njt_msec_t                       connect_timeout;
    njt_msec_t                       timeout;
    njt_str_t                        client_id;
    njt_str_t                        username;
    njt_flag_t                       clean_session;

    njt_flag_t                       not_wait_conn_pkt;

    njt_flag_t                       client_first_pkt;     //used for check client first pkt must be connect pkt
    
    
    njt_flag_t                       multi_connect_server; //used for check wether multi connect server
    // njt_flag_t                       connect_has_send; //used for check wether multi connect server
    // njt_flag_t                       topic_has_send; //used for check wether multi connect server
    njt_flag_t                       reconnecting; //used for check wether multi connect server
    STREAM_MQTT_PROXY_MQTT_RECONNECTE_STATE reconnect_state;

    njt_uint_t                       next_upstream_tries;

    //used for reconnect, to upstream
    njt_chain_t                      *out;
    njt_chain_t                      *busy;

    //to client, when reconnecting, need send pingresp
    njt_chain_t                      *client_out;
    njt_chain_t                      *client_busy;

    //connect pkt full content
    njt_str_t                        conn_pkt;

    //pingresp pkt, init when ctx create
    uint16_t                        pingresp;

    //connect pkt full content
    njt_str_t                        subscribe_pkt;

    //tmp topics, when clientis is not set, used for reconnect server
    njt_array_t                      sub_topics;

    njt_stream_mqtt_proxy_pkt_info_t downstream_pkt;     //downstream pkt buffer
    njt_stream_mqtt_proxy_pkt_info_t upstream_pkt;       //upstream pkt buffer

    njt_pool_t                       *pool;            //cache connection pool
} njt_stream_mqtt_proxy_ctx_t;


void njt_stream_mqtt_proxy_handler(njt_stream_session_t *s);
#endif
