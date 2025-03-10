/* xbxb: e3de4f6afd31e554e300f41095a2cfc8 */
#ifndef _NJT_HTTP_GZIP_FILTER_H_INCLUDED_
#define _NJT_HTTP_GZIP_FILTER_H_INCLUDED_

#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>


#include <zlib.h>

#if (NJT_HTTP_GZIP)

typedef struct {
    uint64_t                    cpr_text_html;  //压缩后文件大小
    uint64_t                    uncpr_text_html;//压缩前文件大小

    uint64_t                 cpr_text_plain;
    uint64_t                 uncpr_text_plain;

    uint64_t                 cpr_text_richtext;
    uint64_t                 uncpr_text_richtext;

    uint64_t                 cpr_text_css;
    uint64_t                 uncpr_text_css;

    uint64_t                 cpr_text_xml;
    uint64_t                 uncpr_text_xml;

    uint64_t                    cpr_text_javascript;
    uint64_t                    uncpr_text_javascript;

    uint64_t                    cpr_app_xml;
    uint64_t                    uncpr_app_xml;

    uint64_t                    cpr_app_json;
    uint64_t                    uncpr_app_json;

    uint64_t                    cpr_app_msword;
    uint64_t                    uncpr_app_msword;

    uint64_t                    cpr_app_vnd_ms_excel;
    uint64_t                    uncpr_app_vnd_ms_excel;

    uint64_t                    cpr_app_vnd_ms_powerpoint;
    uint64_t                    uncpr_app_vnd_ms_powerpoint;

    uint64_t                    cpr_app_xml_rss;
    uint64_t                    uncpr_app_xml_rss;

    uint64_t                    cpr_app_x_javascript;
    uint64_t                    uncpr_app_x_javascript;

    uint64_t                    last_cpr_text_html;
    uint64_t                    last_uncpr_text_html;

    uint64_t                 last_cpr_text_plain;
    uint64_t                 last_uncpr_text_plain;

    uint64_t                 last_cpr_text_richtext;
    uint64_t                 last_uncpr_text_richtext;

    uint64_t                 last_cpr_text_css;
    uint64_t                 last_uncpr_text_css;

    uint64_t                 last_cpr_text_xml;
    uint64_t                 last_uncpr_text_xml;

    uint64_t                    last_cpr_text_javascript;
    uint64_t                    last_uncpr_text_javascript;

    uint64_t                    last_cpr_app_xml;
    uint64_t                    last_uncpr_app_xml;

    uint64_t                    last_cpr_app_json;
    uint64_t                    last_uncpr_app_json;

    uint64_t                    last_cpr_app_msword;
    uint64_t                    last_uncpr_app_msword;

    uint64_t                    last_cpr_app_vnd_ms_excel;
    uint64_t                    last_uncpr_app_vnd_ms_excel;

    uint64_t                    last_cpr_app_vnd_ms_powerpoint;
    uint64_t                    last_uncpr_app_vnd_ms_powerpoint;

    uint64_t                    last_cpr_app_xml_rss;
    uint64_t                    last_uncpr_app_xml_rss;

    uint64_t                    last_cpr_app_x_javascript;
    uint64_t                    last_uncpr_app_x_javascript;

} njt_http_gzip_stat_filter_shctx_t;


typedef struct {
    njt_http_gzip_stat_filter_shctx_t *sh;
    njt_slab_pool_t            *shpool;
    njt_shm_zone_t             *shm_zone;

    njt_event_t      ev;       /* timer event */
} njt_http_gzip_stat_filter_conf_t;
#endif


extern njt_module_t  njt_http_gzip_filter_module;
// 统计不同类型文件的压缩前压缩后大小信息
// extern njt_int_t njt_http_gzip_stat_start_req_timer(njt_cycle_t *cycle);

#endif