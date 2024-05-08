/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 * Client body reception code Copyright (c) 2002-2007 Igor Sysoev
 * Temporary file name generation code Copyright (c) 2002-2007 Igor Sysoev
 * Copyright (C) 2021-2023 TMLake(Beijing) Technology Co., Ltd.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>
#include <njet.h>
#include "njt_http_api_register_module.h"

#if njet_version >= 1011002

#include <njt_md5.h>

typedef njt_md5_t MD5_CTX1;

#define MD5Init njt_md5_init
#define MD5Update njt_md5_update
#define MD5Final njt_md5_final

#define MD5_DIGEST_LENGTH 16

#include <openssl/sha.h>

#else

#if (NJT_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NJT_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NJT_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif


#endif

#define MULTIPART_FORM_DATA_STRING              "multipart/form-data"
#define BOUNDARY_STRING                         "boundary="
#define CONTENT_DISPOSITION_STRING              "Content-Disposition:"
#define CONTENT_TYPE_STRING                     "Content-Type:"
#define CONTENT_RANGE_STRING                    "Content-Range:"
#define X_CONTENT_RANGE_STRING                  "X-Content-Range:"
#define SESSION_ID_STRING                       "Session-ID:"
#define X_SESSION_ID_STRING                     "X-Session-ID:"
#define FORM_DATA_STRING                        "form-data"
#define ATTACHMENT_STRING                       "attachment"
#define FILENAME_STRING                         "filename="
#define FIELDNAME_STRING                        "name="
#define BYTES_UNIT_STRING                       "bytes "

#define NJT_UPLOAD_MALFORMED    -11
#define NJT_UPLOAD_NOMEM        -12
#define NJT_UPLOAD_IOERROR      -13
#define NJT_UPLOAD_SCRIPTERROR  -14
#define NJT_UPLOAD_TOOLARGE     -15

#ifndef NJT_HTTP_V2
#define NJT_HTTP_V2 0
#endif

/*
 * State of multipart/form-data parser
 */
typedef enum {
	upload_state_boundary_seek,
	upload_state_after_boundary,
	upload_state_headers,
	upload_state_data,
	upload_state_finish
} upload_state_t;

/*
 * Range
 */
typedef struct {
    off_t       start, end, total;
} njt_http_upload_range_t;

/*
 * State of range merger
 */
typedef struct {
    njt_buf_t               *in_buf;
    njt_buf_t               *out_buf;
    njt_http_upload_range_t  current_range_n;
    off_t                   *parser_state;
    njt_log_t               *log;

    u_char                  *range_header_buffer;
    u_char                  *range_header_buffer_end;
    u_char                  **range_header_buffer_pos;

    unsigned int             found_lower_bound:1;
    unsigned int             complete_ranges:1;
    unsigned int             first_range:1;
} njt_http_upload_merger_state_t;

/*
 * Template for a field to generate in output form
 */
typedef struct {
    njt_table_elt_t         value;
    njt_array_t             *field_lengths;
    njt_array_t             *field_values;
    njt_array_t             *value_lengths;
    njt_array_t             *value_values;
} njt_http_upload_field_template_t;

/*
 * Template for a header
 */
typedef struct {
    njt_http_complex_value_t      *name;
    njt_http_complex_value_t      *value;
} njt_http_upload_header_template_t;

/*
 * Filter for fields in output form
 */
typedef struct {
#if (NJT_PCRE)
    njt_regex_t              *regex;
    njt_int_t                ncaptures;
#else
    njt_str_t                text;
#endif
} njt_http_upload_field_filter_t;

typedef struct {
    njt_path_t                  *path;
    njt_http_complex_value_t    dynamic;
    unsigned                    is_dynamic:1;
} njt_http_upload_path_t;

/*
 * Upload cleanup record
 */
typedef struct njt_http_upload_cleanup_s {
    njt_fd_t                         fd;
    u_char                           *filename;
    njt_http_headers_out_t           *headers_out;
    njt_array_t                      *cleanup_statuses;
    njt_log_t                        *log;
    unsigned int                     aborted:1;
} njt_upload_cleanup_t;

/*
 * Upload configuration for specific location
 */
typedef struct {
    njt_str_t                     url;
    njt_http_complex_value_t      *url_cv;
    njt_http_upload_path_t        *state_store_path;
    njt_http_upload_path_t        *store_path;
    njt_uint_t                    store_access;
    size_t                        buffer_size;
    size_t                        merge_buffer_size;
    size_t                        range_header_buffer_size;
    size_t                        max_header_len;
    size_t                        max_output_body_len;
    off_t                         max_file_size;
    njt_array_t                   *field_templates;
    njt_array_t                   *aggregate_field_templates;
    njt_array_t                   *field_filters;
    njt_array_t                   *cleanup_statuses;
    njt_array_t                   *header_templates;
    njt_flag_t                    forward_args;
    njt_flag_t                    tame_arrays;
    njt_flag_t                    resumable_uploads;
    njt_flag_t                    empty_field_names;
    size_t                        limit_rate;

    unsigned int                  md5:1;
    unsigned int                  sha1:1;
    unsigned int                  sha256:1;
    unsigned int                  sha512:1;
    unsigned int                  crc32:1;
} njt_http_upload_loc_conf_t;

typedef struct njt_http_upload_md5_ctx_s {
    MD5_CTX1    md5;
    u_char      md5_digest[MD5_DIGEST_LENGTH * 2];
} njt_http_upload_md5_ctx_t;

typedef struct njt_http_upload_sha1_ctx_s {
    SHA_CTX     sha1;
    u_char      sha1_digest[SHA_DIGEST_LENGTH * 2];
} njt_http_upload_sha1_ctx_t;

typedef struct njt_http_upload_sha256_ctx_s {
    SHA256_CTX  sha256;
    u_char      sha256_digest[SHA256_DIGEST_LENGTH * 2];
} njt_http_upload_sha256_ctx_t;

typedef struct njt_http_upload_sha512_ctx_s {
    SHA512_CTX  sha512;
    u_char      sha512_digest[SHA512_DIGEST_LENGTH * 2];
} njt_http_upload_sha512_ctx_t;

struct njt_http_upload_ctx_s;

/*
 * Request body data handler
 */
typedef njt_int_t (*njt_http_request_body_data_handler_pt)
    (struct njt_http_upload_ctx_s*, u_char *, u_char*);

/*
 * Upload module context
 */
typedef struct njt_http_upload_ctx_s {
    njt_str_t           session_id;
    njt_str_t           boundary;
    u_char              *boundary_start;
    u_char              *boundary_pos;

    upload_state_t		state;

    u_char              *header_accumulator;
    u_char              *header_accumulator_end;
    u_char              *header_accumulator_pos;

    njt_str_t           field_name;
    njt_str_t           file_name;
    njt_str_t           content_type;
    njt_str_t           content_range;
    njt_http_upload_range_t     content_range_n;

    njt_uint_t          ordinal;

    u_char              *output_buffer;
    u_char              *output_buffer_end;
    u_char              *output_buffer_pos;
    u_char              *merge_buffer;
    u_char              *range_header_buffer;
    u_char              *range_header_buffer_pos;
    u_char              *range_header_buffer_end;

    njt_http_request_body_data_handler_pt data_handler;

    njt_int_t (*start_part_f)(struct njt_http_upload_ctx_s *upload_ctx);
    void (*finish_part_f)(struct njt_http_upload_ctx_s *upload_ctx);
    void (*abort_part_f)(struct njt_http_upload_ctx_s *upload_ctx);
	njt_int_t (*flush_output_buffer_f)(struct njt_http_upload_ctx_s *upload_ctx, u_char *buf, size_t len);

    njt_http_request_t  *request;
    njt_log_t           *log;

    njt_file_t          output_file;
    njt_file_t          state_file;
    njt_chain_t         *chain;
    njt_chain_t         *last;
    njt_chain_t         *checkpoint;
    njt_chain_t         *to_write;
    size_t              output_body_len;
    size_t              limit_rate;
    ssize_t             received;

    njt_pool_cleanup_t          *cln;

    njt_http_upload_md5_ctx_t   *md5_ctx;    
    njt_http_upload_sha1_ctx_t  *sha1_ctx;    
    njt_http_upload_sha256_ctx_t *sha256_ctx;
    njt_http_upload_sha512_ctx_t *sha512_ctx;
    uint32_t                    crc32;    
    njt_path_t          *store_path;
    njt_path_t          *state_store_path;

    unsigned int        first_part:1;
    unsigned int        discard_data:1;
    unsigned int        is_file:1;
    unsigned int        partial_content:1;
    unsigned int        prevent_output:1;
    unsigned int        calculate_crc32:1;
    unsigned int        started:1;
    unsigned int        unencoded:1;
    unsigned int        no_content:1;
    unsigned int        raw_input:1;
} njt_http_upload_ctx_t;

static njt_int_t njt_http_upload_test_expect(njt_http_request_t *r);

#if (NJT_HTTP_V2)
static void njt_http_upload_read_event_handler(njt_http_request_t *r);
#endif
static njt_int_t njt_http_upload_handler(njt_http_request_t *r);
static njt_int_t njt_http_upload_options_handler(njt_http_request_t *r);
static njt_int_t njt_http_upload_body_handler(njt_http_request_t *r);

static void *njt_http_upload_create_loc_conf(njt_conf_t *cf);
static char *njt_http_upload_merge_loc_conf(njt_conf_t *cf,
    void *parent, void *child);
// static njt_int_t njt_http_upload_add_variables(njt_conf_t *cf);
// static njt_int_t njt_http_upload_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static njt_int_t njt_http_upload_md5_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static njt_int_t njt_http_upload_sha1_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static njt_int_t njt_http_upload_sha256_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static njt_int_t njt_http_upload_sha512_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static njt_int_t njt_http_upload_file_size_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static void njt_http_upload_content_range_variable_set(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data);
// static njt_int_t njt_http_upload_content_range_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data);
// static njt_int_t njt_http_upload_crc32_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static njt_int_t njt_http_upload_uint_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data);
// static char *njt_http_upload_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_int_t
njt_http_upload_process_field_templates(njt_http_request_t *r,
    njt_http_upload_field_template_t *t, njt_str_t *field_name, njt_str_t *field_value);

static njt_int_t njt_http_upload_start_handler(njt_http_upload_ctx_t *u);
static void njt_http_upload_finish_handler(njt_http_upload_ctx_t *u);
static void njt_http_upload_abort_handler(njt_http_upload_ctx_t *u);

static njt_int_t njt_http_upload_flush_output_buffer(njt_http_upload_ctx_t *u,
    u_char *buf, size_t len);
static njt_int_t njt_http_upload_append_field(njt_http_upload_ctx_t *u,
    njt_str_t *name, njt_str_t *value);
static njt_int_t njt_http_upload_merge_ranges(njt_http_upload_ctx_t *u, njt_http_upload_range_t *range_n);
static njt_int_t njt_http_upload_parse_range(njt_str_t *range, njt_http_upload_range_t *range_n);

static void njt_http_read_upload_client_request_body_handler(njt_http_request_t *r);
static njt_int_t njt_http_do_read_upload_client_request_body(njt_http_request_t *r);
static njt_int_t njt_http_process_request_body(njt_http_request_t *r, njt_chain_t *body);

static njt_int_t njt_http_read_upload_client_request_body(njt_http_request_t *r);

static njt_int_t njt_http_dyn_crl_init(njt_conf_t *cf);

// static char *njt_http_upload_set_form_field(njt_conf_t *cf, njt_command_t *cmd,
//     void *conf);
    static njt_int_t njt_http_upload_eval_path(njt_http_request_t *r);
// static njt_int_t njt_http_upload_eval_state_path(njt_http_request_t *r);
// static char *njt_http_upload_pass_form_field(njt_conf_t *cf, njt_command_t *cmd,
//     void *conf);
// static char *njt_http_upload_set_path_slot(njt_conf_t *cf, njt_command_t *cmd,
//     void *conf);
// static char *njt_http_upload_merge_path_value(njt_conf_t *cf, njt_http_upload_path_t **path, njt_http_upload_path_t *prev,
//     njt_path_init_t *init);
// static char *njt_http_upload_cleanup(njt_conf_t *cf, njt_command_t *cmd,
//     void *conf);
static void njt_upload_cleanup_handler(void *data);

static njt_int_t
njt_http_upload_sha_filename(njt_str_t *v, uintptr_t data, u_char *digest,
    njt_uint_t digest_len);

// #if defined njet_version && njet_version >= 7052
// static njt_path_init_t        njt_http_upload_temp_path = {
//     njt_string(NJT_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
// };
// #endif

/*
 * upload_init_ctx
 *
 * Initialize upload context. Memory for upload context which is being passed
 * as upload_ctx parameter could be allocated anywhere and should not be freed
 * prior to upload_shutdown_ctx call.
 *
 * IMPORTANT:
 * 
 * After initialization the following routine SHOULD BE called:
 * 
 * upload_parse_content_type -- to assign part boundary 
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 * 
 */
static void upload_init_ctx(njt_http_upload_ctx_t *upload_ctx);

/*
 * upload_shutdown_ctx
 *
 * Shutdown upload context. Discard all remaining data and 
 * free all memory associated with upload context.
 *
 * Parameter:
 *     upload_ctx -- upload context which is being shut down
 * 
 */
static void upload_shutdown_ctx(njt_http_upload_ctx_t *upload_ctx);

/*
 * upload_start
 *
 * Starts multipart stream processing. Initializes internal buffers
 * and pointers
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 * 
 * Return value:
 *               NJT_OK on success
 *               NJT_ERROR if error has occured
 *
 */
static njt_int_t upload_start(njt_http_upload_ctx_t *upload_ctx, njt_http_upload_loc_conf_t  *ulcf);

/*
 * upload_parse_request_headers
 *
 * Parse and verify HTTP headers, extract boundary or
 * content disposition
 * 
 * Parameters:
 *     upload_ctx -- upload context to populate
 *     headers_in -- request headers
 *
 * Return value:
 *     NJT_OK on success
 *     NJT_ERROR if error has occured
 */
static njt_int_t upload_parse_request_headers(njt_http_upload_ctx_t *upload_ctx, njt_http_headers_in_t *headers_in);

/*
 * upload_process_buf
 *
 * Process buffer with multipart stream starting from start and terminating
 * by end, operating on upload_ctx. The header information is accumulated in
 * This call can invoke one or more calls to start_upload_file, finish_upload_file,
 * abort_upload_file and flush_output_buffer routines.
 *
 * Returns value NJT_OK successful
 *               NJT_UPLOAD_MALFORMED stream is malformed
 *               NJT_UPLOAD_NOMEM insufficient memory 
 *               NJT_UPLOAD_IOERROR input-output error
 *               NJT_UPLOAD_SCRIPTERROR njet script engine failed
 *               NJT_UPLOAD_TOOLARGE field body is too large
 */
static njt_int_t upload_process_buf(njt_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end);
static njt_int_t upload_process_raw_buf(njt_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end);

static njt_command_t  njt_http_upload_commands[] = { /* {{{ */

    // /*
    //  * Enables uploads for location and specifies location to pass modified request to  
    //  */
    // { njt_string("upload_pass"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_http_upload_pass,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   0,
    //   NULL },

    // /*
    //  * Specifies base path of file store
    //  */
    // { njt_string("upload_store"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1234,
    //   njt_http_upload_set_path_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, store_path),
    //   NULL },

    // /*
    //  * Specifies base path of state store
    //  */
    // { njt_string("upload_state_store"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1234,
    //   njt_http_upload_set_path_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, state_store_path),
    //   NULL },

    // /*
    //  * Specifies the access mode for files in store
    //  */
    // { njt_string("upload_store_access"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE123,
    //   njt_conf_set_access_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, store_access),
    //   NULL },

    // /*
    //  * Specifies the size of buffer, which will be used
    //  * to write data to disk
    //  */
    // { njt_string("upload_buffer_size"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, buffer_size),
    //   NULL },

    // /*
    //  * Specifies the size of buffer, which will be used
    //  * for merging ranges into state file
    //  */
    // { njt_string("upload_merge_buffer_size"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, merge_buffer_size),
    //   NULL },

    // /*
    //  * Specifies the size of buffer, which will be used
    //  * for returning range header
    //  */
    // { njt_string("upload_range_header_buffer_size"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, range_header_buffer_size),
    //   NULL },

    // /*
    //  * Specifies the maximal length of the part header
    //  */
    // { njt_string("upload_max_part_header_len"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, max_header_len),
    //   NULL },

    // /*
    //  * Specifies the maximal size of the file to be uploaded
    //  */
    // { njt_string("upload_max_file_size"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_conf_set_off_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, max_file_size),
    //   NULL },

    // /*
    //  * Specifies the maximal length of output body
    //  */
    // { njt_string("upload_max_output_body_len"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, max_output_body_len),
    //   NULL },

    // /*
    //  * Specifies the field to set in altered response body
    //  */
    // { njt_string("upload_set_form_field"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE2,
    //   njt_http_upload_set_form_field,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, field_templates),
    //   NULL},

    // /*
    //  * Specifies the field with aggregate parameters
    //  * to set in altered response body
    //  */
    // { njt_string("upload_aggregate_form_field"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE2,
    //   njt_http_upload_set_form_field,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, aggregate_field_templates),
    //   NULL},

    // /*
    //  * Specifies the field to pass to backend
    //  */
    // { njt_string("upload_pass_form_field"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_http_upload_pass_form_field,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   0,
    //   NULL},

    // /*
    //  * Specifies http statuses upon reception of
    //  * which cleanup of uploaded files will be initiated
    //  */
    // { njt_string("upload_cleanup"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_1MORE,
    //   njt_http_upload_cleanup,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   0,
    //   NULL},

    //  /*
    //   * Specifies the whether or not to forward query args
    //   * to the upload_pass redirect location
    //   */
    //  { njt_string("upload_pass_args"),
    //    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                      |NJT_CONF_FLAG,
    //    njt_conf_set_flag_slot,
    //    NJT_HTTP_LOC_CONF_OFFSET,
    //    offsetof(njt_http_upload_loc_conf_t, forward_args),
    //    NULL },

    //  /*
    //   * Specifies request body reception rate limit
    //   */
    // { njt_string("upload_limit_rate"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE1,
    //   njt_conf_set_size_slot,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, limit_rate),
    //   NULL },

    //  /*
    //   * Specifies whether array brackets in file field names must be dropped
    //   */
    //  { njt_string("upload_tame_arrays"),
    //    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                      |NJT_CONF_FLAG,
    //    njt_conf_set_flag_slot,
    //    NJT_HTTP_LOC_CONF_OFFSET,
    //    offsetof(njt_http_upload_loc_conf_t, tame_arrays),
    //    NULL },

    //  /*
    //   * Specifies whether resumable uploads are allowed
    //   */
    //  { njt_string("upload_resumable"),
    //    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                      |NJT_CONF_FLAG,
    //    njt_conf_set_flag_slot,
    //    NJT_HTTP_LOC_CONF_OFFSET,
    //    offsetof(njt_http_upload_loc_conf_t, resumable_uploads),
    //    NULL },

    //  /*
    //   * Specifies whether empty field names are allowed
    //   */
    //  { njt_string("upload_empty_fiels_names"),
    //    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                      |NJT_CONF_FLAG,
    //    njt_conf_set_flag_slot,
    //    NJT_HTTP_LOC_CONF_OFFSET,
    //    offsetof(njt_http_upload_loc_conf_t, empty_field_names),
    //    NULL },

    // /*
    //  * Specifies the name and content of the header that will be added to the response
    //  */
    // { njt_string("upload_add_header"),
    //   NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_HTTP_LMT_CONF|NJT_HTTP_LIF_CONF
    //                     |NJT_CONF_TAKE2,
    //   njt_http_upload_set_form_field,
    //   NJT_HTTP_LOC_CONF_OFFSET,
    //   offsetof(njt_http_upload_loc_conf_t, header_templates),
    //   NULL},

      njt_null_command
}; /* }}} */

njt_http_module_t  njt_http_upload_module_ctx = { /* {{{ */
    // njt_http_upload_add_variables,         /* preconfiguration */
    NULL,
    njt_http_dyn_crl_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    njt_http_upload_create_loc_conf,       /* create location configuration */
    njt_http_upload_merge_loc_conf         /* merge location configuration */
}; /* }}} */

njt_module_t  njt_http_upload_module = { /* {{{ */
    NJT_MODULE_V1,
    &njt_http_upload_module_ctx,           /* module context */
    njt_http_upload_commands,              /* module directives */
    NJT_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
}; /* }}} */

// static njt_http_variable_t  njt_http_upload_variables[] = { /* {{{ */

//     { njt_string("upload_field_name"), NULL, njt_http_upload_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, field_name),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_content_type"),
//       NULL,
//       njt_http_upload_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, content_type),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_name"), NULL, njt_http_upload_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, file_name),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_number"), NULL, njt_http_upload_uint_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, ordinal),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_tmp_path"), NULL, njt_http_upload_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, output_file.name),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_content_range"),
//       njt_http_upload_content_range_variable_set,
//       njt_http_upload_content_range_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, content_range_n),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     njt_http_null_variable
// }; /* }}} */

// static njt_http_variable_t  njt_http_upload_aggregate_variables[] = { /* {{{ */

//     { njt_string("upload_file_md5"), NULL, njt_http_upload_md5_variable,
//       (uintptr_t) "0123456789abcdef",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_md5_uc"), NULL, njt_http_upload_md5_variable,
//       (uintptr_t) "0123456789ABCDEF",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_sha1"), NULL, njt_http_upload_sha1_variable,
//       (uintptr_t) "0123456789abcdef",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_sha1_uc"), NULL, njt_http_upload_sha1_variable,
//       (uintptr_t) "0123456789ABCDEF",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_sha256"), NULL, njt_http_upload_sha256_variable,
//       (uintptr_t) "0123456789abcdef",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_sha256_uc"), NULL, njt_http_upload_sha256_variable,
//       (uintptr_t) "0123456789ABCDEF",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_sha512"), NULL, njt_http_upload_sha512_variable,
//       (uintptr_t) "0123456789abcdef",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_sha512_uc"), NULL, njt_http_upload_sha512_variable,
//       (uintptr_t) "0123456789ABCDEF",
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_crc32"), NULL, njt_http_upload_crc32_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, crc32),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     { njt_string("upload_file_size"), NULL, njt_http_upload_file_size_variable,
//       (uintptr_t) offsetof(njt_http_upload_ctx_t, output_file.offset),
//       NJT_HTTP_VAR_CHANGEABLE|NJT_HTTP_VAR_NOCACHEABLE|NJT_HTTP_VAR_NOHASH, 0, NJT_VAR_INIT_REF_COUNT },

//     njt_http_null_variable
// }; /* }}} */

static njt_str_t  njt_http_upload_empty_field_value = njt_null_string;

static njt_str_t  njt_upload_field_part1 = { /* {{{ */
    sizeof(CRLF CONTENT_DISPOSITION_STRING " form-data; name=\"") - 1,
    (u_char*)CRLF CONTENT_DISPOSITION_STRING " form-data; name=\""
}; /* }}} */

static njt_str_t  njt_upload_field_part2 = { /* {{{ */
    sizeof("\"" CRLF CRLF) - 1,
    (u_char*)"\"" CRLF CRLF
}; /* }}} */


// static void *
// njt_http_dyn_ssl_create_main_conf(njt_conf_t *cf) {
//     //ssize_t size;
//     //njt_str_t zone = njt_string("api_dy_server");

//     njt_http_dyn_ssl_main_conf_t *uclcf;

//     //size = (ssize_t)(10 * njt_pagesize);
//     uclcf = njt_pcalloc(cf->pool, sizeof(njt_http_dyn_ssl_main_conf_t));
//     if (uclcf == NULL) {
//         njt_log_error(NJT_LOG_ERR, cf->log, 0, "malloc njt_http_dyn_ssl_main_conf_t eror");
//         return NULL;
//     }
// 	uclcf->size = NJT_CONF_UNSET;
//     return uclcf;
// }


static njt_int_t
njt_http_dyn_crl_init(njt_conf_t *cf) {
    njt_http_api_reg_info_t             h;
	// njt_http_dyn_ssl_main_conf_t        *dlmcf;

    // dlmcf = njt_http_conf_get_module_main_conf(cf,njt_http_ssl_api_module);
    // if(dlmcf == NULL){
    //     return NJT_ERROR;
    // }

    // if(dlmcf->size == NJT_CONF_UNSET){
    //     dlmcf->size = 500;
    // }

    // dlmcf->reqs = njt_pcalloc(cf->pool, sizeof(njt_http_request_t*)*dlmcf->size);
    // if(dlmcf->reqs == NULL){
    //     njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "njt_http_dyn_ssl_postconfiguration alloc mem error");
    //     return NJT_ERROR;
    // }

    njt_str_t  module_key = njt_string("/v1/upload");
    njt_memzero(&h, sizeof(njt_http_api_reg_info_t));
    h.key = &module_key;
    h.handler = njt_http_upload_handler;
    njt_http_api_module_reg_handler(&h);

    return NJT_OK;
}


static njt_int_t /* {{{ njt_http_upload_handler */
njt_http_upload_handler(njt_http_request_t *r)
{
    njt_http_upload_loc_conf_t  *ulcf;
    njt_http_upload_ctx_t     *u;
    njt_int_t                 rc;

    if(r->method & NJT_HTTP_OPTIONS)
        return njt_http_upload_options_handler(r);

    if (!(r->method & NJT_HTTP_POST))
        return NJT_HTTP_NOT_ALLOWED;

    ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);

    u = njt_http_get_module_ctx(r, njt_http_upload_module);

    if (u == NULL) {
        u = njt_pcalloc(r->pool, sizeof(njt_http_upload_ctx_t));
        if (u == NULL) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        njt_http_set_ctx(r, u, njt_http_upload_module);
    }

    if(ulcf->md5) {
        if(u->md5_ctx == NULL) {
            u->md5_ctx = njt_palloc(r->pool, sizeof(njt_http_upload_md5_ctx_t));
            if (u->md5_ctx == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->md5_ctx = NULL;

    if(ulcf->sha1) {
        if(u->sha1_ctx == NULL) {
            u->sha1_ctx = njt_palloc(r->pool, sizeof(njt_http_upload_sha1_ctx_t));
            if (u->sha1_ctx == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->sha1_ctx = NULL;

    if(ulcf->sha256) {
        if(u->sha256_ctx == NULL) {
            u->sha256_ctx = njt_palloc(r->pool, sizeof(njt_http_upload_sha256_ctx_t));
            if (u->sha256_ctx == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->sha256_ctx = NULL;

    if(ulcf->sha512) {
        if(u->sha512_ctx == NULL) {
            u->sha512_ctx = njt_palloc(r->pool, sizeof(njt_http_upload_sha512_ctx_t));
            if (u->sha512_ctx == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->sha512_ctx = NULL;

    u->calculate_crc32 = ulcf->crc32;

    u->request = r;
    u->log = r->connection->log;
    u->chain = u->last = u->checkpoint = NULL;
    u->output_body_len = 0;

    u->prevent_output = 0;
    u->no_content = 1;
    u->limit_rate = ulcf->limit_rate;
    u->received = 0;
    u->ordinal = 0;

    upload_init_ctx(u);

    rc = upload_parse_request_headers(u, &r->headers_in);

    if(rc != NJT_OK) {
        upload_shutdown_ctx(u);
        return rc;
    }

    rc = njt_http_upload_eval_path(r);

    if(rc != NJT_OK) {
        upload_shutdown_ctx(u);
        return rc;
    }

    // rc = njt_http_upload_eval_state_path(r);

    // if(rc != NJT_OK) {
    //     upload_shutdown_ctx(u);
    //     return rc;
    // }

    if (njt_http_upload_test_expect(r) != NJT_OK) {
        upload_shutdown_ctx(u);
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    if(upload_start(u, ulcf) != NJT_OK)
        return NJT_HTTP_INTERNAL_SERVER_ERROR;

#if (NJT_HTTP_V2)
    if (r->stream) {
        r->request_body_no_buffering = 1;

        rc = njt_http_read_client_request_body(r, njt_http_upload_read_event_handler);

        if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            upload_shutdown_ctx(u);
            return rc;
        }

        return NJT_DONE;
    }
#endif

    rc = njt_http_read_upload_client_request_body(r);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NJT_DONE;
} /* }}} */

#if (NJT_HTTP_V2)
static void
njt_http_upload_read_event_handler(njt_http_request_t *r)
{
    njt_http_upload_ctx_t      *u;
    njt_http_request_body_t    *rb;
    njt_int_t                   rc;
    njt_chain_t                *in;
    ssize_t                     n, limit, buf_read_size, next_buf_size, remaining;
    njt_msec_t                  delay;
    njt_event_t                *rev;

    if (njt_exiting || njt_terminate) {
        njt_http_finalize_request(r, NJT_HTTP_CLOSE);
        return;
    }

    rev = r->connection->read;
    rb = r->request_body;

    if (rb == NULL) {
        njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    r->read_event_handler = njt_http_upload_read_event_handler;

    u = njt_http_get_module_ctx(r, njt_http_upload_module);

    for ( ;; ) {
        buf_read_size = 0;

        for (in = rb->bufs ; in; in = in->next) {
            n = in->buf->last - in->buf->pos;

            rc = u->data_handler(u, in->buf->pos, in->buf->pos + n);

            in->buf->pos += n;
            u->received += n;
            buf_read_size += n;

            if (rc != NJT_OK) {
                goto err;
            }
        }
        rb->bufs = NULL;

        // We're done reading the request body, break out of loop
        if (!r->reading_body) {
            rc = u->data_handler(u, NULL, NULL);
            if (rc == NJT_OK) {
                break;
            } else {
                goto err;
            }
        }

        // Check whether we have exceeded limit_rate and should delay the next
        // buffer read
        if (u->limit_rate) {
            remaining = ((ssize_t) r->headers_in.content_length_n) - u->received;
            next_buf_size = (buf_read_size > remaining) ? remaining : buf_read_size;
            limit = u->limit_rate * (njt_time() - r->start_sec + 1) - (u->received + next_buf_size);
            if (limit < 0) {
                rev->delayed = 1;
                njt_add_timer(rev, (njt_msec_t) ((limit * -1000 / u->limit_rate) + 1));
                return;
            }
        }

        rc = njt_http_read_unbuffered_request_body(r);

        if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
            goto err;
        }

        if (rb->bufs == NULL) {
            return;
        }

        // Check whether we should delay processing the latest request body
        // buffers to stay within limit_rate
        if (u->limit_rate) {
            buf_read_size = 0;
            for (in = rb->bufs ; in; in = in->next) {
                buf_read_size += (in->buf->last - in->buf->pos);
            }
            delay = (njt_msec_t) (buf_read_size * 1000 / u->limit_rate + 1);
            if (delay > 0) {
                rev->delayed = 1;
                njt_add_timer(rev, delay);
                return;
            }
        }
    }

    // Finally, send the response
    rc = njt_http_upload_body_handler(r);
    // rc = NJT_OK;
err:
    switch(rc) {
        case NJT_UPLOAD_MALFORMED:
            rc = NJT_HTTP_BAD_REQUEST;
            break;
        case NJT_UPLOAD_TOOLARGE:
            rc = NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
            break;
        case NJT_UPLOAD_IOERROR:
            rc = NJT_HTTP_SERVICE_UNAVAILABLE;
            break;
        case NJT_UPLOAD_NOMEM:
        case NJT_UPLOAD_SCRIPTERROR:
            rc = NJT_HTTP_INTERNAL_SERVER_ERROR;
            break;
    }
    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        upload_shutdown_ctx(u);
        njt_http_finalize_request(r, rc);
    }
}
#endif

static njt_int_t njt_http_upload_add_headers(njt_http_request_t *r, njt_http_upload_loc_conf_t *ulcf) { /* {{{ */
    njt_str_t                            name;
    njt_str_t                            value;
    njt_http_upload_field_template_t     *t;
    njt_table_elt_t                      *h;
    njt_uint_t                           i;

    if (ulcf->header_templates != NULL) {
        t = ulcf->header_templates->elts;
        for (i = 0; i < ulcf->header_templates->nelts; i++) {
            if (njt_http_upload_process_field_templates(r, &t[i], &name, &value) != NJT_OK) {
                return NJT_ERROR;
            }

            if(name.len != 0 && value.len != 0) {
                h = njt_list_push(&r->headers_out.headers);
                if(h == NULL) {
                    return NJT_ERROR;
                }

                h->hash = 1;
                h->key.len = name.len;
                h->key.data = name.data;
                h->value.len = value.len;
                h->value.data = value.data;
            }
        }
    }

    return NJT_OK;
} /* }}} */

static njt_int_t /* {{{  */
njt_http_upload_eval_path(njt_http_request_t *r) {
    njt_http_upload_ctx_t       *u;
    njt_http_upload_loc_conf_t  *ulcf;
    njt_str_t                   value;

    ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);
    u = njt_http_get_module_ctx(r, njt_http_upload_module);

    if(ulcf->store_path->is_dynamic) {
        u->store_path = njt_pcalloc(r->pool, sizeof(njt_path_t));
        if(u->store_path == NULL) {
            return NJT_ERROR;
        }

        njt_memcpy(u->store_path, ulcf->store_path->path, sizeof(njt_path_t));

        if(njt_http_complex_value(r, &ulcf->store_path->dynamic, &value) != NJT_OK) {
            return NJT_ERROR;
        }

        u->store_path->name.data = value.data;
        u->store_path->name.len = value.len;
    }
    else{
        u->store_path = ulcf->store_path->path;
    }

    return NJT_OK;
} /* }}} */

// static njt_int_t /* {{{  */
// njt_http_upload_eval_state_path(njt_http_request_t *r) {
//     njt_http_upload_ctx_t       *u;
//     njt_http_upload_loc_conf_t  *ulcf;
//     njt_str_t                   value;

//     ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);
//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     if(ulcf->state_store_path->is_dynamic) {
//         u->state_store_path = njt_pcalloc(r->pool, sizeof(njt_path_t));
//         if(u->store_path == NULL) {
//             return NJT_ERROR;
//         }

//         njt_memcpy(u->state_store_path, ulcf->state_store_path->path, sizeof(njt_path_t));

//         if(njt_http_complex_value(r, &ulcf->state_store_path->dynamic, &value) != NJT_OK) {
//             return NJT_ERROR;
//         }

//         u->state_store_path->name.data = value.data;
//         u->state_store_path->name.len = value.len;
//     }
//     else{
//         u->state_store_path = ulcf->state_store_path->path;
//     }

//     return NJT_OK;
// } /* }}} */

static njt_int_t njt_http_upload_options_handler(njt_http_request_t *r) { /* {{{ */
    njt_http_upload_loc_conf_t *ulcf;

    ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);

    r->headers_out.status = NJT_HTTP_OK;

    if(njt_http_upload_add_headers(r, ulcf) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    r->allow_ranges = 0;

    return njt_http_send_header(r);
} /* }}} */



static int njt_http_upload_ok_request_output(njt_http_request_t *r){
    njt_int_t rc;
    njt_buf_t *buf;
    njt_chain_t out;
    njt_str_t   msg;
    u_char      *p;
    u_char      tmp_buf[1024];
    u_char      sha256[256];
    njt_str_t   tmp_sha;
    njt_http_upload_ctx_t     *u = njt_http_get_module_ctx(r, njt_http_upload_module);

    r->headers_out.status = NJT_HTTP_OK;

    njt_memzero(sha256, 256);
    tmp_sha.data = sha256;
    njt_http_upload_sha_filename(&tmp_sha, (uintptr_t) "0123456789abcdef", u->sha256_ctx->sha256_digest, SHA256_DIGEST_LENGTH);

    msg.data = tmp_buf;
    p = njt_sprintf(msg.data, "{\"code\":200,\"file\":\"%V.dat\"}", &tmp_sha);
    msg.len = p - msg.data;

    njt_str_t type=njt_string("application/json");
    r->headers_out.content_type = type;
    r->headers_out.content_length_n = msg.len;

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }
    rc = njt_http_send_header(r);
    if(rc == NJT_ERROR || rc > NJT_OK || r->header_only){
        return rc;
    }
    buf = njt_create_temp_buf(r->pool, msg.len);
    if(buf == NULL){
        return NJT_ERROR;
    }

    njt_memcpy(buf->pos, msg.data, msg.len);
    buf->last = buf->pos + msg.len;
    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;

    njt_http_finalize_request(r, njt_http_output_filter(r, &out));

    return NJT_OK;
}


static njt_int_t njt_http_upload_body_handler(njt_http_request_t *r) { /* {{{ */
    njt_http_upload_loc_conf_t  *ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);
    njt_http_upload_ctx_t       *ctx = njt_http_get_module_ctx(r, njt_http_upload_module);

    // njt_str_t                   args;
    // njt_uint_t                  flags;
    njt_int_t                   rc;
    // njt_str_t                   uri;
    njt_buf_t                      *b;
    // njt_chain_t                    *cl, out;
    njt_chain_t                 out;
    njt_str_t                   dummy = njt_string("<njt_upload_module_dummy>");
    njt_table_elt_t             *h;

    if(ctx->prevent_output) {
        r->headers_out.status = NJT_HTTP_CREATED;

        /*
         * Add range header and body
         */
        if(ctx->range_header_buffer_pos != ctx->range_header_buffer) {
            h = njt_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            h->hash = 1;
            h->key.len = sizeof("Range") - 1;
            h->key.data = (u_char *) "Range";
            h->value.len = ctx->range_header_buffer_pos - ctx->range_header_buffer;
            h->value.data = ctx->range_header_buffer;

            b = njt_pcalloc(r->pool, sizeof(njt_buf_t));
            if (b == NULL) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            r->headers_out.content_length_n = h->value.len;

            r->allow_ranges = 0;

            rc = njt_http_send_header(r);

            if(rc == NJT_ERROR) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            if(rc > NJT_OK) {
                return rc;
            }

            b->in_file = 0;
            b->memory = 1;
            b->last_buf = b->last_in_chain = b->flush = 1;

            b->start = b->pos = ctx->range_header_buffer;
            b->last = ctx->range_header_buffer_pos;
            b->end = ctx->range_header_buffer_end;

            out.buf = b;
            out.next = NULL;

            njt_http_finalize_request(r, njt_http_output_filter(r, &out));
        }
        else {
            r->header_only = 1;
            r->headers_out.content_length_n = 0;

            njt_http_finalize_request(r, njt_http_send_header(r));
        }

        return NJT_OK;
    }

    if(ulcf->max_output_body_len != 0) {
        if(ctx->output_body_len + ctx->boundary.len + 4 > ulcf->max_output_body_len)
            return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    if(ctx->no_content) {
        rc = njt_http_upload_append_field(ctx, &dummy, &njt_http_upload_empty_field_value);

        if(rc != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return njt_http_upload_ok_request_output(r);

//     /*
//      * Append final boundary
//      */
//     b = njt_create_temp_buf(r->pool, ctx->boundary.len + 4);

//     if (b == NULL) {
//         return NJT_HTTP_INTERNAL_SERVER_ERROR;
//     }

//     cl = njt_alloc_chain_link(r->pool);
//     if (cl == NULL) {
//         return NJT_HTTP_INTERNAL_SERVER_ERROR;
//     }

//     b->last_in_chain = 1;
//     b->last_buf = 1;

//     cl->buf = b;
//     cl->next = NULL;
    
//     if(ctx->chain == NULL) {
//         ctx->chain = cl;
//         ctx->last = cl;
//     }else{
//         ctx->last->next = cl;
//         ctx->last = cl;
//     }

//     b->last = njt_cpymem(b->last, ctx->boundary.data, ctx->boundary.len);

//     *b->last++ = '-';
//     *b->last++ = '-';
//     *b->last++ = CR;
//     *b->last++ = LF;

//     if (ulcf->url_cv) {
//         /* complex value */
//         if (njt_http_complex_value(r, ulcf->url_cv, &uri) != NJT_OK) {
//             return NJT_HTTP_INTERNAL_SERVER_ERROR;
//         }

//         if (uri.len == 0) {
//             njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
//                           "empty \"upload_pass\" (was: \"%V\")",
//                           &ulcf->url_cv->value);

//             return NJT_HTTP_INTERNAL_SERVER_ERROR;
//         }
//     } else {
//         /* simple value */
//         uri = ulcf->url;
//     }

//     if (ulcf->forward_args) {
//       args = r->args; /* forward the query args */
//     }
//     else {
//       args.len = 0;
//       args.data = NULL;
//     }

//     flags = 0;

//     if (njt_http_parse_unsafe_uri(r, &uri, &args, &flags) != NJT_OK) {
//         return NJT_HTTP_INTERNAL_SERVER_ERROR;
//     }

//     r->request_body->bufs = ctx->chain;

//     // Recalculate content length
//     r->headers_in.content_length_n = 0;

//     for(cl = ctx->chain ; cl ; cl = cl->next)
//         r->headers_in.content_length_n += (cl->buf->last - cl->buf->pos);

//     r->headers_in.content_length->value.data = njt_palloc(r->pool, NJT_OFF_T_LEN);

//     if (r->headers_in.content_length->value.data == NULL) {
//         return NJT_HTTP_INTERNAL_SERVER_ERROR;
//     }

//     r->headers_in.content_length->value.len =
//         njt_sprintf(r->headers_in.content_length->value.data, "%O", r->headers_in.content_length_n)
//             - r->headers_in.content_length->value.data;

// #if defined njet_version && njet_version >= 8011
//     r->main->count--;
// #endif

//     if(uri.len != 0 && uri.data[0] == '/') {
//         rc = njt_http_internal_redirect(r, &uri, &args);
//     }
//     else{
//         rc = njt_http_named_location(r, &uri);
//     }

//     if (rc == NJT_ERROR) {
//         return NJT_HTTP_INTERNAL_SERVER_ERROR;
//     }

//     return rc;
} /* }}} */

static njt_int_t
njt_http_upload_process_field_templates(
    njt_http_request_t *r, njt_http_upload_field_template_t *t,
    njt_str_t *name, njt_str_t *value)
{
    if (t->field_lengths == NULL) {
        *name = t->value.key;
    } else if (njt_http_script_run(r, name, t->field_lengths->elts, 0,
                                   t->field_values->elts) == NULL) {
        return NJT_UPLOAD_SCRIPTERROR;
    }

    if (t->value_lengths == NULL) {
        *value = t->value.value;
    } else if (njt_http_script_run(r, value, t->value_lengths->elts, 0,
                                   t->value_values->elts) == NULL) {
            return NJT_UPLOAD_SCRIPTERROR;
    }
    return NJT_OK;
}

static njt_int_t njt_http_upload_start_handler(njt_http_upload_ctx_t *u) { /* {{{ */
    njt_http_request_t        *r = u->request;
    njt_http_upload_loc_conf_t  *ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);

    njt_file_t  *file = &u->output_file;
    njt_path_t  *path = u->store_path;
    // njt_path_t  *path = &njt_cycle->conf_prefix;
    // njt_path_t  *state_path = u->state_store_path;
    uint32_t    n;
    u_char      *p;
    njt_uint_t  i;
    njt_int_t   rc;
    njt_err_t   err;
    njt_http_upload_field_template_t    *t;
    njt_http_upload_field_filter_t    *f;
    njt_str_t   field_name, field_value;
    njt_uint_t  pass_field;
    njt_upload_cleanup_t  *ucln;

    if(u->is_file) {
        u->ordinal++;

        u->cln = njt_pool_cleanup_add(r->pool, sizeof(njt_upload_cleanup_t));

        if(u->cln == NULL)
            return NJT_UPLOAD_NOMEM;

        // file->name.len = path->name.len + 1 + path->len + (u->session_id.len != 0 ? u->session_id.len : 10);
        file->name.len = path->name.len + 256 + 1;

        file->name.data = njt_palloc(u->request->pool, file->name.len);

        if(file->name.data == NULL)
            return NJT_UPLOAD_NOMEM;

        // njt_memcpy(file->name.data, path->name.data, path->name.len);
// njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "==========feilename:%V  path:%V", &file->name, &path->name);
        file->log = r->connection->log;

        if(u->session_id.len != 0) {
//             (void) njt_sprintf(file->name.data + path->name.len + 1 + path->len,
//                                "%V%Z", &u->session_id);

//             njt_create_hashed_filename(path, file->name.data, file->name.len);

//             njt_log_debug1(NJT_LOG_DEBUG_CORE, file->log, 0,
//                            "hashed path: %s", file->name.data);

//             if(u->partial_content) {
//                 njt_file_t *state_file = &u->state_file;
//                 if(u->merge_buffer == NULL) {
//                     u->merge_buffer = njt_palloc(r->pool, ulcf->merge_buffer_size);

//                     if(u->merge_buffer == NULL)
//                         return NJT_UPLOAD_NOMEM;
//                 }

//                 state_file->name.len = state_path->name.len + 1 + state_path->len + u->session_id.len + sizeof(".state")-1;
//                 state_file->name.data = njt_palloc(u->request->pool, state_file->name.len + 1);

//                 if(state_file->name.data == NULL)
//                     return NJT_UPLOAD_NOMEM;

//                 njt_memcpy(state_file->name.data, state_path->name.data, state_path->name.len);
//                 (void) njt_sprintf(state_file->name.data + state_path->name.len + 1 + state_path->len,
//                         "%V.state%Z", &u->session_id);

//                 njt_create_hashed_filename(state_path, state_file->name.data, state_file->name.len);

//                 njt_log_debug1(NJT_LOG_DEBUG_CORE, file->log, 0,
//                                "hashed path of state file: %s", state_file->name.data);
//             }

//             file->fd = njt_open_file(file->name.data, NJT_FILE_WRONLY, NJT_FILE_CREATE_OR_OPEN, ulcf->store_access);
// njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "========== sesstion feilename:%V", &file->name);
//             if (file->fd == NJT_INVALID_FILE) {
//                 err = njt_errno;

//                 njt_log_error(NJT_LOG_ERR, r->connection->log, njt_errno,
//                               "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
//                 return NJT_UPLOAD_IOERROR;
//             }

//             file->offset = u->content_range_n.start;
        }
        else{
            for(;;) {
                n = (uint32_t) njt_next_temp_number(0);
// njt_log_error(NJT_LOG_EMERG, njt_cycle->log, 0, "========== before hash filename:%V u_filename:%V", &file->name, &u->file_name);
                // (void) njt_sprintf(file->name.data + path->name.len + 1 + path->len,
                //                    "%010uD%Z", n);

                // njt_create_hashed_filename(path, file->name.data, file->name.len);
                p = njt_sprintf(file->name.data, "%V/%010uD%Z", &path->name, n);
                file->name.len = p - file->name.data;
                njt_log_debug1(NJT_LOG_DEBUG_CORE, file->log, 0,
                               "hashed path: %s", file->name.data);

                file->fd = njt_open_tempfile(file->name.data, 1, ulcf->store_access);

                if (file->fd != NJT_INVALID_FILE) {
                    file->offset = 0;
                    break;
                }

                err = njt_errno;

                if (err == NJT_EEXIST) {
                    n = (uint32_t) njt_next_temp_number(1);
                    continue;
                }

                njt_log_error(NJT_LOG_ERR, r->connection->log, njt_errno,
                            "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
                return NJT_UPLOAD_IOERROR;
            }
        }

        u->cln->handler = njt_upload_cleanup_handler;

        ucln = u->cln->data;
        ucln->fd = file->fd;
        ucln->filename = file->name.data;
        ucln->log = r->connection->log;
        ucln->headers_out = &r->headers_out;
        ucln->cleanup_statuses = ulcf->cleanup_statuses;
        ucln->aborted = 0;

        if(ulcf->field_templates) {

            if(ulcf->tame_arrays && u->field_name.len > 2 &&
                u->field_name.data[u->field_name.len - 1] == ']' &&
                u->field_name.data[u->field_name.len - 2] == '[')
            {
                u->field_name.len -= 2;
            }

            t = ulcf->field_templates->elts;
            for (i = 0; i < ulcf->field_templates->nelts; i++) {
                rc = njt_http_upload_process_field_templates(r, &t[i], &field_name, &field_value);

                if(rc != NJT_OK)
                    goto cleanup_file;

                rc = njt_http_upload_append_field(u, &field_name, &field_value);

                if(rc != NJT_OK)
                    goto cleanup_file;
            }
        }

        if(u->md5_ctx != NULL)
            MD5Init(&u->md5_ctx->md5);

        if(u->sha1_ctx != NULL)
            SHA1_Init(&u->sha1_ctx->sha1);

        if(u->sha256_ctx != NULL)
            SHA256_Init(&u->sha256_ctx->sha256);

        if(u->sha512_ctx != NULL)
            SHA512_Init(&u->sha512_ctx->sha512);

        if(u->calculate_crc32)
            njt_crc32_init(u->crc32);

        if(u->partial_content) {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0
                , "started uploading part %O-%O/%O of file \"%V\" to \"%V\" (field \"%V\", content type \"%V\")"
                , u->content_range_n.start
                , u->content_range_n.end
                , u->content_range_n.total
                , &u->file_name
                , &u->output_file.name
                , &u->field_name
                , &u->content_type
                );
        }
        else {
            njt_log_error(NJT_LOG_INFO, r->connection->log, 0
                , "started uploading file \"%V\" to \"%V\" (field \"%V\", content type \"%V\")"
                , &u->file_name
                , &u->output_file.name
                , &u->field_name
                , &u->content_type
                );
        }
    }else{
        pass_field = 0;

        if(ulcf->field_filters) {
            f = ulcf->field_filters->elts;
            for (i = 0; i < ulcf->field_filters->nelts; i++) {
#if (NJT_PCRE)
                rc = njt_regex_exec(f[i].regex, &u->field_name, NULL, 0);

                /* Modified by Naren to work around iMovie and Quicktime which send empty values Added:  &&  u->field_name.len > 0 */
                if ((ulcf->empty_field_names && rc != NJT_REGEX_NO_MATCHED && rc < 0 && u->field_name.len != 0)
                    || (!ulcf->empty_field_names && rc != NJT_REGEX_NO_MATCHED && rc < 0))
                {
                    return NJT_UPLOAD_SCRIPTERROR;
                }

                /*
                 * If at least one filter succeeds, we pass the field
                 */
                if(rc == 0)
                    pass_field = 1;
#else
                if(njt_strncmp(f[i].text.data, u->field_name.data, u->field_name.len) == 0)
                    pass_field = 1;
#endif
            }
        }

        if(pass_field && u->field_name.len != 0) { 
            /*
             * Here we do a small hack: the content of a non-file field
             * is not known until njt_http_upload_flush_output_buffer
             * is called. We pass empty field value to simplify things.
             */
            rc = njt_http_upload_append_field(u, &u->field_name, &njt_http_upload_empty_field_value);

            if(rc != NJT_OK)
                return rc;
        }else
            u->discard_data = 1;
    }


    if(njt_http_upload_add_headers(r, ulcf) != NJT_OK) {
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NJT_OK;

cleanup_file:
    return rc;
} /* }}} */



static njt_int_t
njt_http_upload_sha_filename(njt_str_t *v, uintptr_t data, u_char *digest,
    njt_uint_t digest_len)
{
    njt_uint_t             i;
    u_char                 *c;
    u_char                 *p;
    u_char                 *hex_table;

    hex_table = (u_char*)data;
    // p = data;
    p = v->data;
    c = p + digest_len * 2;
    i = digest_len;

    do{
        i--;
        *--c = hex_table[digest[i] & 0xf];
        *--c = hex_table[digest[i] >> 4];
    }while(i != 0);

    // v->data = c;
    v->len = digest_len;

    return NJT_OK;
} /* }}} */

static void njt_http_upload_finish_handler(njt_http_upload_ctx_t *u) { /* {{{ */
    njt_http_upload_field_template_t    *af;
    njt_str_t   aggregate_field_name, aggregate_field_value;
    njt_http_request_t        *r = u->request;
    njt_http_upload_loc_conf_t  *ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);
    njt_uint_t  i;
    njt_int_t   rc;
    njt_upload_cleanup_t  *ucln;
    u_char        dst_filename[1024];
    u_char        sha256[256];
    u_char        *p;
    njt_str_t     tmp_sha;

    if(u->is_file) {
        ucln = u->cln->data;
        ucln->fd = -1;

        njt_close_file(u->output_file.fd);

        if(u->md5_ctx)
            MD5Final(u->md5_ctx->md5_digest, &u->md5_ctx->md5);

        if(u->sha1_ctx)
            SHA1_Final(u->sha1_ctx->sha1_digest, &u->sha1_ctx->sha1);

        if(u->sha256_ctx)
            SHA256_Final(u->sha256_ctx->sha256_digest, &u->sha256_ctx->sha256);

        if(u->sha512_ctx)
            SHA512_Final(u->sha512_ctx->sha512_digest, &u->sha512_ctx->sha512);

        if(u->calculate_crc32)
            njt_crc32_final(u->crc32);

        if(u->partial_content) {
            if(u->output_file.offset != u->content_range_n.end + 1) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0
                    , "file offset at the end of a part %O does not match the end specified range %O-%O/%O"
                    , u->output_file.offset
                    , u->content_range_n.start
                    , u->content_range_n.end
                    , u->content_range_n.total
                    , u->output_file.name
                    );

                goto rollback;
            }

            rc = njt_http_upload_merge_ranges(u, &u->content_range_n);

            if(rc == NJT_ERROR) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0
                    , "error merging ranges"
                    );

                goto rollback;
            }

            if(rc == NJT_AGAIN) {
                /*
                 * If there are more parts to go, we do not produce any output
                 */
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0
                    , "finished uploading part %O-%O/%O of a file \"%V\" to \"%V\""
                    , u->content_range_n.start
                    , u->content_range_n.end
                    , u->content_range_n.total
                    , &u->file_name
                    , &u->output_file.name
                    );

                u->prevent_output = 1;

                return;
            }

            if(njt_delete_file(u->state_file.name.data) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "failed to remove state file \"%V\"", &u->state_file.name);
            } else {
                njt_log_error(NJT_LOG_INFO, r->connection->log, 0, "removed state file \"%V\"", &u->state_file.name);
            }
        }

        // njt_log_error(NJT_LOG_INFO, r->connection->log, 0
        //     , "finished uploading file \"%V\" to \"%V\""
        //     , &u->file_name
        //     , &u->output_file.name
        //     );
        
        //rename
        njt_memzero(sha256, 256);
        tmp_sha.data = sha256;
        njt_http_upload_sha_filename(&tmp_sha, (uintptr_t) "0123456789abcdef", u->sha256_ctx->sha256_digest, SHA256_DIGEST_LENGTH);
        njt_memzero(dst_filename, 1024);
        p = njt_sprintf(dst_filename, "%V/%V.dat", &u->store_path->name, &tmp_sha);
        tmp_sha.len = p - dst_filename;
        tmp_sha.data = dst_filename;

        if (njt_rename_file(u->output_file.name.data, dst_filename) == NJT_FILE_ERROR) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "rename \"%V\" to \"%V\" error",
                &u->output_file.name, &tmp_sha);
            goto rollback;
        }

        njt_log_error(NJT_LOG_INFO, r->connection->log, 0
            , "finished uploading file \"%V\" to \"%V\" tmpfile:\"%V\""
            , &u->file_name
            , &tmp_sha
            , &u->output_file.name
            );

        if(ulcf->aggregate_field_templates) {
            af = ulcf->aggregate_field_templates->elts;
            for (i = 0; i < ulcf->aggregate_field_templates->nelts; i++) {
                rc = njt_http_upload_process_field_templates(r, &af[i], &aggregate_field_name,
                                                             &aggregate_field_value);
                if (rc != NJT_OK) {
                    goto rollback;
                }

                rc = njt_http_upload_append_field(u, &aggregate_field_name, &aggregate_field_value);

                if(rc != NJT_OK)
                    goto rollback;
            }
        }
    }

    // Checkpoint current output chain state
    u->checkpoint = u->last;
    return;

rollback:
    njt_http_upload_abort_handler(u);
} /* }}} */

static void njt_http_upload_abort_handler(njt_http_upload_ctx_t *u) { /* {{{ */
    njt_upload_cleanup_t  *ucln;

    if(u->is_file) {
        /*
         * Upload of a part could be aborted due to temporary reasons, thus
         * next body part will be potentially processed successfuly.
         *
         * Therefore we don't postpone cleanup to the request finallization
         * in order to save additional resources, instead we mark existing
         * cleanup record as aborted.
         */
        ucln = u->cln->data;
        ucln->fd = -1;
        ucln->aborted = 1;

        njt_close_file(u->output_file.fd);

        if(!u->partial_content) {
            if(njt_delete_file(u->output_file.name.data) == NJT_FILE_ERROR) { 
                njt_log_error(NJT_LOG_ERR, u->log, njt_errno
                    , "aborted uploading file \"%V\" to \"%V\", failed to remove destination file"
                    , &u->file_name
                    , &u->output_file.name);
            } else {
                njt_log_error(NJT_LOG_ALERT, u->log, 0
                    , "aborted uploading file \"%V\" to \"%V\", dest file removed"
                    , &u->file_name
                    , &u->output_file.name);
            }
        }
    }

    // Rollback output chain to the previous consistant state
    if(u->checkpoint != NULL) {
        u->last = u->checkpoint;
        u->last->next = NULL;
    }else{
        u->chain = u->last = NULL;
        u->first_part = 1;
    }
} /* }}} */

static njt_int_t njt_http_upload_flush_output_buffer(njt_http_upload_ctx_t *u, u_char *buf, size_t len) { /* {{{ */
    njt_http_request_t             *r = u->request;
    njt_buf_t                      *b;
    njt_chain_t                    *cl;
    njt_http_upload_loc_conf_t     *ulcf = njt_http_get_module_loc_conf(r, njt_http_upload_module);

    if(u->is_file) {
        if(u->partial_content) {
            if(u->output_file.offset > u->content_range_n.end)
                return NJT_OK;

            if(u->output_file.offset + (off_t)len > u->content_range_n.end + 1)
                len = u->content_range_n.end - u->output_file.offset + 1;
        }

        if(u->md5_ctx)
            MD5Update(&u->md5_ctx->md5, buf, len);

        if(u->sha1_ctx)
            SHA1_Update(&u->sha1_ctx->sha1, buf, len);

        if(u->sha256_ctx)
            SHA256_Update(&u->sha256_ctx->sha256, buf, len);

        if(u->sha512_ctx)
            SHA512_Update(&u->sha512_ctx->sha512, buf, len);

        if(u->calculate_crc32)
            njt_crc32_update(&u->crc32, buf, len);

        if(ulcf->max_file_size != 0 && !u->partial_content) {
            if(u->output_file.offset + (off_t)len > ulcf->max_file_size)
                return NJT_UPLOAD_TOOLARGE;
        }

        if(njt_write_file(&u->output_file, buf, len, u->output_file.offset) == NJT_ERROR) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, njt_errno,
                           "write to file \"%V\" failed", &u->output_file.name);
            return NJT_UPLOAD_IOERROR;
        }else
            return NJT_OK;
    }else{
        if(ulcf->max_output_body_len != 0) {
            if (u->output_body_len + len > ulcf->max_output_body_len)
                return NJT_UPLOAD_TOOLARGE;
        }

        u->output_body_len += len;

        b = njt_create_temp_buf(u->request->pool, len);

        if (b == NULL) {
            return NJT_ERROR;
        }

        cl = njt_alloc_chain_link(u->request->pool);
        if (cl == NULL) {
            return NJT_ERROR;
        }

        b->last_in_chain = 0;

        cl->buf = b;
        cl->next = NULL;

        b->last = njt_cpymem(b->last, buf, len);

        if(u->chain == NULL) {
            u->chain = cl;
            u->last = cl;
        }else{
            u->last->next = cl;
            u->last = cl;
        }

        return NJT_OK;
    }
} /* }}} */

static void /* {{{ njt_http_upload_append_str */
njt_http_upload_append_str(njt_http_upload_ctx_t *u, njt_buf_t *b, njt_chain_t *cl, njt_str_t *s)
{
    b->start = b->pos = s->data;
    b->end = b->last = s->data + s->len;
    b->memory = 1;
    b->temporary = 1;
    b->in_file = 0;
    b->last_buf = 0;

    b->last_in_chain = 0;
    b->last_buf = 0;

    cl->buf = b;
    cl->next = NULL;

    if(u->chain == NULL) {
        u->chain = cl;
        u->last = cl;
    }else{
        u->last->next = cl;
        u->last = cl;
    }

    u->output_body_len += s->len;
} /* }}} */

static njt_int_t /* {{{ njt_http_upload_append_field */
njt_http_upload_append_field(njt_http_upload_ctx_t *u, njt_str_t *name, njt_str_t *value)
{
    njt_http_upload_loc_conf_t     *ulcf = njt_http_get_module_loc_conf(u->request, njt_http_upload_module);
    njt_str_t   boundary = { u->first_part ? u->boundary.len - 2 : u->boundary.len,
         u->first_part ? u->boundary.data + 2 : u->boundary.data };

    njt_buf_t *b;
    njt_chain_t *cl;

    if(name->len > 0) {
        if(ulcf->max_output_body_len != 0) {
            if(u->output_body_len + boundary.len + njt_upload_field_part1.len + name->len
               + njt_upload_field_part2.len + value->len > ulcf->max_output_body_len)
                return NJT_UPLOAD_TOOLARGE;
        }

        b = njt_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(njt_buf_t) : 4 * sizeof(njt_buf_t));

        if (b == NULL) {
            return NJT_UPLOAD_NOMEM;
        }

        cl = njt_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(njt_chain_t) : 4 * sizeof(njt_chain_t));

        if (cl == NULL) {
            return NJT_UPLOAD_NOMEM;
        }

        njt_http_upload_append_str(u, b, cl, &boundary);

        njt_http_upload_append_str(u, b + 1, cl + 1, &njt_upload_field_part1);

        njt_http_upload_append_str(u, b + 2, cl + 2, name);

        njt_http_upload_append_str(u, b + 3, cl + 3, &njt_upload_field_part2);

        if(value->len > 0)
            njt_http_upload_append_str(u, b + 4, cl + 4, value);

        u->output_body_len += boundary.len + njt_upload_field_part1.len + name->len
            + njt_upload_field_part2.len + value->len;

        u->first_part = 0;

        u->no_content = 0;
    }

    return NJT_OK;
} /* }}} */

static njt_int_t njt_http_upload_add_range(njt_http_upload_merger_state_t *ms, njt_http_upload_range_t *range_n) {
    ms->out_buf->last = njt_sprintf(ms->out_buf->last, "%O-%O/%O\x0a",
        range_n->start,
        range_n->end,
        range_n->total);

    if(*ms->range_header_buffer_pos < ms->range_header_buffer_end) {
        *ms->range_header_buffer_pos = njt_sprintf(*ms->range_header_buffer_pos,
            ms->first_range ? "%O-%O/%O" : ",%O-%O/%O",
            range_n->start,
            range_n->end,
            range_n->total);

        ms->first_range = 0;
    }

    return NJT_OK;
}

static njt_int_t /* {{{ njt_http_upload_buf_merge_range */
njt_http_upload_buf_merge_range(njt_http_upload_merger_state_t *ms, njt_http_upload_range_t *range_n) {
    u_char *p, c;
    off_t                  *field;

    p = ms->in_buf->pos;

    field = ms->parser_state;

    do{
        *field = 0;

        while(p != ms->in_buf->last) {

            c = *p++;

            if(c >= '0' && c <= '9') {
                (*field) = (*field) * 10 + (c - '0');
            }
            else if(c == '-') {
                if(field != &ms->current_range_n.start) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "unexpected - while parsing range");
                    return NJT_ERROR;
                }

                field = &ms->current_range_n.end;
                break;
            }
            else if(c == '/') {
                if(field != &ms->current_range_n.end) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "unexpected / while parsing range");
                    return NJT_ERROR;
                }

                field = &ms->current_range_n.total;
                break;
            }
            else if(c == LF) {
                if(field != &ms->current_range_n.total) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "unexpected end of line while parsing range");
                    return NJT_ERROR;
                }

                if(ms->current_range_n.start > ms->current_range_n.end || ms->current_range_n.start > ms->current_range_n.total
                    || ms->current_range_n.end > ms->current_range_n.total)
                {
                    njt_log_debug3(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "inconsistent bounds while parsing range: %O-%O/%O",
                                   ms->current_range_n.start,
                                   ms->current_range_n.end,
                                   ms->current_range_n.total);
                    return NJT_ERROR;
                }

                if(ms->current_range_n.total != range_n->total) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "total number of bytes mismatch while parsing range");
                    return NJT_ERROR;
                } 

                field = &ms->current_range_n.start;

                if(ms->current_range_n.end + 1 < range_n->start) {
                    /*
                     * Current range is entirely below the new one,
                     * output current one and seek next
                     */
                    if(njt_http_upload_add_range(ms, &ms->current_range_n) != NJT_OK) {
                        return NJT_ERROR;
                    }

                    njt_log_debug3(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "< %O-%O/%O", ms->current_range_n.start,
                                   ms->current_range_n.end, ms->current_range_n.total);
                    break;
                }

                if(ms->current_range_n.start > range_n->end + 1) {
                    /*
                     * Current range is entirely above the new one,
                     * insert new range
                     */
                    if(!ms->found_lower_bound) {
                        if(njt_http_upload_add_range(ms, range_n) != NJT_OK) {
                            return NJT_ERROR;
                        }
                    }

                    if(njt_http_upload_add_range(ms, &ms->current_range_n) != NJT_OK) {
                        return NJT_ERROR;
                    }

                    njt_log_debug6(NJT_LOG_DEBUG_CORE, ms->log, 0,
                                   "> %O-%O/%O %O-%O/%O",
                                   range_n->start,
                                   range_n->end,
                                   range_n->total,
                                   ms->current_range_n.start,
                                   ms->current_range_n.end,
                                   ms->current_range_n.total);

                    ms->found_lower_bound = 1;
                    break;
                }

                /*
                 * Extend range to be merged with the current range
                 */
                range_n->start = range_n->start < ms->current_range_n.start ? range_n->start : ms->current_range_n.start;
                range_n->end = range_n->end > ms->current_range_n.end ? range_n->end : ms->current_range_n.end;
                break;
            }
            else {
                njt_log_debug1(NJT_LOG_DEBUG_CORE, ms->log, 0,
                               "unexpected character %c", *p);
                return NJT_ERROR;
            }
        }
    }while(p != ms->in_buf->last);

    if(ms->in_buf->last_buf) {
        if(field != &ms->current_range_n.start) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, ms->log, 0,
                           "unexpected end of file while merging ranges");
            return NJT_ERROR;
        }

        if(!ms->found_lower_bound) {
            if(njt_http_upload_add_range(ms, range_n) != NJT_OK) {
                return NJT_ERROR;
            }

            njt_log_debug3(NJT_LOG_DEBUG_CORE, ms->log, 0,
                           "a %O-%O/%O",
                           range_n->start,
                           range_n->end,
                           range_n->total);

            ms->complete_ranges = (range_n->start == 0) && (range_n->end == range_n->total - 1) ? 1 : 0;

            ms->found_lower_bound = 1;
        }
    }

    ms->parser_state = field;

    return NJT_OK;
} /* }}} */

static njt_int_t /* {{{ njt_http_upload_merge_ranges */
njt_http_upload_merge_ranges(njt_http_upload_ctx_t *u, njt_http_upload_range_t *range_n) {
    njt_file_t  *state_file = &u->state_file;
    njt_http_upload_merger_state_t ms;
    off_t        remaining;
    ssize_t      rc;
    __attribute__((__unused__)) int result;
    njt_buf_t    in_buf;
    njt_buf_t    out_buf;
    njt_http_upload_loc_conf_t  *ulcf = njt_http_get_module_loc_conf(u->request, njt_http_upload_module);
    njt_http_upload_range_t  range_to_merge_n;
    

    state_file->fd = njt_open_file(state_file->name.data, NJT_FILE_RDWR, NJT_FILE_CREATE_OR_OPEN, ulcf->store_access);

    if (state_file->fd == NJT_INVALID_FILE) {
        njt_log_error(NJT_LOG_ERR, u->log, njt_errno,
                      "failed to create or open state file \"%V\"", &state_file->name);
        return NJT_ERROR;
    }

    njt_lock_fd(state_file->fd);

    njt_fd_info(state_file->fd, &state_file->info);

    state_file->offset = 0;
    state_file->log = u->log;

    ms.in_buf = &in_buf;
    ms.out_buf = &out_buf;
    ms.parser_state = &ms.current_range_n.start;
    ms.log = u->log;

    ms.found_lower_bound = 0;
    ms.complete_ranges = 0;
    ms.first_range = 1;

    ms.range_header_buffer = u->range_header_buffer;
    ms.range_header_buffer_pos = &u->range_header_buffer_pos;
    ms.range_header_buffer_end = u->range_header_buffer_end;

    range_to_merge_n = *range_n;

    out_buf.start = out_buf.pos = out_buf.last = u->merge_buffer;
    out_buf.end = u->merge_buffer + (ulcf->merge_buffer_size >> 1) + NJT_OFF_T_LEN*3 + 2 + 1;
    out_buf.file_pos = 0;

    in_buf.start = in_buf.pos = in_buf.last = out_buf.end;
    in_buf.end = u->merge_buffer + ulcf->merge_buffer_size;

    do {
        in_buf.file_pos = state_file->offset;
        in_buf.pos = in_buf.last = in_buf.start;

        if(state_file->offset < state_file->info.st_size) {
            remaining = state_file->info.st_size - state_file->offset > in_buf.end - in_buf.start
                ? in_buf.end - in_buf.start : state_file->info.st_size - state_file->offset;

            rc = njt_read_file(state_file, in_buf.pos, remaining, state_file->offset);

            if(rc < 0 || rc != remaining) {
                goto failed;
            }

            in_buf.last = in_buf.pos + rc;
        }

        in_buf.last_buf = state_file->offset == state_file->info.st_size ? 1 : 0;

        if(out_buf.pos != out_buf.last) {
            rc = njt_write_file(state_file, out_buf.pos, out_buf.last - out_buf.pos, out_buf.file_pos);

            if(rc < 0 || rc != out_buf.last - out_buf.pos) {
                goto failed;
            }

            out_buf.file_pos += out_buf.last - out_buf.pos;
        }

        out_buf.pos = out_buf.last = out_buf.start;

        if(njt_http_upload_buf_merge_range(&ms, &range_to_merge_n) != NJT_OK) {
            njt_log_error(NJT_LOG_ERR, u->log, 0,
                          "state file \"%V\" is corrupt", &state_file->name);
            rc = NJT_ERROR;
            goto failed;
        }
    } while(state_file->offset < state_file->info.st_size);

    if(out_buf.pos != out_buf.last) {
        rc = njt_write_file(state_file, out_buf.pos, out_buf.last - out_buf.pos, out_buf.file_pos);

        if(rc < 0 || rc != out_buf.last - out_buf.pos) {
            goto failed;
        }

        out_buf.file_pos += out_buf.last - out_buf.pos;
    }

    if(out_buf.file_pos < state_file->info.st_size) {
        result = ftruncate(state_file->fd, out_buf.file_pos);
    }

    rc = ms.complete_ranges ? NJT_OK : NJT_AGAIN;

failed:
    njt_unlock_fd(state_file->fd);

    njt_close_file(state_file->fd);

    return rc;
} /* }}} */

static void * /* {{{ njt_http_upload_create_loc_conf */
njt_http_upload_create_loc_conf(njt_conf_t *cf)
{
    njt_http_upload_loc_conf_t  *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_http_upload_loc_conf_t));
    if (conf == NULL) {
        return NJT_CONF_ERROR;
    }

    conf->store_access = NJT_CONF_UNSET_UINT;
    conf->forward_args = NJT_CONF_UNSET;
    conf->tame_arrays = NJT_CONF_UNSET;
    conf->resumable_uploads = NJT_CONF_UNSET;
    conf->empty_field_names = NJT_CONF_UNSET;

    conf->buffer_size = NJT_CONF_UNSET_SIZE;
    conf->merge_buffer_size = NJT_CONF_UNSET_SIZE;
    conf->range_header_buffer_size = NJT_CONF_UNSET_SIZE;
    conf->max_header_len = NJT_CONF_UNSET_SIZE;
    conf->max_output_body_len = NJT_CONF_UNSET_SIZE;
    conf->max_file_size = NJT_CONF_UNSET;
    conf->limit_rate = NJT_CONF_UNSET_SIZE;

    /*
     * conf->header_templates,
     * conf->field_templates,
     * conf->aggregate_field_templates,
     * and conf->field_filters are
     * zeroed by njt_pcalloc
     */

    return conf;
} /* }}} */



static char * /* {{{ njt_http_upload_set_path_slot */
njt_http_upload_set_store_path_slot(njt_conf_t *cf, njt_http_upload_loc_conf_t *conf)
{
    // char  *p = conf;

    // ssize_t      level;
    // njt_str_t   *value;
    // njt_uint_t   i, n;
    njt_http_upload_path_t *path;
    // njt_http_compile_complex_value_t   ccv;

    path = njt_pcalloc(cf->pool, sizeof(njt_http_upload_path_t));
    if (path == NULL) {
        return NJT_CONF_ERROR;
    }

    path->path = njt_pcalloc(cf->pool, sizeof(njt_path_t));
    if (path->path == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_str_set(&path->path->name, "data");

    if (path->path->name.data[path->path->name.len - 1] == '/') {
        path->path->name.len--;
    }

    if (njt_conf_full_name(cf->cycle, &path->path->name, 0) != NJT_OK) {
        return NULL;
    }

    path->path->len = 0;
    path->path->manager = NULL;
    path->path->loader = NULL;
    path->path->conf_file = cf->conf_file->file.name.data;
    path->path->line = cf->conf_file->line;

    path->path->level[0] = 0;

    conf->store_path = path;

    // if (njt_add_path(cf, &path->path) == NJT_ERROR) {
    //     return NJT_CONF_ERROR;
    // }

    return NJT_CONF_OK;
} /* }}} */


static char * /* {{{ njt_http_upload_merge_loc_conf */
njt_http_upload_merge_loc_conf(njt_conf_t *cf, void *parent, void *child)
{
    njt_http_upload_loc_conf_t  *prev = parent;
    njt_http_upload_loc_conf_t  *conf = child;

    // if ((conf->url.len == 0) && (conf->url_cv == NULL)) {
    //     conf->url = prev->url;
    //     conf->url_cv = prev->url_cv;
    // }

    // if(conf->url.len != 0) {
    //     njt_http_upload_merge_path_value(cf,
    //                               &conf->store_path,
    //                               prev->store_path,
    //                               &njt_http_upload_temp_path);

    //     njt_http_upload_merge_path_value(cf,
    //                               &conf->state_store_path,
    //                               prev->state_store_path,
    //                               &njt_http_upload_temp_path);
    // }

    if(conf->store_path == NULL){
        njt_http_upload_set_store_path_slot(cf, conf);
    }

    // conf->crc32 = 1;
    conf->sha256 = 1;

    njt_conf_merge_uint_value(conf->store_access,
                              prev->store_access, 0600);

    njt_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size,
                              (size_t) njt_pagesize);

    njt_conf_merge_size_value(conf->merge_buffer_size,
                              prev->merge_buffer_size,
                              (size_t) njt_pagesize >> 1);

    njt_conf_merge_size_value(conf->range_header_buffer_size,
                              prev->range_header_buffer_size,
                              (size_t) 256);

    njt_conf_merge_size_value(conf->max_header_len,
                              prev->max_header_len,
                              (size_t) 512);

    njt_conf_merge_size_value(conf->max_output_body_len,
                              prev->max_output_body_len,
                              (size_t) 100 * 1024);

    njt_conf_merge_off_value(conf->max_file_size,
                             prev->max_file_size,
                             0);

    njt_conf_merge_size_value(conf->limit_rate, prev->limit_rate, 0);

    if(conf->forward_args == NJT_CONF_UNSET) {
        conf->forward_args = (prev->forward_args != NJT_CONF_UNSET) ?
            prev->forward_args : 0;
    }

    if(conf->tame_arrays == NJT_CONF_UNSET) {
        conf->tame_arrays = (prev->tame_arrays != NJT_CONF_UNSET) ?
            prev->tame_arrays : 0;
    }

    if(conf->resumable_uploads == NJT_CONF_UNSET) {
        conf->resumable_uploads = (prev->resumable_uploads != NJT_CONF_UNSET) ?
            prev->resumable_uploads : 0;
    }

    if(conf->empty_field_names == NJT_CONF_UNSET) {
        conf->empty_field_names = (prev->empty_field_names != NJT_CONF_UNSET) ?
            prev->empty_field_names : 0;
    }

    if(conf->field_templates == NULL) {
        conf->field_templates = prev->field_templates;
    }

    if(conf->aggregate_field_templates == NULL) {
        conf->aggregate_field_templates = prev->aggregate_field_templates;

        if(prev->md5) {
            conf->md5 = prev->md5;
        }

        if(prev->sha1) {
            conf->sha1 = prev->sha1;
        }

        if(prev->sha256) {
            conf->sha256 = prev->sha256;
        }

        if(prev->sha512) {
            conf->sha512 = prev->sha512;
        }

        if(prev->crc32) {
            conf->crc32 = prev->crc32;
        }
    }

    if(conf->field_filters == NULL) {
        conf->field_filters = prev->field_filters;
    }

    if(conf->cleanup_statuses == NULL) {
        conf->cleanup_statuses = prev->cleanup_statuses;
    }

    if(conf->header_templates == NULL) {
        conf->header_templates = prev->header_templates;
    }

    return NJT_CONF_OK;
} /* }}} */

// static njt_int_t /* {{{ njt_http_upload_add_variables */
// njt_http_upload_add_variables(njt_conf_t *cf)
// {
//     njt_http_variable_t  *var, *v;

//     for (v = njt_http_upload_variables; v->name.len; v++) {
//         var = njt_http_add_variable(cf, &v->name, v->flags);
//         if (var == NULL) {
//             return NJT_ERROR;
//         }

//         var->get_handler = v->get_handler;
//         var->data = v->data;
//     }

//     for (v = njt_http_upload_aggregate_variables; v->name.len; v++) {
//         var = njt_http_add_variable(cf, &v->name, v->flags);
//         if (var == NULL) {
//             return NJT_ERROR;
//         }

//         var->get_handler = v->get_handler;
//         var->data = v->data;
//     }

//     return NJT_OK;
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_variable */
// njt_http_upload_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;
//     njt_str_t              *value;

//     v->valid = 1;
//     v->no_cacheable = 0;
//     v->not_found = 0;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     value = (njt_str_t *) ((char *) u + data);

//     v->data = value->data;
//     v->len = value->len;

//     return NJT_OK;
// } /* }}} */

// static njt_int_t
// njt_http_upload_hash_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v, uintptr_t data, u_char *digest,
//     njt_uint_t digest_len)
// {
//     njt_uint_t             i;
//     u_char                 *c;
//     u_char                 *p;
//     u_char                 *hex_table;

//     v->valid = 1;
//     v->no_cacheable = 0;
//     v->not_found = 0;

//     hex_table = (u_char*)data;

//     p = njt_palloc(r->pool, digest_len * 2);
//     if (p == NULL) {
//         return NJT_ERROR;
//     }

//     c = p + digest_len * 2;
//     i = digest_len;

//     do{
//         i--;
//         *--c = hex_table[digest[i] & 0xf];
//         *--c = hex_table[digest[i] >> 4];
//     }while(i != 0);

//     v->data = c;
//     v->len = digest_len * 2;

//     return NJT_OK;
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_md5_variable */
// njt_http_upload_md5_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     if(u->md5_ctx == NULL || u->partial_content) {
//         v->not_found = 1;
//         return NJT_OK;
//     }
//     return njt_http_upload_hash_variable(r, v, data, u->md5_ctx->md5_digest, MD5_DIGEST_LENGTH);
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_sha1_variable */
// njt_http_upload_sha1_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     if(u->sha1_ctx == NULL || u->partial_content) {
//         v->not_found = 1;
//         return NJT_OK;
//     }

//     return njt_http_upload_hash_variable(r, v, data, u->sha1_ctx->sha1_digest, SHA_DIGEST_LENGTH);
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_sha256_variable */
// njt_http_upload_sha256_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     if(u->sha256_ctx == NULL || u->partial_content) {
//         v->not_found = 1;
//         return NJT_OK;
//     }

//     return njt_http_upload_hash_variable(r, v, data, u->sha256_ctx->sha256_digest, SHA256_DIGEST_LENGTH);
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_sha512_variable */
// njt_http_upload_sha512_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     if(u->sha512_ctx == NULL || u->partial_content) {
//         v->not_found = 1;
//         return NJT_OK;
//     }

//     return njt_http_upload_hash_variable(r, v, data, u->sha512_ctx->sha512_digest, SHA512_DIGEST_LENGTH);
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_crc32_variable */
// njt_http_upload_crc32_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;
//     u_char                 *p;
//     uint32_t               *value;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     if(u->partial_content) {
//         v->not_found = 1;
//         return NJT_OK;
//     }

//     value = (uint32_t *) ((char *) u + data);

//     p = njt_palloc(r->pool, NJT_INT_T_LEN);
//     if (p == NULL) {
//         return NJT_ERROR;
//     }

//     v->len = njt_sprintf(p, "%08uxd", *value) - p;
//     v->valid = 1;
//     v->no_cacheable = 0;
//     v->not_found = 0;
//     v->data = p;

//     return NJT_OK;
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_file_size_variable */
// njt_http_upload_file_size_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;
//     u_char                 *p;
//     off_t                  *value;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     value = (off_t *) ((char *) u + data);

//     p = njt_palloc(r->pool, NJT_OFF_T_LEN);
//     if (p == NULL) {
//         return NJT_ERROR;
//     }

//     v->len = njt_sprintf(p, "%O", *value) - p;
//     v->valid = 1;
//     v->no_cacheable = 0;
//     v->not_found = 0;
//     v->data = p;

//     return NJT_OK;
// } /* }}} */

// static void /* {{{ njt_http_upload_content_range_variable_set */
// njt_http_upload_content_range_variable_set(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t   *u;
//     njt_str_t                val;
//     njt_http_upload_range_t *value;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     value = (njt_http_upload_range_t *) ((char *) u + data);

//     val.len = v->len;
//     val.data = v->data;

//     if(njt_http_upload_parse_range(&val, value) != NJT_OK) {
//         njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
//                       "invalid range \"%V\"", &val);
//     }
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_content_range_variable */
// njt_http_upload_content_range_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;
//     u_char                 *p;
//     njt_http_upload_range_t *value;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     value = (njt_http_upload_range_t *) ((char *) u + data);

//     p = njt_palloc(r->pool, sizeof("bytes ") - 1 + 3*NJT_OFF_T_LEN + 2);
//     if (p == NULL) {
//         return NJT_ERROR;
//     }

//     v->len = u->partial_content ?
//         njt_sprintf(p, "bytes %O-%O/%O", value->start, value->end, value->total) - p :
//         njt_sprintf(p, "bytes %O-%O/%O", (off_t)0, u->output_file.offset, u->output_file.offset) - p
//         ;
//     v->valid = 1;
//     v->no_cacheable = 0;
//     v->not_found = 0;
//     v->data = p;

//     return NJT_OK;
// } /* }}} */

// static njt_int_t /* {{{ njt_http_upload_uint_variable */
// njt_http_upload_uint_variable(njt_http_request_t *r,
//     njt_http_variable_value_t *v,  uintptr_t data)
// {
//     njt_http_upload_ctx_t  *u;
//     u_char                 *p;
//     njt_uint_t             *value;

//     u = njt_http_get_module_ctx(r, njt_http_upload_module);

//     value = (njt_uint_t *) ((char *) u + data);

//     p = njt_palloc(r->pool, sizeof("18446744073709551616") - 1);
//     if (p == NULL) {
//         return NJT_ERROR;
//     }

//     v->len = njt_sprintf(p, "%ui", *value) - p;
//     v->valid = 1;
//     v->no_cacheable = 0;
//     v->not_found = 0;
//     v->data = p;

//     return NJT_OK;
// } /* }}} */


// static char * /* {{{ njt_http_upload_set_form_field */
// njt_http_upload_set_form_field(njt_conf_t *cf, njt_command_t *cmd, void *conf)
// {
//     njt_int_t                   n, i;
//     njt_str_t                  *value;
//     njt_http_script_compile_t   sc;
//     njt_http_upload_field_template_t *h;
//     njt_array_t                 **field;
//     njt_http_variable_t         *v;
//     u_char                      *match;
//     njt_http_upload_loc_conf_t  *ulcf = conf;

//     field = (njt_array_t**) (((u_char*)conf) + cmd->offset);

//     value = cf->args->elts;

//     if (*field == NULL) {
//         *field = njt_array_create(cf->pool, 1,
//                                   sizeof(njt_http_upload_field_template_t));
//         if (*field == NULL) {
//             return NJT_CONF_ERROR;
//         }
//     }

//     h = njt_array_push(*field);
//     if (h == NULL) {
//         return NJT_CONF_ERROR;
//     }

//     h->value.hash = 1;
//     h->value.key = value[1];
//     h->value.value = value[2];
//     h->field_lengths = NULL;
//     h->field_values = NULL;
//     h->value_lengths = NULL;
//     h->value_values = NULL;

//     /*
//      * Compile field name
//      */
//     n = njt_http_script_variables_count(&value[1]);

//     if (n > 0) {
//         njt_memzero(&sc, sizeof(njt_http_script_compile_t));

//         sc.cf = cf;
//         sc.source = &value[1];
//         sc.lengths = &h->field_lengths;
//         sc.values = &h->field_values;
//         sc.variables = n;
//         sc.complete_lengths = 1;
//         sc.complete_values = 1;

//         if (njt_http_script_compile(&sc) != NJT_OK) {
//             return NJT_CONF_ERROR;
//         }
//     }

//     /*
//      * Compile field value
//      */
//     n = njt_http_script_variables_count(&value[2]);

//     if (n > 0) {
//         njt_memzero(&sc, sizeof(njt_http_script_compile_t));

//         sc.cf = cf;
//         sc.source = &value[2];
//         sc.lengths = &h->value_lengths;
//         sc.values = &h->value_values;
//         sc.variables = n;
//         sc.complete_lengths = 1;
//         sc.complete_values = 1;

//         if (njt_http_script_compile(&sc) != NJT_OK) {
//             return NJT_CONF_ERROR;
//         }
//     }

//     /*
//      * Check for aggregate variables in script
//      */
//     for(i = 1;i <= 2;i++) {
//         for (v = njt_http_upload_aggregate_variables; v->name.len; v++) {
//             match = njt_strcasestrn(value[i].data, (char*)v->name.data, v->name.len - 1);

//             /*
//              * njt_http_script_compile does check for final bracket earlier,
//              * therefore we don't need to care about it, which simplifies things
//              */
//             if(match != NULL
//                 && ((match - value[i].data >= 1 && match[-1] == '$') 
//                     || (match - value[i].data >= 2 && match[-2] == '$' && match[-1] == '{')))
//             {
//                 if(cmd->offset != offsetof(njt_http_upload_loc_conf_t, aggregate_field_templates)) {
//                     njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                                        "variables upload_file_md5"
//                                        ", upload_file_md5_uc"
//                                        ", upload_file_sha1"
//                                        ", upload_file_sha1_uc"
//                                        ", upload_file_sha256"
//                                        ", upload_file_sha256_uc"
//                                        ", upload_file_sha512"
//                                        ", upload_file_sha512_uc"
//                                        ", upload_file_crc32"
//                                        ", upload_content_range"
//                                        " and upload_file_size"
//                                        " could be specified only in upload_aggregate_form_field directive");
//                     return NJT_CONF_ERROR;
//                 }

//                 if(v->get_handler == njt_http_upload_md5_variable)
//                     ulcf->md5 = 1;

//                 if(v->get_handler == njt_http_upload_sha1_variable)
//                     ulcf->sha1 = 1;

//                 if(v->get_handler == njt_http_upload_sha256_variable)
//                     ulcf->sha256 = 1;

//                 if(v->get_handler == njt_http_upload_sha512_variable)
//                     ulcf->sha512 = 1;

//                 if(v->get_handler == njt_http_upload_crc32_variable)
//                     ulcf->crc32 = 1;
//             }
//         }
//     }

//     return NJT_CONF_OK;
// } /* }}} */

// static char * /* {{{ njt_http_upload_pass_form_field */
// njt_http_upload_pass_form_field(njt_conf_t *cf, njt_command_t *cmd, void *conf)
// {
//     njt_http_upload_loc_conf_t *ulcf = conf;

//     njt_str_t                  *value;
// #if (NJT_PCRE)
// #if defined njet_version && njet_version >= 8025
//     njt_regex_compile_t         rc;
//     u_char                      errstr[NJT_MAX_CONF_ERRSTR];
// #else
//     njt_int_t                   n;
//     njt_str_t                  err;
// #endif
// #endif
//     njt_http_upload_field_filter_t *f;

//     value = cf->args->elts;

//     if (ulcf->field_filters == NULL) {
//         ulcf->field_filters = njt_array_create(cf->pool, 1,
//                                         sizeof(njt_http_upload_field_filter_t));
//         if (ulcf->field_filters == NULL) {
//             return NJT_CONF_ERROR;
//         }
//     }

//     f = njt_array_push(ulcf->field_filters);
//     if (f == NULL) {
//         return NJT_CONF_ERROR;
//     }

// #if (NJT_PCRE)
// #if defined njet_version && njet_version >= 8025
//     njt_memzero(&rc, sizeof(njt_regex_compile_t));

//     rc.pattern = value[1];
//     rc.pool = cf->pool;
//     rc.err.len = NJT_MAX_CONF_ERRSTR;
//     rc.err.data = errstr;

//     if(njt_regex_compile(&rc) != NJT_OK) {
//         njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%V", &rc.err);
//         return NJT_CONF_ERROR;
//     }

//     f->regex = rc.regex;
//     f->ncaptures = rc.captures;
// #else
//     f->regex = njt_regex_compile(&value[1], 0, cf->pool, &err);

//     if (f->regex == NULL) {
//         njt_conf_log_error(NJT_LOG_EMERG, cf, 0, "%s", err.data);
//         return NJT_CONF_ERROR;
//     }
    
//     n = njt_regex_capture_count(f->regex);

//     if (n < 0) {
//         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                            njt_regex_capture_count_n " failed for "
//                            "pattern \"%V\"", &value[1]);
//         return NJT_CONF_ERROR;
//     }

//     f->ncaptures = n;
// #endif
// #else
//     f->text.len = value[1].len;
//     f->text.data = value[1].data;
// #endif

//     return NJT_CONF_OK;
// } /* }}} */

// static char * /* {{{ njt_http_upload_cleanup */
// njt_http_upload_cleanup(njt_conf_t *cf, njt_command_t *cmd, void *conf)
// {
//     njt_http_upload_loc_conf_t *ulcf = conf;

//     njt_str_t                  *value;
//     njt_uint_t                 i;
//     njt_int_t                  status, lo, hi;
//     uint16_t                   *s;

//     value = cf->args->elts;

//     if (ulcf->cleanup_statuses == NULL) {
//         ulcf->cleanup_statuses = njt_array_create(cf->pool, 1,
//                                         sizeof(uint16_t));
//         if (ulcf->cleanup_statuses == NULL) {
//             return NJT_CONF_ERROR;
//         }
//     }

//     for (i = 1; i < cf->args->nelts; i++) {
//         if(value[i].len > 4 && value[i].data[3] == '-') {
//             lo = njt_atoi(value[i].data, 3);

//             if (lo == NJT_ERROR) {
//                 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                                    "invalid lower bound \"%V\"", &value[i]);
//                 return NJT_CONF_ERROR;
//             }

//             hi = njt_atoi(value[i].data + 4, value[i].len - 4);

//             if (hi == NJT_ERROR) {
//                 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                                    "invalid upper bound \"%V\"", &value[i]);
//                 return NJT_CONF_ERROR;
//             }

//             if (hi < lo) {
//                 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                                    "upper bound must be greater then lower bound in \"%V\"",
//                                    &value[i]);
//                 return NJT_CONF_ERROR;
//             }

//         }else{
//             status = njt_atoi(value[i].data, value[i].len);

//             if (status == NJT_ERROR) {
//                 njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                                    "invalid value \"%V\"", &value[i]);
//                 return NJT_CONF_ERROR;
//             }

//             hi = lo = status;
//         }

//         if (lo < 200 || hi > 599) {
//             njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                                "value(s) \"%V\" must be between 200 and 599",
//                                &value[i]);
//             return NJT_CONF_ERROR;
//         }

//         for(status = lo ; status <= hi; status++) {
//             s = njt_array_push(ulcf->cleanup_statuses);
//             if (s == NULL) {
//                 return NJT_CONF_ERROR;
//             }

//             *s = status;
//         }
//     }


//     return NJT_CONF_OK;
// } /* }}} */

// static char * /* {{{ njt_http_upload_pass */
// njt_http_upload_pass(njt_conf_t *cf, njt_command_t *cmd, void *conf)
// {
//     njt_http_core_loc_conf_t          *clcf;
//     njt_http_upload_loc_conf_t        *ulcf = conf;
//     njt_str_t                         *value;
//     njt_http_compile_complex_value_t   ccv;

//     if ((ulcf->url.len != 0) || (ulcf->url_cv != NULL)) {
//         return "is duplicate";
//     }

//     value = cf->args->elts;

//     if (value[1].len == 0) {
//         njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
//                            "empty value in \"%V\" directive",
//                            &cmd->name);

//         return NJT_CONF_ERROR;
//     }

//     clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
//     clcf->handler = njt_http_upload_handler;

//     if (njt_http_script_variables_count(&value[1])) {
//         /* complex value */
//         ulcf->url_cv = njt_palloc(cf->pool, sizeof(njt_http_complex_value_t));
//         if (ulcf->url_cv == NULL) {
//             return NJT_CONF_ERROR;
//         }

//         njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

//         ccv.cf = cf;
//         ccv.value = &value[1];
//         ccv.complex_value = ulcf->url_cv;

//         if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
//             return NJT_CONF_ERROR;
//         }
//     } else {
//         /* simple value */
//         ulcf->url = value[1];
//     }

//     return NJT_CONF_OK;
// } /* }}} */

// static char * /* {{{ njt_http_upload_set_path_slot */
// njt_http_upload_set_path_slot(njt_conf_t *cf, njt_command_t *cmd, void *conf)
// {
//     char  *p = conf;

//     ssize_t      level;
//     njt_str_t   *value;
//     njt_uint_t   i, n;
//     njt_http_upload_path_t *path, **slot;
//     njt_http_compile_complex_value_t   ccv;

//     slot = (njt_http_upload_path_t **) (p + cmd->offset);

//     if (*slot) {
//         return "is duplicate";
//     }

//     path = njt_pcalloc(cf->pool, sizeof(njt_http_upload_path_t));
//     if (path == NULL) {
//         return NJT_CONF_ERROR;
//     }

//     path->path = njt_pcalloc(cf->pool, sizeof(njt_path_t));
//     if (path->path == NULL) {
//         return NJT_CONF_ERROR;
//     }

//     value = cf->args->elts;

//     path->path->name = value[1];

//     if (path->path->name.data[path->path->name.len - 1] == '/') {
//         path->path->name.len--;
//     }

//     if (njt_conf_full_name(cf->cycle, &path->path->name, 0) != NJT_OK) {
//         return NULL;
//     }

//     path->path->len = 0;
//     path->path->manager = NULL;
//     path->path->loader = NULL;
//     path->path->conf_file = cf->conf_file->file.name.data;
//     path->path->line = cf->conf_file->line;

//     for (i = 0, n = 2; n < cf->args->nelts; i++, n++) {
//         level = njt_atoi(value[n].data, value[n].len);
//         if (level == NJT_ERROR || level == 0) {
//             return "invalid value";
//         }

//         path->path->level[i] = level;
//         path->path->len += level + 1;
//     }

//     while (i < 3) {
//         path->path->level[i++] = 0;
//     }

//     *slot = path;

//     if(njt_http_script_variables_count(&value[1])) {
//         njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

//         ccv.cf = cf;
//         ccv.value = &value[1];
//         ccv.complex_value = &path->dynamic;

//         if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
//             return NJT_CONF_ERROR;
//         }

//         path->is_dynamic = 1;
//     }
//     else {
//         if (njt_add_path(cf, &path->path) == NJT_ERROR) {
//             return NJT_CONF_ERROR;
//         }
//     }

//     return NJT_CONF_OK;
// } /* }}} */


// static char * /* {{{ njt_http_upload_merge_path_value */
// njt_http_upload_merge_path_value(njt_conf_t *cf, njt_http_upload_path_t **path, njt_http_upload_path_t *prev,
//     njt_path_init_t *init)
// {
//     if (*path) {
//         return NJT_CONF_OK;
//     }

//     if (prev) {
//         *path = prev;
//         return NJT_CONF_OK;
//     }

//     *path = njt_pcalloc(cf->pool, sizeof(njt_http_upload_path_t));
//     if(*path == NULL) {
//         return NJT_CONF_ERROR;
//     }

//     (*path)->path = njt_pcalloc(cf->pool, sizeof(njt_path_t));
//     if((*path)->path == NULL) {
//         return NJT_CONF_ERROR;
//     }

//     (*path)->path->name = init->name;

//     if(njt_conf_full_name(cf->cycle, &(*path)->path->name, 0) != NJT_OK) {
//         return NJT_CONF_ERROR;
//     }

//     (*path)->path->level[0] = init->level[0];
//     (*path)->path->level[1] = init->level[1];
//     (*path)->path->level[2] = init->level[2];

//     (*path)->path->len = init->level[0] + (init->level[0] ? 1 : 0)
//                    + init->level[1] + (init->level[1] ? 1 : 0)
//                    + init->level[2] + (init->level[2] ? 1 : 0);

//     (*path)->path->manager = NULL;
//     (*path)->path->loader = NULL;
//     (*path)->path->conf_file = NULL;

//     if(njt_add_path(cf, &(*path)->path) != NJT_OK) {
//         return NJT_CONF_ERROR;
//     }

//     return NJT_CONF_OK;
// } /* }}} */

njt_int_t /* {{{ njt_http_read_upload_client_request_body */
njt_http_read_upload_client_request_body(njt_http_request_t *r) {
    ssize_t                    size, preread;
    njt_buf_t                 *b;
    njt_chain_t               *cl, **next;
    njt_http_request_body_t   *rb;
    njt_http_core_loc_conf_t  *clcf;
    njt_http_upload_ctx_t     *u = njt_http_get_module_ctx(r, njt_http_upload_module);

#if defined njet_version && njet_version >= 8011
    r->main->count++;
#endif

    if (r->request_body || r->discard_body) {
        return NJT_OK;
    }

    rb = njt_pcalloc(r->pool, sizeof(njt_http_request_body_t));
    if (rb == NULL) {
        upload_shutdown_ctx(u);
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body = rb;

    if (r->headers_in.content_length_n <= 0) {
        upload_shutdown_ctx(u);
        return NJT_HTTP_BAD_REQUEST;
    }

    /*
     * set by njt_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        u->received = preread;

        b = njt_calloc_buf(r->pool);
        if (b == NULL) {
            upload_shutdown_ctx(u);
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->start = r->header_in->pos;
        b->pos = r->header_in->pos;
        b->last = r->header_in->last;
        b->end = r->header_in->end;

        rb->bufs = njt_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            upload_shutdown_ctx(u);
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;
        rb->buf = b;

        if (preread >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            if (njt_http_process_request_body(r, rb->bufs) != NJT_OK) {
                upload_shutdown_ctx(u);
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            upload_shutdown_ctx(u);
            return njt_http_upload_body_handler(r);
            // return NJT_OK;
        }

        /*
         * to not consider the body as pipelined request in
         * njt_http_set_keepalive()
         */
        r->header_in->pos = r->header_in->last;

        r->request_length += preread;

        rb->rest = r->headers_in.content_length_n - preread;

        if (rb->rest <= (off_t) (b->end - b->last)) {

            /* the whole request body may be placed in r->header_in */

            u->to_write = rb->bufs;

            r->read_event_handler = njt_http_read_upload_client_request_body_handler;

            return njt_http_do_read_upload_client_request_body(r);
        }

        next = &rb->bufs->next;

    } else {
        b = NULL;
        rb->rest = r->headers_in.content_length_n;
        next = &rb->bufs;
    }

    clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    if (rb->rest < (ssize_t) size) {
        size = rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;

        /* disable copying buffer for r->request_body_in_single_buf */
        b = NULL;
    }

    rb->buf = njt_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        upload_shutdown_ctx(u);
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = njt_alloc_chain_link(r->pool);
    if (cl == NULL) {
        upload_shutdown_ctx(u);
        return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (b && r->request_body_in_single_buf) {
        size = b->last - b->pos;
        njt_memcpy(rb->buf->pos, b->pos, size);
        rb->buf->last += size;

        next = &rb->bufs;
    }

    *next = cl;

    u->to_write = rb->bufs;

    r->read_event_handler = njt_http_read_upload_client_request_body_handler;

    return njt_http_do_read_upload_client_request_body(r);
} /* }}} */

static void /* {{{ njt_http_read_upload_client_request_body_handler */
njt_http_read_upload_client_request_body_handler(njt_http_request_t *r)
{
    njt_int_t  rc;
    njt_http_upload_ctx_t     *u = njt_http_get_module_ctx(r, njt_http_upload_module);
    njt_event_t               *rev = r->connection->read;
    njt_http_core_loc_conf_t  *clcf;

    if (rev->timedout) {
        if(!rev->delayed) {
            r->connection->timedout = 1;
            upload_shutdown_ctx(u);
            njt_http_finalize_request(r, NJT_HTTP_REQUEST_TIME_OUT);
            return;
        }

        rev->timedout = 0;
        rev->delayed = 0;

        if (!rev->ready) {
            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
            njt_add_timer(rev, clcf->client_body_timeout);

            if (njt_handle_read_event(rev, clcf->send_lowat) != NJT_OK) {
                upload_shutdown_ctx(u);
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }
    else{
        if (r->connection->read->delayed) {
            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
            njt_log_debug0(NJT_LOG_DEBUG_HTTP, rev->log, 0,
                           "http read delayed");

            if (njt_handle_read_event(rev, clcf->send_lowat) != NJT_OK) {
                upload_shutdown_ctx(u);
                njt_http_finalize_request(r, NJT_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    rc = njt_http_do_read_upload_client_request_body(r);

    if (rc >= NJT_HTTP_SPECIAL_RESPONSE) {
        upload_shutdown_ctx(u);
        njt_http_finalize_request(r, rc);
    }
} /* }}} */

static njt_int_t /* {{{ njt_http_do_read_upload_client_request_body */
njt_http_do_read_upload_client_request_body(njt_http_request_t *r)
{
    ssize_t                     size, n, limit;
    njt_connection_t          *c;
    njt_http_request_body_t   *rb;
    njt_http_upload_ctx_t     *u = njt_http_get_module_ctx(r, njt_http_upload_module);
    njt_int_t                  rc;
    njt_http_core_loc_conf_t  *clcf;
    njt_msec_t                 delay;

    c = r->connection;
    rb = r->request_body;

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {

                rc = njt_http_process_request_body(r, u->to_write);

                switch(rc) {
                    case NJT_OK:
                        break;
                    case NJT_UPLOAD_MALFORMED:
                        return NJT_HTTP_BAD_REQUEST;
                    case NJT_UPLOAD_TOOLARGE:
                        return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
                    case NJT_UPLOAD_IOERROR:
                        return NJT_HTTP_SERVICE_UNAVAILABLE;
                    case NJT_UPLOAD_NOMEM: case NJT_UPLOAD_SCRIPTERROR:
                    default:
                        return NJT_HTTP_INTERNAL_SERVER_ERROR;
                }

                u->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;

            if ((off_t)size > rb->rest) {
                size = (size_t)rb->rest;
            }

            if (u->limit_rate) {
                limit = u->limit_rate * (njt_time() - r->start_sec + 1) - u->received;

                if (limit < 0) {
                    c->read->delayed = 1;
                    njt_add_timer(c->read,
                                  (njt_msec_t) (- limit * 1000 / u->limit_rate + 1));

                    return NJT_AGAIN;
                }

                if(limit > 0 && size > limit) {
                    size = limit;
                }
            }

            n = c->recv(c, rb->buf->last, size);

            njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NJT_AGAIN) {
                break;
            }

            if (n == 0) {
                njt_log_error(NJT_LOG_INFO, c->log, 0,
                              "client closed prematurely connection");
            }

            if (n == 0 || n == NJT_ERROR) {
                c->error = 1;
                return NJT_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            rb->rest -= n;
            r->request_length += n;
            u->received += n;

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }

            if (u->limit_rate) {
                delay = (njt_msec_t) (n * 1000 / u->limit_rate + 1);

                if (delay > 0) {
                    c->read->delayed = 1;
                    njt_add_timer(c->read, delay);
                    return NJT_AGAIN;
                }
            }
        }

        njt_log_debug1(NJT_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %uz", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {
            clcf = njt_http_get_module_loc_conf(r, njt_http_core_module);
            njt_add_timer(c->read, clcf->client_body_timeout);

            if (njt_handle_read_event(c->read, 0) != NJT_OK) {
                return NJT_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NJT_AGAIN;
        }
    }

    if (c->read->timer_set) {
        njt_del_timer(c->read);
    }

    r->read_event_handler = njt_http_block_reading;

    rc = njt_http_process_request_body(r, u->to_write);

    switch(rc) {
        case NJT_OK:
            break;
        case NJT_UPLOAD_MALFORMED:
            return NJT_HTTP_BAD_REQUEST;
        case NJT_UPLOAD_TOOLARGE:
            return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
        case NJT_UPLOAD_IOERROR:
            return NJT_HTTP_SERVICE_UNAVAILABLE;
        case NJT_UPLOAD_NOMEM: case NJT_UPLOAD_SCRIPTERROR:
        default:
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
    }

    upload_shutdown_ctx(u);

    return njt_http_upload_body_handler(r);
} /* }}} */

static njt_int_t /* {{{ njt_http_process_request_body */
njt_http_process_request_body(njt_http_request_t *r, njt_chain_t *body)
{
    njt_int_t rc;
    njt_http_upload_ctx_t     *u = njt_http_get_module_ctx(r, njt_http_upload_module);

    // Feed all the buffers into data handler
    while(body) {
        rc = u->data_handler(u, body->buf->pos, body->buf->last);

        if(rc != NJT_OK)
            return rc;

        body = body->next;
    }

    if(u->raw_input) {
        // Signal end of body
        if(r->request_body->rest == 0) {
            rc = u->data_handler(u, NULL, NULL);

            if(rc != NJT_OK)
                return rc;
        }
    }

    return NJT_OK;
} /* }}} */

static njt_int_t upload_parse_content_disposition(njt_http_upload_ctx_t *upload_ctx, njt_str_t *content_disposition) { /* {{{ */
    char *filename_start, *filename_end;
    char *fieldname_start, *fieldname_end;
    char *p, *q;

    p = (char*)content_disposition->data;

    if(strncasecmp(FORM_DATA_STRING, p, sizeof(FORM_DATA_STRING)-1) && 
            strncasecmp(ATTACHMENT_STRING, p, sizeof(ATTACHMENT_STRING)-1)) {
        njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "Content-Disposition is not form-data or attachment");
        return NJT_UPLOAD_MALFORMED;
    }

    filename_start = strstr(p, FILENAME_STRING);

    if(filename_start != 0) {
        
        filename_start += sizeof(FILENAME_STRING) - 1;

        if (*filename_start == '\"') {
            filename_start++;
        }

        filename_end = filename_start + strcspn(filename_start, "\";");

        /*
         * IE sends full path, strip path from filename 
         * Also strip all UNIX path references
         */
        for(q = filename_end-1; q > filename_start; q--)
            if(*q == '\\' || *q == '/') {
                filename_start = q+1;
                break;
            }

        upload_ctx->file_name.len = filename_end - filename_start;
        upload_ctx->file_name.data = njt_palloc(upload_ctx->request->pool, upload_ctx->file_name.len + 1);
        
        if(upload_ctx->file_name.data == NULL)
            return NJT_UPLOAD_NOMEM;

        strncpy((char*)upload_ctx->file_name.data, filename_start, filename_end - filename_start);
    }

    fieldname_start = p;

//    do{
        fieldname_start = strstr(fieldname_start, FIELDNAME_STRING);
//    }while((fieldname_start != 0) && (fieldname_start + sizeof(FIELDNAME_STRING) - 1 == filename_start));

    if(fieldname_start != 0) {
        fieldname_start += sizeof(FIELDNAME_STRING) - 1;

        if (*fieldname_start == '\"') {
            fieldname_start++;
        }

        if(fieldname_start != filename_start) {
            fieldname_end = fieldname_start + strcspn(fieldname_start, "\";");

            upload_ctx->field_name.len = fieldname_end - fieldname_start;
            upload_ctx->field_name.data = njt_pcalloc(upload_ctx->request->pool, upload_ctx->field_name.len + 1);

            if(upload_ctx->field_name.data == NULL)
                return NJT_UPLOAD_NOMEM;

            strncpy((char*)upload_ctx->field_name.data, fieldname_start, fieldname_end - fieldname_start);
        }
    }

    return NJT_OK;
} /* }}} */

static njt_int_t upload_parse_part_header(njt_http_upload_ctx_t *upload_ctx, char *header, char *header_end) { /* {{{ */
    njt_str_t s;

    if(!strncasecmp(CONTENT_DISPOSITION_STRING, header, sizeof(CONTENT_DISPOSITION_STRING) - 1)) {
        char *p = header + sizeof(CONTENT_DISPOSITION_STRING) - 1;

        p += strspn(p, " ");
        
        s.data = (u_char*)p;
        s.len = header_end - p;

        if(upload_parse_content_disposition(upload_ctx, &s) != NJT_OK) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "invalid Content-Disposition header");
            return NJT_UPLOAD_MALFORMED;
        }
    }
    else if(!strncasecmp(CONTENT_TYPE_STRING, header, sizeof(CONTENT_TYPE_STRING)-1)) {
        char *content_type_str = header + sizeof(CONTENT_TYPE_STRING)-1;
        
        content_type_str += strspn(content_type_str, " ");
        upload_ctx->content_type.len = header_end - content_type_str;
        
        if(upload_ctx->content_type.len == 0) {
            njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0,
                           "empty Content-Type in part header");
            return NJT_UPLOAD_MALFORMED; // Empty Content-Type field
        }

        upload_ctx->content_type.data = njt_pcalloc(upload_ctx->request->pool, upload_ctx->content_type.len + 1);
        
        if(upload_ctx->content_type.data == NULL)
            return NJT_UPLOAD_NOMEM; // Unable to allocate memory for string

        strncpy((char*)upload_ctx->content_type.data, content_type_str, upload_ctx->content_type.len);
    }

    return NJT_OK;
} /* }}} */

static void upload_discard_part_attributes(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
    upload_ctx->file_name.len = 0;
    upload_ctx->file_name.data = NULL;

    upload_ctx->field_name.len = 0;
    upload_ctx->field_name.data = NULL;

    upload_ctx->content_type.len = 0;
    upload_ctx->content_type.data = NULL;

    upload_ctx->content_range.len = 0;
    upload_ctx->content_range.data = NULL;

    upload_ctx->session_id.len = 0;
    upload_ctx->session_id.data = NULL;

    upload_ctx->partial_content = 0;
} /* }}} */

static njt_int_t upload_start_file(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->start_part_f)
        return upload_ctx->start_part_f(upload_ctx);
    else
        return NJT_OK;
} /* }}} */

static void upload_finish_file(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
    // Call user-defined event handler
    if(upload_ctx->finish_part_f)
        upload_ctx->finish_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_abort_file(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->abort_part_f)
        upload_ctx->abort_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_flush_output_buffer(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->output_buffer_pos > upload_ctx->output_buffer) {
        if(upload_ctx->flush_output_buffer_f)
            if(upload_ctx->flush_output_buffer_f(upload_ctx, (void*)upload_ctx->output_buffer, 
                (size_t)(upload_ctx->output_buffer_pos - upload_ctx->output_buffer)) != NJT_OK)
                upload_ctx->discard_data = 1;

        upload_ctx->output_buffer_pos = upload_ctx->output_buffer;	
    }
} /* }}} */

static void upload_init_ctx(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
    upload_ctx->boundary.data = upload_ctx->boundary_start = upload_ctx->boundary_pos = 0;

	upload_ctx->state = upload_state_boundary_seek;

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;

	upload_ctx->start_part_f = njt_http_upload_start_handler;
	upload_ctx->finish_part_f = njt_http_upload_finish_handler;
	upload_ctx->abort_part_f = njt_http_upload_abort_handler;
	upload_ctx->flush_output_buffer_f = njt_http_upload_flush_output_buffer;

    upload_ctx->started = 0;
    upload_ctx->unencoded = 0;
    /*
     * Set default data handler
     */
    upload_ctx->data_handler = upload_process_buf;
} /* }}} */

static void upload_shutdown_ctx(njt_http_upload_ctx_t *upload_ctx) { /* {{{ */
	if(upload_ctx != 0) {
        // Abort file if we still processing it
        if(upload_ctx->state == upload_state_data) {
            upload_flush_output_buffer(upload_ctx);
            upload_abort_file(upload_ctx);
        }

        upload_discard_part_attributes(upload_ctx);
	}
} /* }}} */

static njt_int_t upload_start(njt_http_upload_ctx_t *upload_ctx, njt_http_upload_loc_conf_t *ulcf) { /* {{{ */
	if(upload_ctx == NULL)
		return NJT_ERROR;

	upload_ctx->header_accumulator = njt_pcalloc(upload_ctx->request->pool, ulcf->max_header_len + 1);

	if(upload_ctx->header_accumulator == NULL)
		return NJT_ERROR;

	upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
	upload_ctx->header_accumulator_end = upload_ctx->header_accumulator + ulcf->max_header_len;

	upload_ctx->output_buffer = njt_pcalloc(upload_ctx->request->pool, ulcf->buffer_size);

	if(upload_ctx->output_buffer == NULL)
		return NJT_ERROR;

    upload_ctx->output_buffer_pos = upload_ctx->output_buffer;
    upload_ctx->output_buffer_end = upload_ctx->output_buffer + ulcf->buffer_size;

    upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;

    upload_ctx->range_header_buffer = njt_pcalloc(upload_ctx->request->pool, ulcf->range_header_buffer_size);

	if(upload_ctx->range_header_buffer == NULL)
		return NJT_ERROR;

    upload_ctx->range_header_buffer_pos = upload_ctx->range_header_buffer;
    upload_ctx->range_header_buffer_end = upload_ctx->range_header_buffer + ulcf->range_header_buffer_size;

    upload_ctx->first_part = 1;

	return NJT_OK;
} /* }}} */

static njt_int_t /* {{{ njt_http_upload_validate_session_id */
njt_http_upload_validate_session_id(njt_str_t *session_id) {
    u_char *p, *q;

    p = session_id->data;
    q = session_id->data + session_id->len;

    while(p != q) {
        if(!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
            || *p == '_' || *p == '-'))
        {
            return NJT_ERROR;
        }

        p++;
    }

    return NJT_OK;
}

static njt_int_t upload_parse_request_headers(njt_http_upload_ctx_t *upload_ctx, njt_http_headers_in_t *headers_in) { /* {{{ */
    njt_str_t                 *content_type, s;
    njt_list_part_t           *part;
    njt_table_elt_t           *header;
    njt_uint_t                 i;
    u_char                    *mime_type_end_ptr;
    u_char                    *boundary_start_ptr, *boundary_end_ptr;
    njt_atomic_uint_t          boundary;
    njt_http_upload_loc_conf_t *ulcf;

    ulcf = njt_http_get_module_loc_conf(upload_ctx->request, njt_http_upload_module);

    // Check whether Content-Type header is missing
    if(headers_in->content_type == NULL) {
        njt_log_error(NJT_LOG_ERR, upload_ctx->log, njt_errno,
                      "missing Content-Type header");
        return NJT_HTTP_BAD_REQUEST;
    }

    content_type = &headers_in->content_type->value;

    if(njt_strncasecmp(content_type->data, (u_char*) MULTIPART_FORM_DATA_STRING,
        sizeof(MULTIPART_FORM_DATA_STRING) - 1)) {

        if(!ulcf->resumable_uploads) {
            njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0,
                "Content-Type is not multipart/form-data and resumable uploads are off: %V", content_type);
            return NJT_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }
        /*
         * Content-Type is not multipart/form-data,
         * look for Content-Disposition header now
         */
        part = &headers_in->headers.part;
        header = part->elts;

        for (i = 0;;i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                  break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if(!strncasecmp(CONTENT_DISPOSITION_STRING, (char*)header[i].key.data, sizeof(CONTENT_DISPOSITION_STRING) - 1 - 1)) {
                if(upload_parse_content_disposition(upload_ctx, &header[i].value)) {
                    njt_log_error(NJT_LOG_INFO, upload_ctx->log, 0,
                        "invalid Content-Disposition header");
                    return NJT_ERROR;
                }

                upload_ctx->is_file = 1;
                upload_ctx->unencoded = 1;
                upload_ctx->raw_input = 1;
        
                upload_ctx->data_handler = upload_process_raw_buf;
            }else if(!strncasecmp(SESSION_ID_STRING, (char*)header[i].key.data, sizeof(SESSION_ID_STRING) - 1 - 1)
                || !strncasecmp(X_SESSION_ID_STRING, (char*)header[i].key.data, sizeof(X_SESSION_ID_STRING) - 1 - 1))
            {
                if(header[i].value.len == 0) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "empty Session-ID in header");
                    return NJT_ERROR;
                }

                if(njt_http_upload_validate_session_id(&header[i].value) != NJT_OK) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "invalid Session-ID in header");
                    return NJT_ERROR;
                }

                upload_ctx->session_id = header[i].value;

                njt_log_debug1(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                               "session id %V", &upload_ctx->session_id);
            }else if(!strncasecmp(CONTENT_RANGE_STRING, (char*)header[i].key.data, sizeof(CONTENT_RANGE_STRING) - 1 - 1) 
                || !strncasecmp(X_CONTENT_RANGE_STRING, (char*)header[i].key.data, sizeof(X_CONTENT_RANGE_STRING) - 1 - 1))
            {
                if(header[i].value.len == 0) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "empty Content-Range in part header");
                    return NJT_ERROR;
                }

                if(strncasecmp((char*)header[i].value.data, BYTES_UNIT_STRING, sizeof(BYTES_UNIT_STRING) - 1)) {
                    njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "unsupported range unit");
                    return NJT_ERROR;
                }

                s.data = (u_char*)(char*)header[i].value.data + sizeof(BYTES_UNIT_STRING) - 1;
                s.len = header[i].value.len - sizeof(BYTES_UNIT_STRING) + 1;

                if(njt_http_upload_parse_range(&s, &upload_ctx->content_range_n) != NJT_OK) {
                    njt_log_debug2(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "invalid range %V (%V)", &s, &header[i].value);
                    return NJT_ERROR;
                }

                njt_log_debug3(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                               "partial content, range %O-%O/%O", upload_ctx->content_range_n.start, 
                               upload_ctx->content_range_n.end, upload_ctx->content_range_n.total);

                if(ulcf->max_file_size != 0 && upload_ctx->content_range_n.total > ulcf->max_file_size) {
                    njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0,
                                  "entity length is too big");
                    return NJT_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                if( (upload_ctx->content_range_n.end - upload_ctx->content_range_n.start + 1)
                    != headers_in->content_length_n) 
                {
                    njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0,
                                  "range length is not equal to content length");
                    return NJT_HTTP_RANGE_NOT_SATISFIABLE;
                }

                upload_ctx->partial_content = 1;
            }
        }

        if(!upload_ctx->unencoded) {
            njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0,
                           "Content-Type is not multipart/form-data and no Content-Disposition header found");
            return NJT_HTTP_UNSUPPORTED_MEDIA_TYPE;
        }

        upload_ctx->content_type = *content_type;

        boundary = njt_next_temp_number(0);

        content_type->data =
            njt_pnalloc(upload_ctx->request->pool,
                        sizeof(MULTIPART_FORM_DATA_STRING "; boundary=") - 1
                        + NJT_ATOMIC_T_LEN);

        if (content_type->data == NULL) {
            return NJT_ERROR;
        }

        content_type->len =
                       njt_sprintf(content_type->data,
                                   MULTIPART_FORM_DATA_STRING "; boundary=%0muA",
                                   boundary)
                       - content_type->data;

        boundary_start_ptr = content_type->data + sizeof(MULTIPART_FORM_DATA_STRING "; boundary=") - 1;
        boundary_end_ptr = content_type->data + content_type->len;
    }
    else{
        // Find colon in content type string, which terminates mime type
        mime_type_end_ptr = (u_char*) njt_strchr(content_type->data, ';');

        upload_ctx->boundary.data = 0;

        if(mime_type_end_ptr == NULL) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "no boundary found in Content-Type");
            return NJT_UPLOAD_MALFORMED;
        }

        boundary_start_ptr = njt_strstrn(mime_type_end_ptr, BOUNDARY_STRING, sizeof(BOUNDARY_STRING) - 2);

        if(boundary_start_ptr == NULL) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "no boundary found in Content-Type");
            return NJT_UPLOAD_MALFORMED; // No boundary found
        }

        boundary_start_ptr += sizeof(BOUNDARY_STRING) - 1;
        boundary_end_ptr = boundary_start_ptr + strcspn((char*)boundary_start_ptr, " ;\n\r");

        // Handle quoted boundaries
        if ((boundary_end_ptr - boundary_start_ptr) >= 2 && boundary_start_ptr[0] == '"' && *(boundary_end_ptr - 1) == '"') {
          boundary_start_ptr++;
          boundary_end_ptr--;
        }

        if(boundary_end_ptr == boundary_start_ptr) {
            njt_log_debug0(NJT_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "boundary is empty");
            return NJT_UPLOAD_MALFORMED;
        }
    }

    // Allocate memory for entire boundary plus \r\n-- plus terminating character
    upload_ctx->boundary.len = boundary_end_ptr - boundary_start_ptr + 4;
    upload_ctx->boundary.data = njt_palloc(upload_ctx->request->pool, upload_ctx->boundary.len + 1);

    if(upload_ctx->boundary.data == NULL)
        return NJT_HTTP_INTERNAL_SERVER_ERROR;

    njt_cpystrn(upload_ctx->boundary.data + 4, boundary_start_ptr,
        boundary_end_ptr - boundary_start_ptr + 1);
    
    // Prepend boundary data by \r\n--
    upload_ctx->boundary.data[0] = '\r'; 
    upload_ctx->boundary.data[1] = '\n'; 
    upload_ctx->boundary.data[2] = '-'; 
    upload_ctx->boundary.data[3] = '-'; 

    /*
     * NOTE: first boundary doesn't start with \r\n. Here we
     * advance 2 positions forward. We will return 2 positions back 
     * later
     */
    upload_ctx->boundary_start = upload_ctx->boundary.data + 2;
    upload_ctx->boundary_pos = upload_ctx->boundary_start;

    return NJT_OK;
} /* }}} */

static njt_int_t /* {{{ njt_http_upload_parse_range */
njt_http_upload_parse_range(njt_str_t *range, njt_http_upload_range_t *range_n)
{
    u_char *p = range->data;
    u_char *last = range->data + range->len;
    off_t  *field = &range_n->start;

    if(range_n == NULL)
        return NJT_ERROR;

    do{
        *field = 0;

        while(p < last) {

            if(*p >= '0' && *p <= '9') {
                (*field) = (*field) * 10 + (*p - '0');
            }
            else if(*p == '-') {
                if(field != &range_n->start) {
                    return NJT_ERROR;
                }

                field = &range_n->end;
                p++;
                break;
            }
            else if(*p == '/') {
                if(field != &range_n->end) {
                    return NJT_ERROR;
                }

                field = &range_n->total;
                p++;
                break;
            }
            else {
                return NJT_ERROR;
            }

            p++;
        }
    }while(p < last);

    if(field != &range_n->total) {
        return NJT_ERROR;
    }

    if(range_n->start > range_n->end || range_n->start >= range_n->total
        || range_n->end >= range_n->total)
    {
        return NJT_ERROR;
    }

    return NJT_OK;
} /* }}} */

static void upload_putc(njt_http_upload_ctx_t *upload_ctx, u_char c) { /* {{{ */
    if(!upload_ctx->discard_data) {
        *upload_ctx->output_buffer_pos = c;

        upload_ctx->output_buffer_pos++;

        if(upload_ctx->output_buffer_pos == upload_ctx->output_buffer_end)
            upload_flush_output_buffer(upload_ctx);	
    }
} /* }}} */

static njt_int_t upload_process_buf(njt_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end) { /* {{{ */

	u_char *p;
    njt_int_t rc;

	// No more data?
	if(start == end) {
		if(upload_ctx->state != upload_state_finish) {
            njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0, "premature end of body");
			return NJT_UPLOAD_MALFORMED; // Signal error if still haven't finished
        }
		else
			return NJT_OK; // Otherwise confirm end of stream
    }

	for(p = start; p != end; p++) {
		switch(upload_ctx->state) {
			/*
			 * Seek the boundary
			 */
			case upload_state_boundary_seek:
				if(*p == *upload_ctx->boundary_pos) 
					upload_ctx->boundary_pos++;
				else
					upload_ctx->boundary_pos = upload_ctx->boundary_start;

				if(upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
					upload_ctx->state = upload_state_after_boundary;
					upload_ctx->boundary_start = upload_ctx->boundary.data;
					upload_ctx->boundary_pos = upload_ctx->boundary_start;
				}
				break;
			case upload_state_after_boundary:
				switch(*p) {
					case '\n':
						upload_ctx->state = upload_state_headers;
                        upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
					case '\r':
						break;
					case '-':
						upload_ctx->state = upload_state_finish;
						break;
				}
				break;
			/*
			 * Collect and store headers
			 */
			case upload_state_headers:
				switch(*p) {
					case '\n':
						if(upload_ctx->header_accumulator_pos == upload_ctx->header_accumulator) {
                            upload_ctx->is_file = (upload_ctx->file_name.data == 0) || (upload_ctx->file_name.len == 0) ? 0 : 1;

                            rc = upload_start_file(upload_ctx);
                            
                            if(rc != NJT_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // User requested to cancel processing
                            } else {
                                upload_ctx->state = upload_state_data;
                                upload_ctx->output_buffer_pos = upload_ctx->output_buffer;	
                            }
                        } else {
                            *upload_ctx->header_accumulator_pos = '\0';

                            rc = upload_parse_part_header(upload_ctx, (char*)upload_ctx->header_accumulator,
                                (char*)upload_ctx->header_accumulator_pos);

                            if(rc != NJT_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // Malformed header
                            } else
                                upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
                        }
					case '\r':
						break;
					default:
						if(upload_ctx->header_accumulator_pos < upload_ctx->header_accumulator_end - 1)
							*upload_ctx->header_accumulator_pos++ = *p;
						else {
                            njt_log_error(NJT_LOG_ERR, upload_ctx->log, 0, "part header is too long");

                            upload_ctx->state = upload_state_finish;
							return NJT_UPLOAD_MALFORMED;
                        }
						break;
				}
				break;
			/*
			 * Search for separating or terminating boundary
			 * and output data simultaneously
			 */
			case upload_state_data:
				if(*p == *upload_ctx->boundary_pos) 
					upload_ctx->boundary_pos++;
				else {
					if(upload_ctx->boundary_pos == upload_ctx->boundary_start) {
                        // IE 5.0 bug workaround
                        if(*p == '\n') {
                            /*
                             * Set current matched position beyond LF and prevent outputting
                             * CR in case of unsuccessful match by altering boundary_start 
                             */ 
                            upload_ctx->boundary_pos = upload_ctx->boundary.data + 2;
                            upload_ctx->boundary_start = upload_ctx->boundary.data + 1;
                        } else
                            upload_putc(upload_ctx, *p);
                    } else {
						// Output partially matched lump of boundary
						u_char *q;
						for(q = upload_ctx->boundary_start; q != upload_ctx->boundary_pos; q++)
							upload_putc(upload_ctx, *q);

                        p--; // Repeat reading last character

						// And reset matched position
                        upload_ctx->boundary_start = upload_ctx->boundary.data;
						upload_ctx->boundary_pos = upload_ctx->boundary_start;
					}
				}

				if(upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
					upload_ctx->state = upload_state_after_boundary;
					upload_ctx->boundary_pos = upload_ctx->boundary_start;

                    upload_flush_output_buffer(upload_ctx);
                    if(!upload_ctx->discard_data)
                        upload_finish_file(upload_ctx);
                    else
                        upload_abort_file(upload_ctx);
				}
				break;
			/*
			 * Skip trailing garbage
			 */
			case upload_state_finish:
				break;
		}
	}

	return NJT_OK;
} /* }}} */

static njt_int_t
upload_process_raw_buf(njt_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end) { /* {{{ */
    njt_int_t rc;

	if(start == end) {
        if(!upload_ctx->discard_data)
            upload_finish_file(upload_ctx);
        else
            upload_abort_file(upload_ctx);
        return NJT_OK;
    }

    if(!upload_ctx->started) {
        rc = upload_start_file(upload_ctx);
        
        if(rc != NJT_OK) {
            return rc;
        }

        upload_ctx->started = 1;
    }

    if(upload_ctx->flush_output_buffer_f)
        if(upload_ctx->flush_output_buffer_f(upload_ctx, (void*)start, 
            (size_t)(end - start)) != NJT_OK)
            upload_ctx->discard_data = 1;

    return NJT_OK;

} /* }}} */

static void /* {{{ njt_upload_cleanup_handler */
njt_upload_cleanup_handler(void *data)
{
    njt_upload_cleanup_t        *cln = data;
    njt_uint_t                  i;
    uint16_t                    *s;
    u_char                      do_cleanup = 0;

    if(!cln->aborted) {
        if(cln->fd >= 0) {
            if (njt_close_file(cln->fd) == NJT_FILE_ERROR) {
                njt_log_error(NJT_LOG_ALERT, cln->log, njt_errno,
                              njt_close_file_n " \"%s\" failed", cln->filename);
            }
        }

        if(cln->cleanup_statuses != NULL) {
            s = cln->cleanup_statuses->elts;

            for(i = 0; i < cln->cleanup_statuses->nelts; i++) {
                if(cln->headers_out->status == s[i]) {
                    do_cleanup = 1;
                }
            }
        }

        if(do_cleanup) {
                if(njt_delete_file(cln->filename) == NJT_FILE_ERROR) { 
                    njt_log_error(NJT_LOG_ERR, cln->log, njt_errno
                        , "failed to remove destination file \"%s\" after http status %l"
                        , cln->filename
                        , cln->headers_out->status
                        );
                }else
                    njt_log_error(NJT_LOG_INFO, cln->log, 0
                        , "finished cleanup of file \"%s\" after http status %l"
                        , cln->filename
                        , cln->headers_out->status
                        );
        }
    }
} /* }}} */

static njt_int_t /* {{{ */
njt_http_upload_test_expect(njt_http_request_t *r)
{
    njt_int_t   n;
    njt_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NJT_HTTP_VERSION_11)
    {
        return NJT_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || njt_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NJT_OK;
    }

    njt_log_debug0(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NJT_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NJT_ERROR;
} /* }}} */
