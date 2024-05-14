#include <njt_http.h>
#include <njt_md5.h>
#include <gd.h>

#define M_PI 3.14159265358979323846
#define MD5_BHASH_LEN 16
#define MD5_HASH_LEN (MD5_BHASH_LEN * 2)

typedef struct {
    njt_flag_t icase;
    njt_int_t level;
    njt_str_t charset;
    njt_str_t csrf;
    njt_str_t font;
    njt_str_t name;
    njt_http_complex_value_t *secret;
    njt_uint_t arg;
    njt_uint_t cookie;
    njt_uint_t expire;
    njt_uint_t height;
    njt_uint_t length;
    njt_uint_t line;
    njt_uint_t size;
    njt_uint_t star;
    njt_uint_t width;

    njt_array_t                   limits;
    njt_uint_t                    log_level;
    njt_uint_t                    status_code;
    njt_flag_t                    dry_run;
    //add by clb
#if (NJT_HTTP_DYNAMIC_LOC)
    njt_flag_t                    from_up;
#endif

} njt_http_captcha_location_t;

typedef struct {
    u_char                          color;
    u_char                          len;
    u_short                         conn;
    u_char                          data[1];
} njt_http_captcha_node_t;



typedef struct {
    njt_rbtree_t                  rbtree;
    njt_rbtree_node_t             sentinel;
} njt_http_captcha_shctx_t;


typedef struct {
    njt_http_captcha_shctx_t  *sh;
    njt_slab_pool_t              *shpool;
    njt_http_complex_value_t      key;
} njt_http_captcha_ctx_t;


typedef struct {
    njt_shm_zone_t *shm_zone;
    njt_uint_t                    max_conn_rate;
} njt_http_captcha_rate_conf_t;


typedef struct {
    njt_shm_zone_t               *shm_zone;
    njt_rbtree_node_t            *node;
} njt_http_captcha_rate_cleanup_t;


njt_module_t njt_http_captcha_module;

static int mt_rand(int min, int max) {
    return (njt_random() % (max - min + 1)) + min;
}

static void *njt_http_captcha_create_loc_conf(njt_conf_t *cf);
static char *njt_http_captcha_merge_loc_conf(njt_conf_t *cf, void *parent, void *child);

static char *njt_http_captcha_conf(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *
njt_http_captcha_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char *
njt_http_captcha_limit(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static njt_int_t njt_http_captcha_handler(njt_http_request_t *r) ;


static njt_int_t
njt_http_captcha_limit_init(njt_conf_t *cf);


static njt_command_t njt_http_captcha_commands[] = {
  { .name = njt_string("captcha"),
    .type = NJT_HTTP_LOC_CONF|NJT_CONF_NOARGS,
    .set = njt_http_captcha_conf,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = 0,
    .post = NULL },
  { .name = njt_string("captcha_case"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_flag_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, icase),
    .post = NULL },
  { .name = njt_string("captcha_expire"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, expire),
    .post = NULL },
  { .name = njt_string("captcha_height"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, height),
    .post = NULL },
  { .name = njt_string("captcha_length"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, length),
    .post = NULL },
  { .name = njt_string("captcha_size"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, size),
    .post = NULL },
  { .name = njt_string("captcha_width"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, width),
    .post = NULL },
  { .name = njt_string("captcha_line"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, line),
    .post = NULL },
  { .name = njt_string("captcha_star"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, star),
    .post = NULL },
  { .name = njt_string("captcha_level"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_num_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, level),
    .post = NULL },
  { .name = njt_string("captcha_charset"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_str_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, charset),
    .post = NULL },
  { .name = njt_string("captcha_csrf"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_str_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, csrf),
    .post = NULL },
  { .name = njt_string("captcha_font"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_str_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, font),
    .post = NULL },
  { .name = njt_string("captcha_name"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_conf_set_str_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, name),
    .post = NULL },
  { .name = njt_string("captcha_secret"),
    .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    .set = njt_http_set_complex_value_slot,
    .conf = NJT_HTTP_LOC_CONF_OFFSET,
    .offset = offsetof(njt_http_captcha_location_t, secret),
    .post = NULL },
     {.name = njt_string("captcha_zone"),
      .type = NJT_HTTP_MAIN_CONF|NJT_CONF_TAKE2,
      .set  = njt_http_captcha_zone,
      .conf = 0,
      .offset = 0,
      .post   = NULL },
       { .name = njt_string("captcha_limit_rate"),
         .type = NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE2,
         .set  = njt_http_captcha_limit,
         .conf = NJT_HTTP_LOC_CONF_OFFSET,
         .offset = 0,
         .post = NULL },
    njt_null_command
};


static njt_http_module_t njt_http_captcha_ctx = {
    .preconfiguration = NULL,
    .postconfiguration = njt_http_captcha_limit_init,
    .create_main_conf = NULL,
    .init_main_conf = NULL,
    .create_srv_conf = NULL,
    .merge_srv_conf = NULL,
    .create_loc_conf = njt_http_captcha_create_loc_conf,
    .merge_loc_conf = njt_http_captcha_merge_loc_conf
};

njt_module_t njt_http_captcha_module = {
    NJT_MODULE_V1,
    .ctx = &njt_http_captcha_ctx,
    .commands = njt_http_captcha_commands,
    .type = NJT_HTTP_MODULE,
    .init_master = NULL,
    .init_module = NULL,
    .init_process = NULL,
    .init_thread = NULL,
    .exit_thread = NULL,
    .exit_process = NULL,
    .exit_master = NULL,
    NJT_MODULE_V1_PADDING
};





static njt_rbtree_node_t *
njt_http_captcha_limit_lookup(njt_rbtree_t *rbtree, njt_str_t *key, uint32_t hash)
{
    njt_int_t                    rc;
    njt_rbtree_node_t           *node, *sentinel;
    njt_http_captcha_node_t  *lcn;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        lcn = (njt_http_captcha_node_t *) &node->color;

        rc = njt_memn2cmp(key->data, lcn->data, key->len, (size_t) lcn->len);

        if (rc == 0) {
            return node;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static njt_int_t
njt_http_captcha_limit_handler(njt_http_request_t *r)
{
    size_t                          n;
    uint32_t                        hash;
    njt_str_t                       key;
    njt_uint_t                      i;
    njt_rbtree_node_t              *node;
    //njt_pool_cleanup_t             *cln;
    njt_http_captcha_ctx_t      *ctx;
    njt_http_captcha_node_t     *lc;
    njt_http_captcha_location_t     *lccf;
    njt_http_captcha_rate_conf_t    *limits;
    //njt_http_captcha_rate_cleanup_t  *lccln;


    lccf = njt_http_get_module_loc_conf(r, njt_http_captcha_module);
    limits = lccf->limits.elts;

    for (i = 0; i < lccf->limits.nelts; i++) {
        ctx = limits[i].shm_zone->data;

        if (njt_http_complex_value(r, &ctx->key, &key) != NJT_OK) {
            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (key.len == 0) {
            continue;
        }

        if (key.len > 255) {
            njt_log_error(NJT_LOG_ERR, r->connection->log, 0,
                          "the value of the \"%V\" key "
                          "is more than 255 bytes: \"%V\"",
                          &ctx->key.value, &key);
            continue;
        }



        hash = njt_crc32_short(key.data, key.len);

        njt_shmtx_lock(&ctx->shpool->mutex);

        node = njt_http_captcha_limit_lookup(&ctx->sh->rbtree, &key, hash);

        if (node == NULL) {

            n = offsetof(njt_rbtree_node_t, color)
                + offsetof(njt_http_captcha_node_t, data)
                + key.len;

            node = njt_slab_alloc_locked(ctx->shpool, n);

            if (node == NULL) {
               
                return lccf->status_code;  //zyg todo;
            }

            lc = (njt_http_captcha_node_t *) &node->color;

            node->key = hash;
            lc->len = (u_char) key.len;
            lc->conn = 1;
            njt_memcpy(lc->data, key.data, key.len);

            njt_rbtree_insert(&ctx->sh->rbtree, node);

        } else {

            lc = (njt_http_captcha_node_t *) &node->color;
            lc->conn++;
        }

        njt_log_debug2(NJT_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "limit conn: %08Xi %d", node->key, lc->conn);

        njt_shmtx_unlock(&ctx->shpool->mutex);
    }

    return NJT_DECLINED;
}


static njt_int_t
njt_http_captcha_limit_init(njt_conf_t *cf)
{
    njt_http_handler_pt        *h;
    njt_http_core_main_conf_t  *cmcf;

    cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

    h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NJT_ERROR;
    }

    *h = njt_http_captcha_limit_handler;

    return NJT_OK;
}


static njt_int_t njt_http_captcha_handler(njt_http_request_t *r) {

/*
    njt_http_complex_value_t  text;
    njt_str_t rename = njt_string("http://www.baidu.com");

    njt_memzero(&text,sizeof(njt_http_complex_value_t));

    text.value = rename;

    return njt_http_send_response(r,NJT_HTTP_MOVED_PERMANENTLY,NULL,&text);
*/
    size_t i;
    njt_uint_t number,brect[8],x;
    if (!(r->method & (NJT_HTTP_GET|NJT_HTTP_HEAD))) return NJT_HTTP_NOT_ALLOWED;
    njt_int_t rc = njt_http_discard_request_body(r);
    if (rc != NJT_OK && rc != NJT_AGAIN) return rc;
    njt_http_captcha_location_t *location = njt_http_get_module_loc_conf(r, njt_http_captcha_module);
    if (!location->secret)  { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!location->secret"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    u_char *code = njt_pnalloc(r->pool, location->length + 1);
    if (!code) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!njt_pnalloc"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    for (i = 0; i < location->length; i++) code[i] = location->charset.data[mt_rand(0, location->charset.len - 1)];
    code[location->length] = '\0';
    njt_http_variable_value_t *csrf = njt_http_get_indexed_variable(r, location->cookie);
    if (!csrf || !csrf->data || !csrf->len) {
        njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "captcha: no \"%V\" cookie specified, trying arg...", &location->csrf);
        csrf = njt_http_get_indexed_variable(r, location->arg);
        if (!csrf || !csrf->data || !csrf->len) { njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "captcha: no \"%V\" arg specified", &location->csrf); return NJT_HTTP_NOT_FOUND; }
    }
    if (location->icase) {
        u_char *icode = njt_pnalloc(r->pool, location->length);
        if (!icode) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!njt_pnalloc"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
        (void)njt_strlow(icode, code, location->length);
        code = icode;
    }
    njt_md5_t md5;
    (void)njt_md5_init(&md5);
    njt_str_t secret;
    if (njt_http_complex_value(r, location->secret, &secret) != NJT_OK) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "njt_http_complex_value != NJT_OK"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    (void)njt_md5_update(&md5, (const void *)secret.data, secret.len);
    (void)njt_md5_update(&md5, (const void *)code, (size_t)location->length);
    (void)njt_md5_update(&md5, (const void *)csrf->data, csrf->len);
    u_char bhash[MD5_BHASH_LEN];
    (void)njt_md5_final(bhash, &md5);
    u_char hash[MD5_HASH_LEN + 1];
    (u_char *)njt_hex_dump(hash, bhash, MD5_BHASH_LEN);
    hash[MD5_HASH_LEN] = '\0';
    njt_table_elt_t *set_cookie_name = njt_list_push(&r->headers_out.headers);
    if (!set_cookie_name) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!njt_list_push"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    set_cookie_name->hash = 1;
    njt_str_set(&set_cookie_name->key, "Set-Cookie");
    set_cookie_name->value.len = location->name.len + MD5_HASH_LEN + sizeof("%V=%s; Max-Age=%d") - 1 - 6;
    for (number = location->expire; number /= 10; set_cookie_name->value.len++);
    set_cookie_name->value.len++;
    if (!(set_cookie_name->value.data = njt_pnalloc(r->pool, set_cookie_name->value.len))) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!njt_pnalloc"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    if (njt_snprintf(set_cookie_name->value.data, set_cookie_name->value.len, "%V=%s; Max-Age=%d", &location->name, hash, location->expire) != set_cookie_name->value.data + set_cookie_name->value.len) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "njt_snprintf"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    njt_str_set(&r->headers_out.content_type, "image/png");
    r->headers_out.status = NJT_HTTP_OK;
    r->headers_out.content_length_n = 0;
    if (r->method == NJT_HTTP_HEAD) {
        rc = njt_http_send_header(r);
        if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) return rc;
    }
    njt_memzero(brect,sizeof(brect));
    gdFTUseFontConfig(1);
    gdImagePtr img = gdImageCreateTrueColor(location->width, location->height);
    if (!img) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!gdImageCreateTrueColor"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    (void)gdImageFilledRectangle(img, 0, location->height, location->width, 0, gdImageColorAllocate(img, mt_rand(157, 255), mt_rand(157, 255), mt_rand(157, 255)));
    for (i = 0, x = location->width / location->length; i < location->length; i++) (char *)gdImageStringFT(img, (int *)brect, gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)), (char *)location->font.data, location->size, mt_rand(-30, 30) * (M_PI / 180), x * i + mt_rand(1, 5), location->height / 1.4, (char *)(u_char [2]){*code++, '\0'});
    for (i = 0; i < location->line; i++) (void)gdImageLine(img, mt_rand(0, location->width), mt_rand(0, location->height), mt_rand(0, location->width), mt_rand(0, location->height), gdImageColorAllocate(img, mt_rand(0, 156), mt_rand(0, 156), mt_rand(0, 156)));
    njt_memzero(brect,sizeof(brect));
    for (i = 0; i < location->star; i++) (char *)gdImageStringFT(img, (int *)brect, gdImageColorAllocate(img, mt_rand(200, 255), mt_rand(200, 255), mt_rand(200, 255)), (char *)location->font.data, 8, 0, mt_rand(0, location->width), mt_rand(0, location->height), "*");
    int size;
    u_char *img_buf = (u_char *)gdImagePngPtrEx(img, &size, location->level);
    (void)gdImageDestroy(img);
    if (!img_buf) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!gdImagePngPtrEx"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    njt_buf_t *b = njt_create_temp_buf(r->pool, size);
    if (!b) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "!njt_create_temp_buf"); gdFree(img_buf); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    b->memory = 1;
    b->last_buf = 1;
    b->last = njt_copy(b->last, img_buf, size);
    gdFree(img_buf);
    if (b->last != b->end) { njt_log_error(NJT_LOG_ERR, r->connection->log, 0, "b->last != b->end"); return NJT_HTTP_INTERNAL_SERVER_ERROR; }
    r->headers_out.content_length_n = size;
    rc = njt_http_send_header(r);
    if (rc == NJT_ERROR || rc > NJT_OK || r->header_only) return rc;
    njt_chain_t cl = {.buf = b, .next = NULL};
    return njt_http_output_filter(r, &cl);
}

static char *njt_http_captcha_conf(njt_conf_t *cf, njt_command_t *cmd, void *conf) {
    njt_http_core_loc_conf_t *clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    clcf->handler = njt_http_captcha_handler;
    return NJT_CONF_OK;
}



static char *
njt_http_captcha_limit(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    njt_shm_zone_t               *shm_zone;
    njt_http_captcha_location_t   *lccf = conf;
    njt_http_captcha_rate_conf_t  *limit, *limits;

    njt_str_t  *value;
    njt_int_t   n;
    njt_uint_t  i;

    value = cf->args->elts;

    shm_zone = njt_shared_memory_add(cf, &value[1], 0,
                                     &njt_http_captcha_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    limits = lccf->limits.elts;

    if (limits == NULL) {
        if (njt_array_init(&lccf->limits, cf->pool, 1,
                           sizeof(njt_http_captcha_rate_conf_t))
            != NJT_OK)
        {
            return NJT_CONF_ERROR;
        }
    }

    for (i = 0; i < lccf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    n = njt_atoi(value[2].data, value[2].len);
    if (n <= 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid number of connections \"%V\"", &value[2]);
        return NJT_CONF_ERROR;
    }

    if (n > 65535) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "connection limit must be less 65536");
        return NJT_CONF_ERROR;
    }

    limit = njt_array_push(&lccf->limits);
    if (limit == NULL) {
        return NJT_CONF_ERROR;
    }

    limit->max_conn_rate = n;
    limit->shm_zone = shm_zone;

    return NJT_CONF_OK;
}

static void
njt_http_captcha_rbtree_insert_value(njt_rbtree_node_t *temp,
    njt_rbtree_node_t *node, njt_rbtree_node_t *sentinel)
{
    njt_rbtree_node_t             **p;
    njt_http_captcha_node_t   *lcn, *lcnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lcn = (njt_http_captcha_node_t *) &node->color;
            lcnt = (njt_http_captcha_node_t *) &temp->color;

            p = (njt_memn2cmp(lcn->data, lcnt->data, lcn->len, lcnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    njt_rbt_red(node);
}

static njt_int_t
njt_http_captcha_init_zone(njt_shm_zone_t *shm_zone, void *data)
{
    njt_http_captcha_ctx_t  *octx = data;

    size_t                        len;
    njt_http_captcha_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || njt_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            njt_log_error(NJT_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_conn_zone \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NJT_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NJT_OK;
    }

    ctx->shpool = (njt_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NJT_OK;
    }

    ctx->sh = njt_slab_alloc(ctx->shpool,
                             sizeof(njt_http_captcha_shctx_t));
    if (ctx->sh == NULL) {
        return NJT_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    njt_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    njt_http_captcha_rbtree_insert_value);

    len = sizeof(" in limit_conn_zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = njt_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NJT_ERROR;
    }

    njt_sprintf(ctx->shpool->log_ctx, " in limit_conn_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NJT_OK;
}

static char *
njt_http_captcha_zone(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    u_char                            *p;
    ssize_t                            size;
    njt_str_t                         *value, name, s;
    njt_uint_t                         i;
    njt_shm_zone_t                    *shm_zone;
    njt_http_captcha_ctx_t         *ctx;
    njt_http_compile_complex_value_t   ccv;
    //njt_str_t  var_name = njt_string("$binary_remote_addr");

    value = cf->args->elts;

    ctx = njt_pcalloc(cf->pool, sizeof(njt_http_captcha_ctx_t));
    if (ctx == NULL) {
        return NJT_CONF_ERROR;
    }

    njt_memzero(&ccv, sizeof(njt_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &ctx->key;

    if (njt_http_compile_complex_value(&ccv) != NJT_OK) {
        return NJT_CONF_ERROR;
    }

    size = 0;
    name.len = 0;

    for (i = 2; i < cf->args->nelts; i++) {

        if (njt_strncmp(value[i].data, "zone=", 5) == 0) {

            name.data = value[i].data + 5;

            p = (u_char *) njt_strchr(name.data, ':');

            if (p == NULL) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = value[i].data + value[i].len - s.data;

            size = njt_parse_size(&s);

            if (size == NJT_ERROR) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[i]);
                return NJT_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * njt_pagesize)) {
                njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[i]);
                return NJT_CONF_ERROR;
            }

            continue;
        }

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NJT_CONF_ERROR;
    }

    if (name.len == 0) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" must have \"zone\" parameter",
                           &cmd->name);
        return NJT_CONF_ERROR;
    }

    shm_zone = njt_shared_memory_add(cf, &name, size,
                                     &njt_http_captcha_module);
    if (shm_zone == NULL) {
        return NJT_CONF_ERROR;
    }

    if (shm_zone->data) {
        ctx = shm_zone->data;

        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "%V \"%V\" is already bound to key \"%V\"",
                           &cmd->name, &name, &ctx->key.value);
        return NJT_CONF_ERROR;
    }

    shm_zone->init = njt_http_captcha_init_zone;
    shm_zone->data = ctx;

    return NJT_CONF_OK;
}



static void *njt_http_captcha_create_loc_conf(njt_conf_t *cf) {
    njt_http_captcha_location_t *location = njt_pcalloc(cf->pool, sizeof(*location));
    if (!location) return NULL;
    location->icase = NJT_CONF_UNSET;
    location->expire = NJT_CONF_UNSET_UINT;
    location->height = NJT_CONF_UNSET_UINT;
    location->length = NJT_CONF_UNSET_UINT;
    location->size = NJT_CONF_UNSET_UINT;
    location->width = NJT_CONF_UNSET_UINT;
    location->line = NJT_CONF_UNSET_UINT;
    location->star = NJT_CONF_UNSET_UINT;
    location->level = NJT_CONF_UNSET;
    return location;
}

static char *njt_http_captcha_merge_loc_conf(njt_conf_t *cf, void *parent, void *child) {
    njt_http_captcha_location_t *prev = parent;
    njt_http_captcha_location_t *conf = child;
    njt_conf_merge_value(conf->icase, prev->icase, 1);
    njt_conf_merge_uint_value(conf->expire, prev->expire, 300);
    njt_conf_merge_uint_value(conf->height, prev->height, 30);
    njt_conf_merge_uint_value(conf->length, prev->length, 4);
    njt_conf_merge_uint_value(conf->size, prev->size, 20);
    njt_conf_merge_uint_value(conf->width, prev->width, 130);
    njt_conf_merge_uint_value(conf->line, prev->line, 10);
    njt_conf_merge_uint_value(conf->star, prev->star, 100);
    njt_conf_merge_value(conf->level, prev->level, -1);
    if (conf->level > 9) conf->level = 9; else if (conf->level < -1) conf->level = -1;
    njt_conf_merge_str_value(conf->charset, prev->charset, "abcdefghkmnprstuvwxyzABCDEFGHKMNPRSTUVWXYZ23456789");
    njt_conf_merge_str_value(conf->csrf, prev->csrf, "csrf");
    njt_conf_merge_str_value(conf->font, prev->font, "/usr/local/share/fonts/NimbusSans-Regular.ttf");
    njt_conf_merge_str_value(conf->name, prev->name, "Captcha");
    if (!conf->secret) conf->secret = prev->secret;
    if (conf->size > conf->height) return "captcha size is too large";
    if (!conf->name.len) return "captcha name cannot be empty";
//    if (!conf->secret) return "captcha secret cannot be empty";
    if (!conf->font.len) return "captcha font cannot be empty";
    if (!conf->charset.len) return "captcha charset cannot be empty";
    if (!conf->csrf.len) return "captcha csrf cannot be empty";
    if (prev->cookie && prev->arg) {
        conf->cookie = prev->cookie;
        conf->arg = prev->arg;
    } else {
        njt_str_t name;
        name.len = conf->csrf.len + sizeof("cookie_%V") - 1 - 2;
        if (!(name.data = njt_pnalloc(cf->pool, name.len))) return "!njt_pnalloc";
        if (njt_snprintf(name.data, name.len, "cookie_%V", &conf->csrf) != name.data + name.len) return "njt_snprintf";
        njt_int_t index = njt_http_get_variable_index(cf, &name);
        if (index == NJT_ERROR) return "njt_http_get_variable_index == NJT_ERROR";
        conf->cookie = (njt_uint_t) index;
        name.data += 3;
        name.len -= 3;
        name.data[0] = 'a';
        name.data[1] = 'r';
        name.data[2] = 'g';
        index = njt_http_get_variable_index(cf, &name);
        if (index == NJT_ERROR) return "njt_http_get_variable_index == NJT_ERROR";
        conf->arg = (njt_uint_t) index;
    }
    return NJT_CONF_OK;
}


