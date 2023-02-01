/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) TMLake, Inc.
 */
#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#include <jwt.h>
//#include <jansson.h>

typedef struct {
  njt_str_t jwt_key;          // Forwarded key (with auth_jwt_key)
  njt_int_t jwt_flag;         // Function of "auth_jwt": on -> 1 | off -> 0 | $variable -> 2
  njt_int_t jwt_var_index;    // Used only if jwt_flag==2 to fetch the $variable value
  njt_uint_t jwt_algorithm;
} njt_http_auth_jwt_loc_conf_t;

#define NJT_HTTP_AUTH_JWT_OFF        0
#define NJT_HTTP_AUTH_JWT_BEARER     1
#define NJT_HTTP_AUTH_JWT_VARIABLE   2

#define NJT_HTTP_AUTH_JWT_ENCODING_HEX     0
#define NJT_HTTP_AUTH_JWT_ENCODING_BASE64  1
#define NJT_HTTP_AUTH_JWT_ENCODING_UTF8    2

#define JWT_ALG_ANY JWT_ALG_NONE

/*
 * Enum of accepted jwt algorithms, mapped on the libjwt one.
 * Note that the "any" string is mapped on the JWT_ALG_ANY=JWT_ALG_NONE value to avoid conflict with other ones.
 */
static njt_conf_enum_t njt_http_auth_jwt_algorithms[] = {
  { njt_string("HS256"), JWT_ALG_HS256 },
  { njt_string("HS384"), JWT_ALG_HS384 },
  { njt_string("HS512"), JWT_ALG_HS512 },
  { njt_string("RS256"), JWT_ALG_RS256 },
  { njt_string("RS384"), JWT_ALG_RS384 },
  { njt_string("RS512"), JWT_ALG_RS512 },
  { njt_string("ES256"), JWT_ALG_ES256 },
  { njt_string("ES384"), JWT_ALG_ES384 },
  { njt_string("ES512"), JWT_ALG_ES512 },
  { njt_string("any"), JWT_ALG_ANY }
};

static njt_int_t njt_http_auth_jwt_handler(njt_http_request_t *r);
static njt_int_t auth_jwt_get_token(u_char **token, njt_http_request_t *r, const njt_http_auth_jwt_loc_conf_t *conf);
static char * auth_jwt_key_from_file(njt_conf_t *cf, const char *path, njt_str_t *key);
static u_char * auth_jwt_safe_string(njt_pool_t *pool, u_char *src, size_t len);

// Configuration functions
static njt_int_t njt_http_auth_jwt_init(njt_conf_t *cf);
static void * njt_http_auth_jwt_create_conf(njt_conf_t *cf);
static char * njt_http_auth_jwt_merge_conf(njt_conf_t *cf, void *parent, void *child);

// Declaration functions
static char * njt_conf_set_auth_jwt_key(njt_conf_t *cf, njt_command_t *cmd, void *conf);
static char * njt_conf_set_auth_jwt(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_command_t njt_http_auth_jwt_commands[] = {

  // auth_jwt_key value [hex | base64 | utf8 | file];
  { njt_string("auth_jwt_key"),
    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE12,
    njt_conf_set_auth_jwt_key,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_auth_jwt_loc_conf_t, jwt_key),
    NULL },

  // auth_jwt $variable | off | on;
  { njt_string("auth_jwt"),
    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    njt_conf_set_auth_jwt,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_auth_jwt_loc_conf_t, jwt_flag),
    NULL },

  // auth_jwt_alg HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512;
  { njt_string("auth_jwt_alg"),
    NJT_HTTP_MAIN_CONF|NJT_HTTP_SRV_CONF|NJT_HTTP_LOC_CONF|NJT_CONF_TAKE1,
    njt_conf_set_enum_slot,
    NJT_HTTP_LOC_CONF_OFFSET,
    offsetof(njt_http_auth_jwt_loc_conf_t, jwt_algorithm),
    &njt_http_auth_jwt_algorithms },

  njt_null_command
};


static njt_http_module_t njt_http_auth_jwt_module_ctx = {
  NULL,                        /* preconfiguration */
  njt_http_auth_jwt_init,      /* postconfiguration */

  NULL,                        /* create main configuration */
  NULL,                        /* init main configuration */

  NULL,                        /* create server configuration */
  NULL,                        /* merge server configuration */

  njt_http_auth_jwt_create_conf,             /* create location configuration */
  njt_http_auth_jwt_merge_conf               /* merge location configuration */
};


njt_module_t njt_http_auth_jwt_module = {
  NJT_MODULE_V1,
  &njt_http_auth_jwt_module_ctx,     /* module context */
  njt_http_auth_jwt_commands,        /* module directives */
  NJT_HTTP_MODULE,                   /* module type */
  NULL,                              /* init master */
  NULL,                              /* init module */
  NULL,                              /* init process */
  NULL,                              /* init thread */
  NULL,                              /* exit thread */
  NULL,                              /* exit process */
  NULL,                              /* exit master */
  NJT_MODULE_V1_PADDING
};


static njt_int_t njt_http_auth_jwt_handler(njt_http_request_t *r)
{
  const njt_http_auth_jwt_loc_conf_t *conf;
  u_char *jwt_data;
  jwt_t *jwt = NULL;

  conf = njt_http_get_module_loc_conf(r, njt_http_auth_jwt_module);

  // Pass through if "auth_jwt" is "off"
  if (conf->jwt_flag == NJT_HTTP_AUTH_JWT_OFF)
  {
    return NJT_DECLINED;
  }

  // Pass through options requests without token authentication
  if (r->method == NJT_HTTP_OPTIONS)
  {
    return NJT_DECLINED;
  }

  // Get jwt
  if (auth_jwt_get_token(&jwt_data, r, conf) != NJT_OK)
  {
    njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "JWT: failed to find a jwt");
    return NJT_HTTP_UNAUTHORIZED;
  }

  // Validate the jwt
  if (jwt_decode(&jwt, (char *)jwt_data, conf->jwt_key.data, conf->jwt_key.len))
  {
    njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "JWT: failed to parse jwt");
    return NJT_HTTP_UNAUTHORIZED;
  }
  // jwt_decode succeded and allocated an jwt object.
  // We register jwt_free as a function to be called on pool cleanup.
  njt_pool_cleanup_t *cln = njt_pool_cleanup_add(r->pool, 0);
  if (cln == NULL)
  {
    jwt_free(jwt);
    return NJT_ERROR;
  }
  cln->handler = (njt_pool_cleanup_pt)jwt_free;
  cln->data = jwt;

  // Validate the algorithm
  jwt_alg_t alg = jwt_get_alg(jwt);
  // Reject incoming token with a "none" algorithm, or, if auth_jwt_alg is set, those with a different one.
  if (alg == JWT_ALG_NONE || (conf->jwt_algorithm != JWT_ALG_ANY && conf->jwt_algorithm != alg))
  {
    njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "JWT: invalid algorithm in jwt %d", jwt_get_alg(jwt));
    return NJT_HTTP_UNAUTHORIZED;
  }

  // Validate the exp date of the JWT; Still valid if "exp" missing (exp == -1)
  time_t exp = (time_t)jwt_get_grant_int(jwt, "exp");
  if (exp != -1 && exp < time(NULL))
  {
    njt_log_error(NJT_LOG_INFO, r->connection->log, 0, "JWT: the jwt has expired [exp=%ld]", (long)exp);
    return NJT_HTTP_UNAUTHORIZED;
  }

  return NJT_OK;
}


static njt_int_t njt_http_auth_jwt_init(njt_conf_t *cf)
{
  njt_http_handler_pt        *h;
  njt_http_core_main_conf_t  *cmcf;

  cmcf = njt_http_conf_get_module_main_conf(cf, njt_http_core_module);

  h = njt_array_push(&cmcf->phases[NJT_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL)
  {
    return NJT_ERROR;
  }

  *h = njt_http_auth_jwt_handler;

  return NJT_OK;
}


static void * njt_http_auth_jwt_create_conf(njt_conf_t *cf)
{
  njt_http_auth_jwt_loc_conf_t *conf;

  conf = njt_pcalloc(cf->pool, sizeof(njt_http_auth_jwt_loc_conf_t));
  if (conf == NULL)
  {
    njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: conf==NULL");
    return NULL;
  }

  // Initialize variables
  njt_str_null(&conf->jwt_key);
  conf->jwt_flag = NJT_CONF_UNSET;
  conf->jwt_var_index = NJT_CONF_UNSET;
  conf->jwt_algorithm = NJT_CONF_UNSET_UINT;

  return conf;
}


static char * njt_http_auth_jwt_merge_conf(njt_conf_t *cf, void *parent, void *child)
{
  njt_http_auth_jwt_loc_conf_t *prev = parent;
  njt_http_auth_jwt_loc_conf_t *conf = child;

  njt_conf_merge_str_value(conf->jwt_key, prev->jwt_key, "");
  njt_conf_merge_value(conf->jwt_var_index, prev->jwt_var_index, NJT_CONF_UNSET);
  njt_conf_merge_value(conf->jwt_flag, prev->jwt_flag, NJT_HTTP_AUTH_JWT_OFF);
  njt_conf_merge_uint_value(conf->jwt_algorithm, prev->jwt_algorithm, JWT_ALG_ANY);

  return NJT_CONF_OK;
}

// Convert an hexadecimal string to a binary string
static int hex_to_binary(u_char* dest, u_char* src, const size_t n)
{
    size_t i;
    u_char *p = &dest[0];
    njt_int_t dst;
    for( i = 0; i < n; i += 2) {
      dst = njt_hextoi(&src[i], 2);
      if (dst == NJT_ERROR || dst > 255)
      {
        return NJT_ERROR;
      }
      *p++ = (u_char) dst;
    }
    return NJT_OK;
}


// Assign key from file
static char * auth_jwt_key_from_file(njt_conf_t *cf, const char *path, njt_str_t *key)
{
  // Determine file size (avoiding fseek)
  struct stat fstat;
  if (stat(path, &fstat) < 0)
  {
    njt_conf_log_error(NJT_LOG_ERR, cf, errno, strerror(errno));
    return NJT_CONF_ERROR;
  }

  FILE *fp = fopen(path, "rb");
  if (fp == NULL)
  {
    njt_conf_log_error(NJT_LOG_ERR, cf, errno, strerror(errno));
    return NJT_CONF_ERROR;
  }

  key->len = fstat.st_size;
  key->data = njt_pcalloc(cf->pool, key->len);

  if (fread(key->data, 1, key->len, fp) != key->len)
  {
    njt_conf_log_error(NJT_LOG_ERR, cf, 0, "jwt_key file: unexpected end of file");
    fclose(fp);
    return NJT_CONF_ERROR;
  }

  fclose(fp);

  return NJT_CONF_OK;
}


// Parse auth_jwt_key directive
static char * njt_conf_set_auth_jwt_key(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
  njt_str_t *key = conf;
  njt_str_t *value;
  njt_uint_t encoding;

  value = cf->args->elts;

  // If jwt_key.data not null
  if (key->data != NULL)
  {
    return "is duplicate";
  }

  // If there is only the key string;
  if (cf->args->nelts == 2)
  {
    encoding = NJT_HTTP_AUTH_JWT_ENCODING_UTF8;
  }
  // We can have (auth_jwt_key value [encoding | file])
  else if (cf->args->nelts == 3)
  {
    if (njt_strcmp(value[2].data, "file") == 0)
    {
      const char *path = (char *)auth_jwt_safe_string(cf->pool, value[1].data, value[1].len);
      return auth_jwt_key_from_file(cf, path, key);
    }
    else if (njt_strcmp(value[2].data, "hex") == 0)
      encoding = NJT_HTTP_AUTH_JWT_ENCODING_HEX;
    else if (njt_strcmp(value[2].data, "base64") == 0)
      encoding = NJT_HTTP_AUTH_JWT_ENCODING_BASE64;
    else if (njt_strcmp(value[2].data, "utf8") == 0)
      encoding = NJT_HTTP_AUTH_JWT_ENCODING_UTF8;
    else
      return NJT_CONF_ERROR;
  }
  else
  {
    return NJT_CONF_ERROR;
  }

  njt_str_t *keystr = &value[1];

  if (keystr->len == 0 || keystr->data == NULL)
  {
    njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Invalid key");
    return NJT_CONF_ERROR;
  }

  switch (encoding)
  {
    case NJT_HTTP_AUTH_JWT_ENCODING_HEX:
      // Parse provided key
      if (keystr->len % 2)
      {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Invalid hex string");
        return NJT_CONF_ERROR;
      }
      key->data = njt_palloc(cf->pool, keystr->len / 2);
      key->len = keystr->len / 2;
      if (hex_to_binary(key->data, keystr->data, keystr->len) != NJT_OK)
      {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Failed to turn hex key into binary");
        return NJT_CONF_ERROR;
      }
      return NJT_CONF_OK;
    case NJT_HTTP_AUTH_JWT_ENCODING_BASE64:
      key->len = njt_base64_decoded_length(keystr->len);
      key->data = njt_palloc(cf->pool, key->len);

      if (njt_decode_base64(key, keystr) != NJT_OK)
      {
        njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Failed to turn base64 key into binary");
        return NJT_CONF_ERROR;
      }
      return NJT_CONF_OK;
    case NJT_HTTP_AUTH_JWT_ENCODING_UTF8:
      key->data = keystr->data;
      key->len = keystr->len;
      return NJT_CONF_OK;
    default:
      return NJT_CONF_ERROR;
  }

  return NJT_CONF_ERROR;
}


// Parse auth_jwt directive
static char * njt_conf_set_auth_jwt(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
  njt_http_auth_jwt_loc_conf_t *ajcf = conf;

  njt_int_t *flag = &ajcf->jwt_flag;
  njt_int_t *index = &ajcf->jwt_var_index;

  if (*flag != NJT_CONF_UNSET)
  {
    return "is duplicate";
  }

  const njt_str_t *value = cf->args->elts;

  const njt_str_t var = value[1];

  if (var.len == 0)
  {
    njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Invalid value");
    return NJT_CONF_ERROR;
  }

  // Check if enabled, if not: return conf.
  if (var.len == 3 && njt_strncmp(var.data, "off", 3) == 0)
  {
    *flag = NJT_HTTP_AUTH_JWT_OFF;
  }
  // If enabled and "on" we will get token from "Authorization" header.
  else if (var.len == 2 && njt_strncmp(var.data, "on", 2) == 0)
  {
    *flag = NJT_HTTP_AUTH_JWT_BEARER;
  }
  // Else we will get token from passed variable.
  else
  {
    *flag = NJT_HTTP_AUTH_JWT_VARIABLE;

    if (var.data[0] != '$')
    {
      njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Invalid variable name %s", var.data);
      return NJT_CONF_ERROR;
    }

    njt_str_t str = { .data = var.data + 1, .len = var.len - 1 };

    *index = njt_http_get_variable_index(cf, &str);
    if (*index == NJT_ERROR)
    {
      njt_conf_log_error(NJT_LOG_ERR, cf, 0, "JWT: Can get index for {data: %s, len: %d}", var.data, var.len);
      return NJT_CONF_ERROR;
    }
  }

  return NJT_CONF_OK;
}


// Copy a character array into a null terminated one.
static u_char * auth_jwt_safe_string(njt_pool_t *pool, u_char *src, size_t len)
{
  u_char  *dst;

  dst = njt_pcalloc(pool, len + 1);
  if (dst == NULL)
  {
    return NULL;
  }

  njt_memcpy(dst, src, len);

  dst[len] = '\0';

  return dst;
}


static njt_int_t auth_jwt_get_token(u_char **token, njt_http_request_t *r, const njt_http_auth_jwt_loc_conf_t *conf)
{
  static const njt_str_t bearer = njt_string("Bearer ");
  const njt_int_t flag = conf->jwt_flag;

  if (flag == NJT_HTTP_AUTH_JWT_BEARER)
  {
    if (r->headers_in.authorization == NULL)
    {
      return NJT_DECLINED;
    }

    njt_str_t header = r->headers_in.authorization->value;

    // If the "Authorization" header value is less than "Bearer X" length, there is no reason to continue.
    if (header.len < bearer.len + 1)
    {
     njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "JWT: Invalid Authorization length");
     return NJT_DECLINED;
    }
    // If the "Authorization" header does not starts with "Bearer ", return NULL.
    if (njt_strncmp(header.data, bearer.data, bearer.len) != 0)
    {
      njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "JWT: Invalid authorization header content");
      return NJT_DECLINED;
    }

    *token = auth_jwt_safe_string(r->pool, header.data + bearer.len, (size_t) header.len - bearer.len);
  }
  else if (flag == NJT_HTTP_AUTH_JWT_VARIABLE)
  {
    njt_http_variable_value_t * value = njt_http_get_indexed_variable(r, conf->jwt_var_index);

    if (value == NULL || value->not_found || value->len == 0)
    {
      njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "JWT: Variable not found or empty.");
      return NJT_DECLINED;
    }

    *token = auth_jwt_safe_string(r->pool, value->data, value->len);
  }
  else
  {
    njt_log_error(NJT_LOG_ALERT, r->connection->log, 0, "JWT: Invalid flag [%d]", flag);
    return NJT_ERROR;
  }

  if (token == NULL)
  {
    njt_log_error(NJT_LOG_WARN, r->connection->log, 0, "Could not allocate memory.");
    return NJT_ERROR;
  }

  return NJT_OK;
}
