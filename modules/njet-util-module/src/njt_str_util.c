/*************************************************************************************
 Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 File name    : njt_str_util.c
 Version      : 1.0
 Author       : ChengXu
 Date         : 2023/2/16/016 
 Description  : 
 Other        :
 History      :
 <author>       <time>          <version >      <desc>
 ChengXu        2023/2/16/016       1.1             
***********************************************************************************/
//
// Created by Administrator on 2023/2/16/016.
//

#include <njt_str_util.h>

njt_int_t njt_str_split(njt_str_t *src,njt_array_t *array,char sign){
    u_char              *p, *last, *end;
    size_t               len;
    njt_str_t           *pwd;

    p = last=src->data;
    end = src->data + src->len;
    for ( ;last < end ; ) {
        last = njt_strlchr(last, end, sign);
        if (last == NULL) {
            last = end;
        }
        len = last - p;
        if (len) {
            pwd = njt_array_push(array);
            if (pwd == NULL) {
                return NJT_ERROR;
            }
            pwd->len = len;
            pwd->data = p ;
        }
        p = ++last;
    }
    return NJT_OK;
}
njt_str_t njt_del_headtail_space(njt_str_t src){

  njt_uint_t i,j;
  njt_str_t  dst;
  if(src.len == 0){
     return src;
  }
  i=0;
  for(; i < src.len; i++) {
          if(src.data[i] != '\0' && src.data[i] != '\n' && src.data[i] != '\t' && src.data[i] != ' ' && src.data[i] != '\r'){
                break;
          }
  }
  if(i == src.len){
        njt_str_set(&dst,"");
        return dst;
  }
  dst.data = src.data + i;
  j = src.len - 1;
  for(; j > i; j--) {
          if(src.data[j] == '\0' || src.data[j] == '\n' || src.data[j] == '\t' || src.data[j] == ' ' || src.data[j] == '\r'){
                continue;
          }
          break;
  }
  dst.len = j-i+1;
  return dst;
}


njt_str_t  add_escape(njt_pool_t *pool, njt_str_t src) {
    size_t i;
    njt_str_t out;
    njt_uint_t need_convert = 0;
    njt_str_null(&out); 
    char *cur = (char *)src.data;
    for (i = 0; i < src.len && need_convert == 0; i++, cur++) {
        switch (*cur) {
            case '"':  
            case '\\': 
            // case '/':  need_convert = true; break;
            case '\b':  
            case '\f':  
            case '\n':  
            case '\r':  
            case '\t':  need_convert = 1; break;
        default:
            break;
        }
    }
    if (need_convert == 0) {
        return src;
    }

    out.data = (u_char *)njt_pcalloc(pool, 2*src.len);
    char *dst = (char *)out.data;
    out.len = src.len;
    cur = (char *)src.data;
    for (i = 0; i < src.len; i++, cur++) {
        switch (*cur) {
            case '"':  *dst++ = '\\'; *dst++ = '"'; out.len++; break;
            case '\\': *dst++ = '\\'; *dst++ = '\\'; out.len++; break;
            // case '/':  *dst++ = '\\'; *dst++ = '/'; out->len++; break;
            case '\b': *dst++ = '\\'; *dst++ = 'b'; out.len++; break;
            case '\f': *dst++ = '\\'; *dst++ = 'f'; out.len++; break;
            case '\n': *dst++ = '\\'; *dst++ = 'n'; out.len++; break;
            case '\r': *dst++ = '\\'; *dst++ = 'r'; out.len++; break;
            case '\t': *dst++ = '\\'; *dst++ = 't'; out.len++; break;
        default:
            *dst++ = *cur;
        }
    }

    return out;
}


 njt_str_t delete_escape(njt_pool_t *pool, njt_str_t src) {
    u_char *p;
    njt_str_t out;
    u_char* dst;
    p = src.data;
    out.len = 0;
    out.data = (u_char *)njt_pcalloc(pool,src.len+1);
    if(out.data == NULL) {
        return out;
    }
    out.len = src.len;
    dst = out.data;
    for(;p < src.data + src.len;) {
        if (*p == '\\') {
            switch (*++p) {
                case '"':  *dst++ = '"';  p++; break;
                case '\\': *dst++ = '\\'; p++; break;
                case '/':  *dst++ = '/';  p++; break;
                case 'b':  *dst++ = '\b'; p++; break;
                case 'f':  *dst++ = '\f'; p++; break;
                case 'n':  *dst++ = '\n'; p++; break;
                case 'r':  *dst++ = '\r'; p++; break;
                case 't':  *dst++ = '\t'; p++; break;
                default:
                break;
                // unreachable, should get err in jsmn parse string
                    // return_err(src, "invalid escaped character in string");
            }
        } else {
            *dst++ = *p++;
        }
    }
    out.len = dst - out.data;
    out.data[out.len] = 0;
    return out;
}
