/**
 * xmalloc.c -- *alloc functions with error handling
 *    ______      ___
 *   / ____/___  /   | _____________  __________
 *  / / __/ __ \/ /| |/ ___/ ___/ _ \/ ___/ ___/
 * / /_/ / /_/ / ___ / /__/ /__/  __(__  |__  )
 * \____/\____/_/  |_\___/\___/\___/____/____/
 *
 * The MIT License (MIT)
 * Copyright (c) 2009-2022 Gerardo Orellana <hello @ goaccess.io>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#if !defined __SUNPRO_C
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "xmalloc.h"
#include <njt_config.h>
#include <njt_core.h>
//#include <njt_http.h>

extern goaccess_shpool_ctx_t  goaccess_shpool_ctx;

/* Self-checking wrapper to malloc() */
void *
xmalloc (size_t size) {
  void *ptr;

  if ((ptr = malloc (size)) == NULL)
    FATAL ("Unable to allocate memory - failed.");

  return (ptr);
}

char *
xstrdup (const char *s) {
  char *ptr;
  size_t len;

  len = strlen (s) + 1;
  ptr = xmalloc (len);

  strncpy (ptr, s, len);
  return (ptr);
}

/* Self-checking wrapper to calloc() */
void *
xcalloc (size_t nmemb, size_t size) {
  void *ptr;

  if ((ptr = calloc (nmemb, size)) == NULL)
    FATAL ("Unable to calloc memory - failed.");

  return (ptr);
}

/* Self-checking wrapper to realloc() */
void *
xrealloc (void *oldptr, size_t size) {
  void *newptr;

  if ((newptr = realloc (oldptr, size)) == NULL)
    FATAL ("Unable to reallocate memory - failed");

  return (newptr);
}


void *njt_kcalloc (size_t nmemb, size_t size) {

    void *p = njt_slab_calloc_locked(goaccess_shpool_ctx.shpool,size*nmemb); 
    if(p == NULL) {
      goaccess_shpool_ctx.shpool_error = NJT_ERROR;
    }
    return p;
}
void *njt_kmalloc (size_t size){
    void *p = njt_slab_alloc_locked(goaccess_shpool_ctx.shpool,size); 
     if(p == NULL) {
      goaccess_shpool_ctx.shpool_error = NJT_ERROR;
    }
    return  p;
}
void *njt_krealloc (void *ptr, size_t size,size_t old_size){
    char *p = njt_slab_calloc_locked(goaccess_shpool_ctx.shpool,size); 
    if(p != NULL && ptr != NULL) {
        if(old_size > size) {
            njt_memcpy(p,ptr,size);
        } else {
             njt_memcpy(p,ptr,old_size);
        }
        njt_slab_free_locked(goaccess_shpool_ctx.shpool,ptr);
    }
    if(p == NULL) {
      goaccess_shpool_ctx.shpool_error = NJT_ERROR;
    }
    return p;
}
void  njt_kfree (void *ptr){
    if(ptr != NULL) {
     njt_slab_free_locked(goaccess_shpool_ctx.shpool,ptr);
    }
}
char * njt_kstrdup (const char *s){

     char *p = njt_slab_calloc_locked(goaccess_shpool_ctx.shpool,njt_strlen(s)+1);
     if(p != NULL) {
        njt_memcpy(p,s,njt_strlen(s));
     } else {
        goaccess_shpool_ctx.shpool_error = NJT_ERROR;
     } 
     return p;
}


//========================
char *njt_xstrdup (const char *s) {
  char *ptr;
  size_t len;

  len = njt_strlen (s) + 1;
  ptr = njt_pcalloc (goaccess_shpool_ctx.goaccess_pool,len);
  if(ptr == NULL) {
    return ptr;
  }

  strncpy (ptr, s, len);
  return (ptr);
}
void *njt_xcalloc (size_t nmemb, size_t size) {
   void *ptr;

  ptr = njt_pcalloc (goaccess_shpool_ctx.goaccess_pool,nmemb *size);

  return (ptr);
}
void *njt_xmalloc (size_t size) {
   void *ptr;

  ptr = njt_pcalloc (goaccess_shpool_ctx.goaccess_pool,size);

  return (ptr);
}

void  njt_xfree (void *ptr){
    if(goaccess_shpool_ctx.goaccess_pool != NULL) {
      return;
    }
    free(ptr);
}
