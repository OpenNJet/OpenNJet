/**
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

#ifndef XMALLOC_H_INCLUDED
#define XMALLOC_H_INCLUDED
//include <njt_core.h>


typedef struct goaccess_shpool_ctx_s {
    void         *shpool;
    int     shpool_error;
    volatile unsigned long              *rwlock;
    void             *goaccess_pool;
} goaccess_shpool_ctx_t;

char *xstrdup (const char *s);
void *xcalloc (size_t nmemb, size_t size);
void *xmalloc (size_t size);
void *xrealloc (void *oldptr, size_t size);


void *njt_kcalloc (size_t nmemb, size_t size);
void *njt_kmalloc (size_t size);
void *njt_krealloc (void *ptr, size_t size,size_t old_size);
void  njt_kfree (void *ptr);
char * njt_kstrdup (const char *s);



char *njt_xstrdup (const char *s);
void *njt_xcalloc (size_t nmemb, size_t size);
void *njt_xmalloc (size_t size);
void  njt_xfree (void *ptr);

void  append_query_string (void  *pool,char **req, const char *qstr);


#endif
