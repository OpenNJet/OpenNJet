/* https://github.com/api7/lua-resty-radixtree
 *
 * Copyright 2019-2020 Shenzhen ZhiLiu Technology Co., Ltd.
 * https://www.apiseven.com
 *
 * See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The owner licenses this file to You under the Apache License, Version 2.0;
 * you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "easy_rax.h"


void *
radix_tree_new()
{
    return (void *)raxNew();
}

int
radix_tree_remove(void *t, unsigned char *buf, size_t len)
{
    if (t == NULL) {
        return -1;
    }

    if (buf == NULL) {
        return -2;
    }

    return raxRemove((rax *)t, (unsigned char *)buf, len, NULL);
}

int
radix_tree_destroy(void *t)
{
    if (t == NULL) {
        return 0;
    }

    raxFree(t);
    return 0;
}


int
radix_tree_insert(void *t, const unsigned char *buf, size_t len, int idx)
{
    void *data = (void *)idx;

    if (t == NULL) {
        return -1;
    }

    if (buf == NULL) {
        return -2;
    }

    return raxInsert((rax *)t, (unsigned char *)buf, len, data, NULL);
}


void *
radix_tree_find(void *t, const unsigned char *buf, size_t len)
{
    if (t == NULL) {
        return NULL;
    }

    if (buf == NULL) {
        return NULL;
    }

    void *res = raxFind((rax *)t, (unsigned char *)buf, len);
    if (res == raxNotFound) {
        return NULL;
    }

    return res;
}


void *
radix_tree_new_it(void *t)
{
    raxIterator *it = malloc(sizeof(raxIterator));
    if (it == NULL) {
        return NULL;
    }

    raxStart(it, (rax *)t);
    return (void *)it;
}


void *
radix_tree_search(void *t, void *it, const unsigned char *buf, size_t len)
{
    raxIterator *iter = (raxIterator *)it;
    if (it == NULL) {
        return NULL;
    }

    raxSeek(iter, "<=", (unsigned char *)buf, len);
    return (void *)iter;
}


int
radix_tree_next(void *it, const unsigned char *buf, size_t len)
{
    raxIterator    *iter = it;

    int res = raxNext(iter);
    if (!res) {
        return -1;
    }

    // fprintf(stderr, "it key len: %lu buf len: %lu, key: %.*s\n",
    //         iter->key_len, len, (int)iter->key_len, iter->key);

    if (iter->key_len > len ||
        memcmp(buf, iter->key, iter->key_len) != 0) {
        return -1;
    }

    return (int)iter->data;
}


int
radix_tree_prev(void *it, const unsigned char *buf, size_t len)
{
    raxIterator    *iter = it;
    int             res;

    while (1) {
        res = raxPrev(iter);
        if (!res) {
            return -1;
        }

        if (iter->key_len > len ||
            memcmp(buf, iter->key, iter->key_len) != 0) {
            continue;
        }

        break;
    }

    return (int)iter->data;
}


int
radix_tree_up(void *it, const unsigned char *buf, size_t len)
{
    raxIterator    *iter = it;
    int             res;

    while (1) {
        res = raxUp(iter);
        if (!res) {
            return -1;
        }

        if (iter->key_len > len ||
            memcmp(buf, iter->key, iter->key_len) != 0) {
            continue;
        }

        break;
    }

    return (int)iter->data;
}


int
radix_tree_stop(void *it)
{
    if (!it) {
        return 0;
    }

    raxStop(it);
    return 0;
}
