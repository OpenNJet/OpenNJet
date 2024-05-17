/**
 *    ______      ___
 *   / ____/___  /   | _____________  __________
 *  / / __/ __ \/ /| |/ ___/ ___/ _ \/ ___/ ___/
 * / /_/ / /_/ / ___ / /__/ /__/  __(__  |__  )
 * \____/\____/_/  |_\___/\___/\___/____/____/
 *
 * The MIT License (MIT)
 * Copyright (c) 2009-2024 Gerardo Orellana <hello @ goaccess.io>
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

#ifndef GOACCESS_H_INCLUDED
#define GOACCESS_H_INCLUDED

#include "ui.h"

#define RAND_FN 7 + 1
#define NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX 1024

#define GOACCESS_STR_LEN_MAX 1024

#define NJT_ACCESS_DATA_DEFAULT_REPORT_HTML_PATH "/usr/local/njet/goaccess/report.html"

#define NJT_HELPER_ACCESS_DATA_LOGS_MAX 1024

//#define NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX 512

typedef struct njt_access_data_file_logformat_s {
    char file_name[GOACCESS_STR_LEN_MAX];
    char logformat[GOACCESS_STR_LEN_MAX];
} njt_access_data_conf_file_logformat_t;

typedef struct njt_access_data_logformat_convert_s {
    const char *var;
    const char *logformat;
} njt_access_data_logformat_convert_t;

extern njt_access_data_conf_file_logformat_t g_njt_access_data_conf_file_logformat[NJT_ACCESS_DATA_FILE_LOGFORMAT_ARRAY_MAX];

extern GSpinner *parsing_spinner;
extern int active_gdns;         /* kill dns pthread flag */

extern pthread_mutex_t g_njt_helper_access_data_logformat_mutex_lock;

void cleanup (int ret);

void read_client (void *ptr_data);

void *njet_helper_access_data_run (void *log_s);

Logs *njet_helper_access_data_init (int argc, char **argv);
//int njet_helper_access_data_init (int argc, char **argv);

void tail_loop_html (Logs *logs);

void dbg_log_open (const char *file);

void persist_data (void);

#endif
