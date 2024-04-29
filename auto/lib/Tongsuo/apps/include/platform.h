/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_APPS_PLATFORM_H
# define OSSL_APPS_PLATFORM_H

# include <openssl/e_os2.h>

# ifdef _WIN32
/*
 * Win32-specific argv initialization that splits OS-supplied UNICODE
 * command line string to array of UTF8-encoded strings.
 */
void win32_utf8argv(int *argc, char **argv[]);
# endif

#endif
