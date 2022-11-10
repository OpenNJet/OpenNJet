/*
 * Copyright 2005-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DTLS1_H
# define HEADER_DTLS1_H

#ifdef  __cplusplus
extern "C" {
#endif

# define DTLS1_VERSION                   0xFEFF
# define DTLS1_2_VERSION                 0xFEFD
# define DTLS_MIN_VERSION                DTLS1_VERSION
# define DTLS_MAX_VERSION                DTLS1_2_VERSION
# define DTLS1_VERSION_MAJOR             0xFE

# define DTLS1_BAD_VER                   0x0100

/* Special value for method supporting multiple versions */
# define DTLS_ANY_VERSION                0x1FFFF

/* lengths of messages */
/*
 * Actually the max cookie length in DTLS is 255. But we can't change this now
 * due to compatibility concerns.
 */
# define DTLS1_COOKIE_LENGTH                     256

/* DTLS 1.3 Unified Header
        0 1 2 3 4 5 6 7
        +-+-+-+-+-+-+-+-+
        |0|0|1|C|S|L|E E|
        +-+-+-+-+-+-+-+-+
        | Connection ID |   Legend:
        | (if any,      |
        /  length as    /   C   - Connection ID (CID) present
        |  negotiated)  |   S   - Sequence number length
        +-+-+-+-+-+-+-+-+   L   - Length present
        |  8 or 16 bit  |   E   - Epoch
        |Sequence Number|
        +-+-+-+-+-+-+-+-+
        | 16 bit Length |
        | (if present)  |
        +-+-+-+-+-+-+-+-+
*/
# define DTLS13_UNIFIED_HDR_FIXED_BITS_MASK      0xE0
# define DTLS13_UNIFIED_HDR_FIXED_BITS           0x20
# define DTLS13_UNIFIED_HDR_C_MASK               0x10
# define DTLS13_UNIFIED_HDR_S_MASK               0x08
# define DTLS13_UNIFIED_HDR_L_MASK               0x04
# define DTLS13_UNIFIED_HDR_E_MASK               0x03
# define DTLS13_UNIFIED_HDR_BITS_LEN             1

# define DTLS1_RT_HEADER_LENGTH                  13

# define DTLS1_HM_HEADER_LENGTH                  12

# define DTLS1_HM_BAD_FRAGMENT                   -2
# define DTLS1_HM_FRAGMENT_RETRY                 -3

# define DTLS1_CCS_HEADER_LENGTH                  1

# define DTLS1_AL_HEADER_LENGTH                   2

/* Timeout multipliers */
# define DTLS1_TMO_READ_COUNT                      2
# define DTLS1_TMO_WRITE_COUNT                     2

# define DTLS1_TMO_ALERT_COUNT                     12

#ifdef  __cplusplus
}
#endif
#endif
