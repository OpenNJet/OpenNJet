/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <string>

#include "modsecurity/actions/action.h"
#include "src/actions/transformations/transformation.h"

#ifndef SRC_UTILS_MD5_H_
#define SRC_UTILS_MD5_H_

#include <cstring>
#include <iostream>

namespace modsecurity {
namespace Utils {

class Md5 {
 public:
    Md5() { }

    static std::string hexdigest(const std::string& input);
    static std::string digest(const std::string& input);
};

}  // namespace Utils
}  // namespace modsecurity

#endif  // SRC_UTILS_MD5_H_