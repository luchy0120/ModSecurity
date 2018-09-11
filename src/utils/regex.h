/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
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

#include <ch.h>
#include <fstream>
#include <string>
#include <list>
#include <vector>
#ifndef SRC_UTILS_REGEX_H_
#define SRC_UTILS_REGEX_H_


namespace modsecurity {
namespace Utils {


class SMatch {
 public:
    SMatch() : size_(0),
        m_offset(0),
        m_length(0),
        match("") { }
    size_t size() const { return size_; }
    std::string str() const { return match; }

    int size_;
    int m_offset;
    int m_length;
    std::string match;
};


class Regex {
 public:
    explicit Regex(const std::string& pattern_);
    explicit Regex(std::vector<std::string>& patterns);
    ~Regex();
    ch_database_t *database = NULL;

    std::list<SMatch> searchAll(const std::string& s);
};


int regex_search(const std::string& s, SMatch *m,
    const Regex& regex);

int regex_search(const std::string& s, const Regex& r);

int regex_search(const std::string& s, std::string& match,
    const Regex& r);

}  // namespace Utils
}  // namespace modsecurity

#endif  // SRC_UTILS_REGEX_H_
