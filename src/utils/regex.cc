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

#include "src/utils/regex.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <list>

#include <fstream>
#include <iostream>

#include "src/utils/geo_lookup.h"

#include <ch.h>

namespace modsecurity {
namespace Utils {

Regex::Regex(std::vector<std::string>& patterns) {
    std::vector<const char*> pats;
    std::vector<unsigned> ids;
  
    unsigned id = 0;
    for (auto& p : patterns) {
        pats.push_back(p.c_str());
        ids.push_back(id++);
    }

    ch_compile_error_t *compile_err = NULL;
    ch_compile_multi(&pats[0], NULL, &ids[0], patterns.size(), CH_MODE_NOGROUPS, NULL, &database, &compile_err);
}

Regex::Regex(const std::string& pattern) {
    std::string pat(pattern);
    ch_compile_error_t *compile_err = NULL;
      
    if (pat.empty()) {
        pat.assign(".*");
    }
       
    ch_compile(pat.c_str(), CH_FLAG_DOTALL|CH_FLAG_MULTILINE, CH_MODE_GROUPS, NULL, &database, &compile_err);
}
	
Regex::~Regex() {
    if (database != NULL) {
        ch_free_database(database);
        database = NULL;
    }
}


struct MatchesContext{
    const std::string *s;
    std::list<SMatch> *retList;
};

static int record_matches(unsigned int id, unsigned long long from,
		          unsigned long long to, unsigned int flags, unsigned int size, const ch_capture_t *captured, void *ctx) {
    struct MatchesContext *hyctx = (struct MatchesContext *)ctx;
    for (unsigned int i = 0; i < size; ++i) {
         if (captured[i].flags == CH_CAPTURE_FLAG_ACTIVE) {
             SMatch match;
             size_t start = from;
             size_t end = to;
             size_t len = end - start;
             match.match = std::string(*hyctx->s, start, len);
             match.m_offset = start;
             match.m_length = len;
             hyctx->retList->push_front(match);
	     if (len == 0) {
		 return CH_CALLBACK_TERMINATE;
	     } 
	 }
    }

    return CH_CALLBACK_CONTINUE;
}

std::list<SMatch> Regex::searchAll(const std::string& s) {
    std::list<SMatch> retList;
    ch_scratch_t *scratch = NULL;
    if (ch_alloc_scratch(database, &scratch) != CH_SUCCESS) {
        return retList;
    }
    struct MatchesContext ctx = {
        .s = &s,
	.retList = &retList
    };

    ch_scan(database, s.c_str(), s.size(), 0, scratch, record_matches, NULL, &ctx);
    ch_free_scratch(scratch);
    return retList;
}

struct MatchContext {
    SMatch *match;
    const std::string *s;
    int ret;
};


static int record_a_match(unsigned int id, unsigned long long from,
		          unsigned long long to, unsigned int flags, unsigned int size, const ch_capture_t *captured, void *ctx) {
    struct MatchContext *hyctx = (struct MatchContext *)ctx;
    hyctx->match->match = std::string(*hyctx->s, (size_t)from, (size_t)to-from);
    hyctx->match->size_ = 1;
    hyctx->ret = 1;
    return CH_CALLBACK_TERMINATE;
}

int regex_search(const std::string& s, SMatch *match,
    const Regex& regex) {
    ch_scratch_t *scratch = NULL;
    if (ch_alloc_scratch(regex.database, &scratch) != CH_SUCCESS) {
        return 0;
    }

    struct MatchContext ctx = {
        .match = match,
        .s = &s,
        .ret = 0 
    };

    ch_scan(regex.database, s.c_str(), s.size(), 0, scratch, record_a_match, NULL, &ctx);
    ch_free_scratch(scratch);
    return ctx.ret;
}


struct SimpleMatchContext {
    const std::string *s;
    std::string match;
    int to;
};

static int record_simple_match(unsigned int id, unsigned long long from,
                               unsigned long long to, unsigned int flags, unsigned int size, const ch_capture_t *captured, void *ctx) {
    struct SimpleMatchContext *hyctx = (struct SimpleMatchContext *)ctx;
    hyctx->to = (int)to;
    hyctx->match.assign(std::string(*hyctx->s, (size_t)from, (size_t)to-from));
    return CH_CALLBACK_TERMINATE;
}

int regex_search(const std::string &s, std::string &match,
    const Regex& regex) {
    ch_scratch_t *scratch = NULL;
    if (ch_alloc_scratch(regex.database, &scratch) != CH_SUCCESS) {
        return 0;
    }

    struct SimpleMatchContext ctx = {
        .s = &s,
        .match = "",
	.to = 0 
    };

    ch_scan(regex.database, s.c_str(), s.size(), 0, scratch, record_simple_match, NULL, &ctx);
    match = ctx.match;
    ch_free_scratch(scratch);
    return ctx.to;
}

static int found_match(unsigned int id, unsigned long long from,
		       unsigned long long to, unsigned int flags, unsigned int size, const ch_capture_t *captured, void *ctx) {
    int *ret = (int *)ctx;
    *ret = 1;
    return CH_CALLBACK_TERMINATE;
}


int regex_search(const std::string& s, const Regex& regex) {
    ch_scratch_t *scratch = NULL;
    if (ch_alloc_scratch(regex.database, &scratch) != CH_SUCCESS) {
        return 0;
    }
    int ret = 0;
    ch_scan(regex.database, s.c_str(), s.size(), 0, scratch, found_match, NULL, &ret);
    ch_free_scratch(scratch);
    return ret;

}

}  // namespace Utils
}  // namespace modsecurity
