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

#ifndef SRC_OPERATORS_PM_H_
#define SRC_OPERATORS_PM_H_

#include <string>
#include <list>
#include <memory>
#include <utility>

#include "src/operators/operator.h"
#include "src/utils/regex.h"


namespace modsecurity {

using Utils::Regex;

namespace operators {


class Pm : public Operator {
 public:
    /** @ingroup ModSecurity_Operator */
    explicit Pm(std::unique_ptr<RunTimeString> param)
        : Operator("Pm", std::move(param)) {
    }
    explicit Pm(std::string n, std::unique_ptr<RunTimeString> param)
        : Operator(n, std::move(param)) {
    }
    ~Pm();
    bool evaluate(Transaction *transaction, Rule *rule,
        const std::string &str,
        std::shared_ptr<RuleMessage> ruleMessage) override;

    bool init(const std::string &file, std::string *error) override;

 protected:
    Regex *rx;
};


}  // namespace operators
}  // namespace modsecurity


#endif  // SRC_OPERATORS_PM_H_
