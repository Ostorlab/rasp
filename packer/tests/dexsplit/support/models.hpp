// Model pieces and failure capture shared by the tests of the DEX writer.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <utility>

#include "common/ids.hpp"
#include "model/io.hpp"
#include "model/pools.hpp"
#include "model/types.hpp"

namespace dexsplit::support {

inline model::CallSite call_site(uint32_t share_key)
{
    model::CallSite site;
    site.bootstrap =
        model::MethodHandle{model::MethodHandleKind::InvokeStatic,
                            MethodId{"LBoot;", "bootstrap",
                                     "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                                     "Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"}};
    site.method_name = "run";
    site.method_type = "()V";
    site.share_key = share_key;
    return site;
}

template <class Action> model::Error write_failure(Action &&action)
{
    try {
        std::forward<Action>(action)();
    }
    catch (const model::detail::WriteFailure &failure) {
        return failure.error;
    }
    throw std::runtime_error("no WriteFailure was thrown");
}

} // namespace dexsplit::support
