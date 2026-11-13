import Foundation

/// Actual Foundation/Swift/C consumer, not a replacement UIKit SDK or a device result.
@main struct EntryUrlTests {
    static func main() {
        guard MemoryLayout<RaspEntryRuleV1>.size == 676, MemoryLayout<RaspEntryCheckV1>.size == 32,
              let rule = EntryPointValidation.rule(routeId: 1, delivery: 5, dispatchClass: 1,
                  scheme: "https", authority: "links.example.invalid", path: "/open/help",
                  operation: "append_demo_receipt", expectedPolicySha256: String(repeating: "a", count: 64)),
              let binding = EntryPointValidation.Binding(rules: [rule]),
              let benign = URL(string: "https://links.example.invalid/open/help") else { fatalError("source binding") }
        precondition(EntryPointValidation.classify(url: benign, delivery: 5, binding: binding).status == 0)
        precondition(EntryPointValidation.Binding(rules: [rule, rule]) == nil)
        for text in ["https://links.example.invalid/open/help?", "https://links.example.invalid/open/help#",
                     "https://links.example.invalid:443/open/help", "https://evil.test/open/help",
                     "https://links.example.invalid/open/%68elp", "https://links.example.invalid/open/help/"] {
            if let url = URL(string: text) {
                precondition(EntryPointValidation.classify(url: url, delivery: 5, binding: binding).status != 0)
            }
        }
        if let relative = URL(string: "/open/help", relativeTo: benign) {
            precondition(EntryPointValidation.classify(url: relative, delivery: 5, binding: binding).status != 0)
        }
        if let sensitive = EntryPointValidation.rule(routeId: 1, delivery: 5, dispatchClass: 4,
            scheme: "https", authority: "links.example.invalid", path: "/open/help",
            operation: "append_demo_receipt", expectedPolicySha256: String(repeating: "a", count: 64)),
           let sensitiveBinding = EntryPointValidation.Binding(rules: [sensitive]) {
            let check = EntryPointValidation.classify(url: benign, delivery: 5, binding: sensitiveBinding)
            precondition(check.status == 4 && check.route_id == 0)
        } else { fatalError("sensitive fixture") }
        print("PASS actual Foundation/Swift/C URL consumer; no device or UIKit lifecycle claim")
    }
}
