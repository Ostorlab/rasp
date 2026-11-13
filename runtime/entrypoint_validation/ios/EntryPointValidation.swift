import Foundation

/// Host-compiled source contract. A matching route never grants caller, user or server authority.
public enum EntryPointValidation {
    /// Immutable <=16-rule source binding; the whole table is validated by the actual C classifier.
    public struct Binding {
        fileprivate let rules: [RaspEntryRuleV1]
        public init?(rules: [RaspEntryRuleV1]) {
            guard !rules.isEmpty, rules.count <= 16 else { return nil }
            var check = RaspEntryCheckV1()
            let status = rules.withUnsafeBufferPointer { pointer in
                rasp_entry_classify_v1(pointer.baseAddress, UInt32(pointer.count), UInt32(MemoryLayout<RaspEntryRuleV1>.size),
                    4, 1, nil, 0, &check, UInt32(MemoryLayout<RaspEntryCheckV1>.size))
            }
            guard status == 1, check.version == 1, check.reason == 1 else { return nil }
            self.rules = rules
        }
        /// Compiled dispatch lookup, never a reusable authorization result.
        public func rule(_ routeId: UInt32) -> RaspEntryRuleV1? {
            return rules.first { $0.route_id == routeId }
        }
    }
    /// Construct bounded canonical storage from app literals; invalid grammar is rejected by Binding.
    public static func rule(routeId: UInt32, delivery: UInt32, dispatchClass: UInt32,
                            scheme: String, authority: String, path: String,
                            operation: String, expectedPolicySha256: String) -> RaspEntryRuleV1? {
        let schemeBytes = Array(scheme.utf8.prefix(33))
        let authorityBytes = Array(authority.utf8.prefix(254))
        let pathBytes = Array(path.utf8.prefix(257))
        let operationBytes = Array(operation.utf8.prefix(33))
        let hashBytes = Array(expectedPolicySha256.utf8.prefix(65))
        guard schemeBytes.count <= 32, authorityBytes.count <= 253, pathBytes.count <= 256,
              operationBytes.count <= 32, hashBytes.count == 64 else { return nil }
        var value = RaspEntryRuleV1()
        value.version = 1
        value.struct_size = UInt32(MemoryLayout<RaspEntryRuleV1>.size)
        value.route_id = routeId
        value.delivery = delivery
        value.method = 1
        value.dispatch_class = dispatchClass
        withUnsafeMutableBytes(of: &value.scheme) { $0.copyBytes(from: schemeBytes + [0]) }
        withUnsafeMutableBytes(of: &value.authority) { $0.copyBytes(from: authorityBytes + [0]) }
        withUnsafeMutableBytes(of: &value.path) { $0.copyBytes(from: pathBytes + [0]) }
        withUnsafeMutableBytes(of: &value.operation) { $0.copyBytes(from: operationBytes + [0]) }
        withUnsafeMutableBytes(of: &value.expected_policy_sha256) { $0.copyBytes(from: hashBytes + [0]) }
        return value
    }
    /// Validate the delivered representation only; no sourceApplication/domain/caller inference.
    public static func classify(url: URL, delivery: UInt32, binding: Binding) -> RaspEntryCheckV1 {
        var check = RaspEntryCheckV1()
        binding.rules.withUnsafeBufferPointer { pointer in
            _ = rasp_entry_classify_url_v1(pointer.baseAddress, UInt32(pointer.count), delivery, url as CFURL, &check)
        }
        if check.status == 0, let rule = binding.rule(check.route_id) {
            if rule.dispatch_class == 4 {
                check.status = 4; check.reason = 19; check.route_id = 0
            } else if rule.dispatch_class == 2 || rule.caller_profile != 0 {
                check.status = 3; check.reason = 11; check.route_id = 0
            } else {
                check.caller_state = 3
            }
        }
        return check
    }
}
