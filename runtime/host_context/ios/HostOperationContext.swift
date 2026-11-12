import Foundation
import UIKit

/// Host-owned single-flow wrapper. Import host_events.h in the host's bridging header.
/// No text, screen, keyboard contents, delegates or framework-private C++ values cross it.
public final class HostOperationContext {
    private var owner = RaspHostContextV1()

    public init?(operation: String, expectedPolicySha256: String, requireSecureInput: Bool = false) {
        guard Thread.isMainThread else { return nil }
        let operationBytes = Array(operation.utf8.prefix(33))
        let hashBytes = Array(expectedPolicySha256.utf8.prefix(65))
        guard !operationBytes.isEmpty, operationBytes.count <= 32, hashBytes.count == 64 else { return nil }
        var binding = RaspHostBindingV1()
        binding.version = 1
        binding.struct_size = UInt32(MemoryLayout<RaspHostBindingV1>.size)
        binding.require_secure_input = requireSecureInput ? 1 : 0
        withUnsafeMutableBytes(of: &binding.operation) { $0.copyBytes(from: operationBytes + [0]) }
        withUnsafeMutableBytes(of: &binding.expected_policy_sha256) { $0.copyBytes(from: hashBytes + [0]) }
        guard rasp_host_context_init_v1(&owner, &binding, binding.struct_size) == 0 else { return nil }
    }

    /// Apply one borrowed finite C value; the returned view is an independent copy.
    public func apply(_ input: RaspHostEventV1) -> RaspHostContextViewV1 {
        var view = RaspHostContextViewV1()
        guard Thread.isMainThread else { view.status = 4; return view }
        var event = input
        _ = rasp_host_context_apply_v1(&owner, &event, UInt32(MemoryLayout<RaspHostEventV1>.size),
                                      &view, UInt32(MemoryLayout<RaspHostContextViewV1>.size))
        return view
    }

    /// Gate immediately before the host effect, on main, without await/callback/run-loop pumping.
    public func gate(generation: UInt64, sequence: UInt64, attempt: UInt32)
        -> (context: RaspHostContextViewV1, native: RaspLocalGateResultV1) {
        var view = RaspHostContextViewV1()
        var native = RaspLocalGateResultV1()
        native.status = UInt32(kRaspLocalNotReady)
        guard Thread.isMainThread else { view.status = 4; return (view, native) }
        _ = rasp_host_context_gate_v1(&owner, generation, sequence, attempt, &view,
            UInt32(MemoryLayout<RaspHostContextViewV1>.size), &native, UInt32(MemoryLayout<RaspLocalGateResultV1>.size))
        return (view, native)
    }

    /// Explicit main-thread logical disposal; release host callbacks before releasing this object.
    @discardableResult public func close() -> Int32 {
        guard Thread.isMainThread else { return 4 }
        return rasp_host_context_dispose_v1(&owner)
    }

    /// Configuration only. Custom controls/frameworks are unsupported; no field value is read.
    public static func secureEntry(_ selected: AnyObject?) -> UInt32 {
        guard Thread.isMainThread, let selected = selected else { return 0 }
        guard type(of: selected) == UITextField.self, let field = selected as? UITextField else { return 3 }
        return field.isSecureTextEntry ? 1 : 2
    }
}
