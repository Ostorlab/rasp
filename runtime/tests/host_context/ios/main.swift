import UIKit
import Foundation

/// Unsigned UIKit fixture; uses only empty/demo input and an actual local receipt counter.
final class ContextHost: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private var owner: HostOperationContext?
    private var event = RaspHostEventV1()
    private var selected = UITextField()
    private var label = UILabel()
    private var appendButton = UIButton(type: .system)
    private var retryButton = UIButton(type: .system)
    private var cancelButton = UIButton(type: .system)
    private var receipts: UInt32 = 0
    private var consumed = false
    private var pending = false

    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        window = UIWindow(frame: UIScreen.main.bounds)
        window?.makeKeyAndVisible()
        return true
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        owner?.close()
        owner = HostOperationContext(operation: "append_demo_receipt",
            expectedPolicySha256: "093f2b8093e5c12d1d1b8f14f1fa945b87a4a03d15d891b55af861da06d4124e", requireSecureInput: true)
        pending = false
        consumed = false

        let controller = UIViewController()
        controller.view.backgroundColor = .white
        label = UILabel(frame: CGRect(x: 20, y: 60, width: 340, height: 60))
        label.text = "Local demo receipts: \(receipts)"
        selected = UITextField(frame: CGRect(x: 20, y: 130, width: 340, height: 50))
        selected.placeholder = "Demo input; leave empty"
        selected.isSecureTextEntry = true
        selected.textContentType = .oneTimeCode
        controller.view.addSubview(label)
        controller.view.addSubview(selected)
        appendButton = button("Append one demo receipt", y: 200, action: #selector(appendDemo(_:)), in: controller)
        retryButton = button("Retry a denied attempt", y: 260, action: #selector(retryDemo(_:)), in: controller)
        cancelButton = button("Cancel demo flow", y: 320, action: #selector(cancelDemo(_:)), in: controller)
        window?.rootViewController = controller

        guard let owner = owner else { unavailable(); return }
        var next = RaspHostEventV1()
        next.version = 1
        next.struct_size = UInt32(MemoryLayout<RaspHostEventV1>.size)
        next.kind = 1
        next.lifecycle = 1
        next.generation = 1
        next.event_sequence = 1
        next.session_ref = UUID().uuid
        guard owner.apply(next).status == 0 else { unavailable(); return }
        event = next
        next.kind = 2
        next.lifecycle = 0
        next.purpose = 2
        next.secure_entry = HostOperationContext.secureEntry(selected)
        next.attempt = 1
        next.action_ref = UUID().uuid
        next.event_sequence += 1
        guard owner.apply(next).status == 0 else { unavailable(); return }
        event = next
        pending = true
        label.text = "Demo ready; receipts: \(receipts)"
    }

    private func unavailable() {
        pending = false
        consumed = false
        owner?.close()
        owner = nil
        label.text = "Demo flow unavailable; receipts: \(receipts)"
    }

    private func button(_ title: String, y: CGFloat, action: Selector, in controller: UIViewController) -> UIButton {
        let value = UIButton(type: .system)
        value.frame = CGRect(x: 20, y: y, width: 340, height: 50)
        value.setTitle(title, for: .normal)
        value.addTarget(self, action: action, for: .touchUpInside)
        controller.view.addSubview(value)
        return value
    }

    @objc private func appendDemo(_ sender: UIButton) {
        guard sender === appendButton, pending, !consumed, let owner = owner else { return }
        guard event.event_sequence < UInt64(Int64.max) else { unavailable(); return }
        var next = event
        next.kind = 3
        next.secure_entry = HostOperationContext.secureEntry(selected)
        next.event_sequence += 1
        guard owner.apply(next).status == 0 else { unavailable(); return }
        event = next
        let result = owner.gate(generation: event.generation, sequence: event.event_sequence, attempt: event.attempt)
        consumed = result.context.state == 9
        guard consumed else { unavailable(); return }
        guard result.context.status == 0, result.native.status == UInt32(kRaspLocalOk),
              result.native.action == UInt32(kRaspLocalAllow) else {
            guard event.attempt < 3 else { unavailable(); return }
            label.text = "Demo denied/unavailable; receipts: \(receipts)"
            return
        }
        receipts += 1
        guard event.event_sequence < UInt64(Int64.max) else { unavailable(); return }
        next = event
        next.kind = 5
        next.purpose = 0
        next.secure_entry = 0
        next.completion = 1
        next.event_sequence += 1
        guard owner.apply(next).status == 0 else { unavailable(); return }
        event = next
        pending = false
        consumed = false
        owner.close()
        self.owner = nil
        label.text = "Local demo receipts: \(receipts)"
    }

    @objc private func retryDemo(_ sender: UIButton) {
        guard sender === retryButton, pending, consumed, let owner = owner else { return }
        guard event.attempt < 3, event.event_sequence < UInt64(Int64.max) else { unavailable(); return }
        var next = event
        next.kind = 7
        next.purpose = 2
        next.secure_entry = HostOperationContext.secureEntry(selected)
        next.attempt += 1
        next.event_sequence += 1
        guard owner.apply(next).status == 0 else { unavailable(); return }
        event = next
        consumed = false
        label.text = "Demo retry ready; receipts: \(receipts)"
    }

    @objc private func cancelDemo(_ sender: UIButton) {
        guard sender === cancelButton, pending, let owner = owner else { return }
        guard event.event_sequence < UInt64(Int64.max) else { unavailable(); return }
        var next = event
        next.kind = 6
        next.purpose = 0
        next.secure_entry = 0
        next.completion = 0
        next.event_sequence += 1
        guard owner.apply(next).status == 0 else { unavailable(); return }
        event = next
        owner.close()
        self.owner = nil
        pending = false
        consumed = false
        label.text = "Demo canceled; receipts: \(receipts)"
    }

    func applicationWillResignActive(_ application: UIApplication) {
        consumed = false
        pending = false
        owner?.close()
        owner = nil
        event = RaspHostEventV1()
    }
}

UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(ContextHost.self))
