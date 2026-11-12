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
        event = RaspHostEventV1()
        event.version = 1
        event.struct_size = UInt32(MemoryLayout<RaspHostEventV1>.size)
        event.kind = 1
        event.lifecycle = 1
        event.generation = 1
        event.event_sequence = 1
        event.session_ref = UUID().uuid
        _ = owner?.apply(event)

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

        event.kind = 2
        event.lifecycle = 0
        event.purpose = 2
        event.secure_entry = HostOperationContext.secureEntry(selected)
        event.attempt = 1
        event.action_ref = UUID().uuid
        event.event_sequence += 1
        pending = owner?.apply(event).status == 0
        consumed = false
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
        event.kind = 3
        event.secure_entry = HostOperationContext.secureEntry(selected)
        event.event_sequence += 1
        guard owner.apply(event).status == 0 else { return }
        let result = owner.gate(generation: event.generation, sequence: event.event_sequence, attempt: event.attempt)
        consumed = result.context.state == 9
        guard result.context.status == 0, result.native.status == UInt32(kRaspLocalOk),
              result.native.action == UInt32(kRaspLocalAllow) else {
            label.text = "Demo denied/unavailable; receipts: \(receipts)"
            return
        }
        receipts += 1
        event.kind = 5
        event.purpose = 0
        event.secure_entry = 0
        event.completion = 1
        event.event_sequence += 1
        _ = owner.apply(event)
        pending = false
        label.text = "Local demo receipts: \(receipts)"
    }

    @objc private func retryDemo(_ sender: UIButton) {
        guard sender === retryButton, pending, consumed, event.attempt < 3, let owner = owner else { return }
        event.kind = 7
        event.purpose = 2
        event.secure_entry = HostOperationContext.secureEntry(selected)
        event.attempt += 1
        event.event_sequence += 1
        consumed = owner.apply(event).status != 0
    }

    @objc private func cancelDemo(_ sender: UIButton) {
        guard sender === cancelButton, pending else { return }
        event.kind = 6
        event.purpose = 0
        event.secure_entry = 0
        event.event_sequence += 1
        _ = owner?.apply(event)
        owner?.close()
        pending = false
    }

    func applicationWillResignActive(_ application: UIApplication) {
        pending = false
        owner?.close()
        owner = nil
        event = RaspHostEventV1()
    }
}

UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(ContextHost.self))
