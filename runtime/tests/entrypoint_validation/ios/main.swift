import UIKit
import Foundation

/// Real selected-window host controller. Only a route enum/tick/generation may be pending.
final class EntryController: NSObject {
    private let binding: EntryPointValidation.Binding?
    private var pending: UInt32 = 0
    private var tick: Int64 = 0
    private var lastTick: Int64 = 0
    private var generation: Int64 = 0
    private var active = false
    private var busy = false
    private var exhausted = false
    private var receipts: UInt32 = 0
    private var confirmation = false
    private var context: HostOperationContext?
    let view = UIViewController()
    private let label = UILabel(frame: CGRect(x: 20, y: 80, width: 350, height: 90))
    private let button = UIButton(type: .system)
    private static let operation = "append_demo_receipt"
    private static let hash = "093f2b8093e5c12d1d1b8f14f1fa945b87a4a03d15d891b55af861da06d4124e"

    override init() {
        var rules: [RaspEntryRuleV1] = []
        for (route, delivery, effect, scheme, path) in [
            (UInt32(1), UInt32(5), UInt32(1), "https", "/open/help"),
            (2, 5, 3, "https", "/open/confirm"), (3, 5, 4, "https", "/commit"),
            (4, 4, 1, "app.raspdemo", "/open/help")] {
            if let rule = EntryPointValidation.rule(routeId: route, delivery: delivery, dispatchClass: effect,
                scheme: scheme, authority: "links.example.invalid", path: path,
                operation: Self.operation, expectedPolicySha256: Self.hash) { rules.append(rule) }
        }
        binding = rules.count == 4 ? EntryPointValidation.Binding(rules: rules) : nil
        super.init()
        view.view.backgroundColor = .white
        view.view.addSubview(label)
        button.frame = CGRect(x: 20, y: 200, width: 350, height: 70)
        button.setTitle("Confirm a new local demo action", for: .normal)
        button.addTarget(self, action: #selector(confirmDemo), for: .touchUpInside)
        view.view.addSubview(button)
        render()
    }
    private func render() { label.numberOfLines = 3; label.text = "Entry demo receipts: \(receipts)\nConfirmation entry: \(confirmation)" }
    /// Only concrete delegate callbacks call this, with their selected scene's current lifecycle.
    @discardableResult func receive(_ url: URL, delivery: UInt32) -> Bool {
        guard Thread.isMainThread, !busy else { return false }
        pending = 0
        guard !exhausted, generation < Int64.max, let binding = binding else { exhausted = true; return false }
        generation += 1
        let check = EntryPointValidation.classify(url: url, delivery: delivery, binding: binding)
        guard check.status == 0, let rule = binding.rule(check.route_id), rule.dispatch_class == 1 || rule.dispatch_class == 3 else { return false }
        if active { return dispatch(rule) }
        var now: Int64 = 0
        guard rasp_host_clock_v1(&now) == 1, now >= 0, now >= lastTick else { return false }
        tick = now; lastTick = now; pending = rule.route_id
        return true
    }
    /// A rejected mixed or multiple delivery invalidates the preceding public pending candidate.
    func rejectDelivery() { guard Thread.isMainThread, !busy else { return }; pending = 0 }
    func becomeActive() {
        guard Thread.isMainThread else { return }
        active = true
        let route = pending, expectedGeneration = generation
        pending = 0
        guard !exhausted, route != 0, let binding = binding else { return }
        var now: Int64 = 0
        guard rasp_host_clock_v1(&now) == 1, now >= 0, now >= lastTick, now >= tick,
              now - tick <= 30_000_000_000, generation == expectedGeneration,
              let rule = binding.rule(route), rule.dispatch_class == 1 || rule.dispatch_class == 3 else { return }
        lastTick = now
        _ = dispatch(rule)
    }
    func resignActive() {
        guard Thread.isMainThread else { return }
        active = false; pending = 0; confirmation = false
        if generation == Int64.max { exhausted = true } else { generation += 1 }
        context?.close(); context = nil
    }
    /// No callback/run-loop/await occurs between the real final ALLOW and the closed effect switch.
    private func dispatch(_ rule: RaspEntryRuleV1) -> Bool {
        guard Thread.isMainThread, active, !busy, !exhausted, rule.dispatch_class == 1 || rule.dispatch_class == 3 else { return false }
        busy = true
        defer { busy = false }
        var request = RaspLocalGateRequestV1()
        request.abi_version = 1; request.struct_size = UInt32(MemoryLayout<RaspLocalGateRequestV1>.size)
        request.operation = rule.operation; request.expected_policy_sha256 = rule.expected_policy_sha256
        var native = RaspLocalGateResultV1()
        guard rasp_local_policy_gate_v1(&request, request.struct_size, &native, UInt32(MemoryLayout<RaspLocalGateResultV1>.size)) == kRaspLocalOk,
              native.abi_version == 1, native.struct_size == UInt32(MemoryLayout<RaspLocalGateResultV1>.size),
              native.status == UInt32(kRaspLocalOk), native.action == UInt32(kRaspLocalAllow) else { return false }
        switch rule.route_id {
        case 1, 4: guard receipts < UInt32.max else { return false }; receipts += 1
        case 2: confirmation = true
        default: return false
        }
        render(); return true
    }
    /// New deliberate local button action. It never consumes URL data or represents remote authentication.
    @objc private func confirmDemo() {
        guard Thread.isMainThread, active, !busy, confirmation, receipts < UInt32.max else { return }
        busy = true
        confirmation = false
        defer { context?.close(); context = nil; busy = false; render() }
        context = HostOperationContext(operation: Self.operation, expectedPolicySha256: Self.hash)
        guard let context = context else { return }
        var event = RaspHostEventV1()
        event.version = 1; event.struct_size = UInt32(MemoryLayout<RaspHostEventV1>.size)
        event.generation = 1; event.event_sequence = 1; event.kind = 1; event.lifecycle = 1
        event.session_ref = UUID().uuid
        guard context.apply(event).status == 0 else { return }
        event.kind = 2; event.lifecycle = 0; event.purpose = 3; event.secure_entry = 4; event.attempt = 1
        event.action_ref = UUID().uuid; event.event_sequence = 2
        guard context.apply(event).status == 0 else { return }
        let result = context.gate(generation: 1, sequence: 2, attempt: 1)
        guard result.context.status == 0, result.native.status == UInt32(kRaspLocalOk), result.native.action == UInt32(kRaspLocalAllow) else { return }
        receipts += 1; confirmation = false
        event.kind = 5; event.purpose = 0; event.secure_entry = 0; event.completion = 1; event.event_sequence = 3
        if context.apply(event).status != 0 { confirmation = false }
    }
}

/// Legacy iOS12 callbacks; scene hosts select their own controller below.
final class EntryAppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    private var controller: EntryController?
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        if #available(iOS 13, *) {} else {
            let controller = EntryController(); self.controller = controller
            window = UIWindow(frame: UIScreen.main.bounds); window?.rootViewController = controller.view; window?.makeKeyAndVisible()
        }
        return true
    }
    func applicationDidBecomeActive(_ application: UIApplication) {
        if application.applicationState == .active { controller?.becomeActive() } else { controller?.resignActive() }
    }
    func applicationWillResignActive(_ application: UIApplication) { controller?.resignActive() }
    func applicationDidEnterBackground(_ application: UIApplication) { controller?.resignActive() }
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        if app.applicationState != .active { controller?.resignActive() }
        return controller?.receive(url, delivery: 4) ?? false
    }
    func application(_ application: UIApplication, continue activity: NSUserActivity, restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void) -> Bool {
        guard activity.activityType == NSUserActivityTypeBrowsingWeb, let url = activity.webpageURL else { controller?.rejectDelivery(); return false }
        if application.applicationState != .active { controller?.resignActive() }
        return controller?.receive(url, delivery: 5) ?? false
    }
    @available(iOS 13.0, *)
    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let config = UISceneConfiguration(name: "Entry", sessionRole: session.role)
        config.sceneClass = UIWindowScene.self
        config.delegateClass = EntrySceneDelegate.self
        return config
    }
}

/// One explicit scene; an active second scene never substitutes for this scene's lifecycle.
@available(iOS 13.0, *)
final class EntrySceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var controller: EntryController?
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let selected = scene as? UIWindowScene else { return }
        let controller = EntryController(); self.controller = controller
        window = UIWindow(windowScene: selected); window?.rootViewController = controller.view; window?.makeKeyAndVisible()
        guard options.urlContexts.count + options.userActivities.count == 1 else { controller.rejectDelivery(); return }
        if options.urlContexts.count == 1 { for context in options.urlContexts { _ = controller.receive(context.url, delivery: 4) } }
        else { for activity in options.userActivities { receive(activity) } }
    }
    func sceneDidBecomeActive(_ scene: UIScene) {
        guard window?.windowScene === scene, scene.activationState == .foregroundActive else { controller?.resignActive(); return }
        controller?.becomeActive()
    }
    func sceneWillResignActive(_ scene: UIScene) { controller?.resignActive() }
    func sceneDidEnterBackground(_ scene: UIScene) { controller?.resignActive() }
    func sceneDidDisconnect(_ scene: UIScene) { controller?.resignActive(); window = nil; controller = nil }
    func scene(_ scene: UIScene, openURLContexts contexts: Set<UIOpenURLContext>) {
        guard window?.windowScene === scene else { return }
        if scene.activationState != .foregroundActive { controller?.resignActive() }
        guard contexts.count == 1 else { controller?.rejectDelivery(); return }
        for context in contexts { _ = controller?.receive(context.url, delivery: 4) }
    }
    func scene(_ scene: UIScene, continue activity: NSUserActivity) {
        guard window?.windowScene === scene else { return }
        if scene.activationState != .foregroundActive { controller?.resignActive() }
        receive(activity)
    }
    private func receive(_ activity: NSUserActivity) {
        guard activity.activityType == NSUserActivityTypeBrowsingWeb, let url = activity.webpageURL else { controller?.rejectDelivery(); return }
        _ = controller?.receive(url, delivery: 5)
    }
}

UIApplicationMain(CommandLine.argc, CommandLine.unsafeArgv, nil, NSStringFromClass(EntryAppDelegate.self))
