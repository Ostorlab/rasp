#if canImport(UIKit)
import Foundation
import UIKit
import CryptoKit

/** Objective-C visible facade used by Flutter and private framework bindings. */
@objc(RaspNativeClient) public final class RaspNativeClient: NSObject {
    private var core: IOSCore?
    private var startupError: Error?
    @objc public var eventHandler: (([String: Any]) -> Void)?
    public override init() {
        super.init()
        do { core = try IOSCore(event: { [weak self] event in DispatchQueue.main.async { self?.eventHandler?(event) } }) }
        catch { startupError = error }
    }
    @objc public func execute(_ method: String, arguments: [String: Any], completion: @escaping (Any?, NSError?) -> Void) {
        guard let core = core else { completion(nil, (startupError ?? RaspError.invalid("initialization failed")) as NSError); return }
        Task {
            do { let value = try await core.execute(method, arguments); DispatchQueue.main.async { completion(value, nil) } }
            catch { DispatchQueue.main.async { completion(nil, error as NSError) } }
        }
    }
}

private actor IOSCore {
    private let directory: URL
    private let install: String
    private let store: KeychainStore
    private let attest: AppAttestClient
    private let event: ([String: Any]) -> Void
    private var bootstrap: [String: Any] = [:]
    private var config: [String: Any] = [:]
    private var started = false
    private var degraded = false
    private var session: SessionProof?
    private var timer: Task<Void, Never>?
    private var reactions: [UUID: Task<Void, Never>] = [:]
    private var lastThreats = Set<String>()
    private var history: [[String: Any]] = []
    private var revision: Int64 = 0
    private var expiry = Int64.max
    private var generation = 0
    private var sensitive = false
    private var authorizing = false

    init(event: @escaping ([String: Any]) -> Void) throws {
        var root = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("rasp", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        var flags = URLResourceValues(); flags.isExcludedFromBackup = true
        try root.setResourceValues(flags)
        directory = root
        let identity = root.appendingPathComponent("install-id")
        if let value = try? String(contentsOf: identity, encoding: .utf8), !value.isEmpty { install = value }
        else { let value = UUID().uuidString; try Data(value.utf8).write(to: identity, options: [.atomic, .completeFileProtection]); install = value }
        store = KeychainStore(directory: root.appendingPathComponent("store"), install: install)
        attest = AppAttestClient(directory: root)
        self.event = event
        if let data = try? Data(contentsOf: root.appendingPathComponent("events.json")), let saved = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] { history = saved }
    }

    private func required(_ args: [String: Any], _ name: String) throws -> String {
        guard let value = args[name] as? String, !value.isEmpty else { throw RaspError.invalid("\(name) required") }; return value
    }
    private func trusted() throws {
        guard started, !degraded, nowSeconds < expiry else { throw RaspError.invalid("protection not started, degraded or policy expired") }
    }
    private var nowSeconds: Int64 { Int64(Date().timeIntervalSince1970) }
    private var nowMillis: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    private func pins(_ value: [String: Any]) -> [String: [String]] { value["pins"] as? [String: [String]] ?? [:] }
    private var verifier: PolicyVerifier {
        PolicyVerifier(keys: bootstrap["policyKeys"] as? [String: String] ?? [:], tenant: bootstrap["tenantId"] as? String ?? "", app: Bundle.main.bundleIdentifier ?? "")
    }
    private func validate(_ value: [String: Any]) throws {
        let delay = (value["reactionDelayMillis"] as? NSNumber)?.int64Value ?? 4000
        guard delay >= 0, delay <= 60000 else { throw RaspError.invalid("reaction delay must be 0..60000ms") }
        if let supplied = value["pins"], !(supplied is [String: [String]]) { throw RaspError.invalid("invalid pin map") }
    }
    private func stop() { timer?.cancel(); timer = nil; reactions.values.forEach { $0.cancel() }; reactions = [:]; attest.cancelEnrollment(); generation += 1; session = nil; started = false }
    private func startTimer() {
        let seconds = max(5, min(3600, (config["checkIntervalSeconds"] as? NSNumber)?.intValue ?? 15))
        timer = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000) } catch { break }
                guard !Task.isCancelled else { break }
                guard let self else { break }
                _ = try? await self.scan()
            }
        }
    }

    func execute(_ method: String, _ args: [String: Any]) async throws -> Any? {
        switch method {
        case "start":
            stop(); bootstrap = args; config = args
            let file = directory.appendingPathComponent("policy.json")
            if FileManager.default.fileExists(atPath: file.path) {
                guard let envelope = try JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any] else { throw RaspError.invalid("invalid cached policy") }
                let cached = try verifier.verify(envelope, revision: revision, now: nowSeconds, cached: true)
                revision = cached.revision; expiry = cached.expiresAt
                if expiry > nowSeconds { config.merge(cached.config) { _, new in new } }
            }
            try validate(config); started = true
            let report = try await scan(); startTimer(); return report
        case "stop": stop(); return nil
        case "check": guard started else { throw RaspError.invalid("not started") }; return try await scan()
        case "guard":
            try trusted()
            let flow = try required(args, "flow"), report = try await scan()
            try trusted()
            let sensitive = Set(config["sensitiveFlows"] as? [String] ?? []).contains(flow)
            let threats = report["threats"] as? [[String: Any]] ?? []
            let blocking = sensitive ? threats.filter { ($0["reactions"] as? [String] ?? []).contains("blockSensitive") }.compactMap { $0["type"] as? String } : []
            let warnings = threats.filter { ($0["reactions"] as? [String] ?? []).contains("warnUser") }.compactMap { $0["type"] as? String }
            return ["flow": flow, "allowed": blocking.isEmpty, "blockingThreats": blocking, "warnings": warnings, "report": report]
        case "setSecureScreen", "setSensitiveScreen":
            sensitive = args["enabled"] as? Bool ?? false
            let enabled = sensitive
            await MainActor.run { IOSScreenProtector.shared.setEnabled(enabled) }
            return nil
        case "installId": return install
        case "isDeviceBound": return attest.activeKey != nil
        case "unbindDevice": try attest.unbind(); generation += 1; session = nil; return nil
        case "appAttestBind":
            guard !authorizing else { throw RaspError.invalid("authorization already in progress") }
            authorizing = true; defer { authorizing = false }
            let nonce = try required(args, "nonce")
            let epoch = generation
            let result = try await attest.bind(nonce: nonce)
            guard epoch == generation else { throw RaspError.invalid("enrollment superseded") }
            return result.merging(["installId": install, "nonce": nonce]) { _, new in new }
        case "confirmAppAttestBinding": try attest.confirm(key: required(args, "keyId")); generation += 1; session = nil; return nil
        case "prepareAppAttestToken":
            guard !authorizing else { throw RaspError.invalid("authorization already in progress") }
            authorizing = true; defer { authorizing = false }
            try trusted(); let epoch = generation
            let nonce = try required(args, "nonce")
            guard let key = attest.activeKey else { throw RaspError.invalid("App Attest binding required") }
            let report = try await scan(); try trusted()
            let sealed = try seal(nonce: nonce, signals: report["signals"] as? [[String: Any]] ?? [])
            let candidate = SessionProof()
            let assertion = try await attest.assertion(key: key, message: Wire.token(nonce: nonce, mac: sealed["mac"]!, thumbprint: candidate.thumbprint))
            try trusted(); guard epoch == generation else { throw RaspError.invalid("session replaced during assertion") }
            session = candidate
            return ["installId": install, "nonce": nonce, "keyId": key, "assertion": assertion.base64EncodedString(), "sealedReport": sealed, "sessionPublicKey": candidate.publicKey]
        case "signRequest":
            try trusted(); guard let session = session else { throw RaspError.invalid("no authorized session") }
            return try session.sign(method: args["method"] as? String ?? "POST", path: required(args, "path"), body: args["body"] as? Data ?? Data(), now: nowMillis)
        case "request":
            try trusted()
            return try await PinnedTransport(pins: pins(config)).request(url: required(args, "url"), method: args["method"] as? String ?? "GET", headers: args["headers"] as? [String: String] ?? [:], body: args["body"] as? Data ?? Data())
        case "securePut": try trusted(); guard let value = args["value"] as? Data else { throw RaspError.invalid("binary value required") }; try store.put(required(args, "key"), value: value); return nil
        case "secureGet": try trusted(); return try store.get(required(args, "key"))
        case "secureDelete": try store.delete(required(args, "key")); return nil
        case "secureClear": try store.clear(); session = nil; return nil
        case "eventLog": return history
        case "clearEventLog": history = []; try persistHistory(); return nil
        case "applyPolicy": try applyPolicy(required(args, "envelope")); return nil
        case "refreshPolicy":
            let response = try await PinnedTransport(pins: pins(bootstrap)).request(url: required(args, "url"), method: "GET", headers: [:], body: Data())
            guard response["status"] as? Int == 200, let body = response["body"] as? Data, let envelope = String(data: body, encoding: .utf8) else { throw RaspError.invalid("policy refresh failed") }
            try applyPolicy(envelope); return nil
        default: throw RaspError.invalid("unsupported iOS operation: \(method)")
        }
    }

    private func applyPolicy(_ text: String) throws {
        guard started, text.utf8.count <= 131072, let envelope = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { throw RaspError.invalid("invalid policy envelope") }
        let verified = try verifier.verify(envelope, revision: revision, now: nowSeconds)
        let updated = bootstrap.merging(verified.config) { _, new in new }
        try validate(updated)
        try Data(text.utf8).write(to: directory.appendingPathComponent("policy.json"), options: [.atomic, .completeFileProtection])
        stop(); revision = verified.revision; expiry = verified.expiresAt; config = updated; started = true; startTimer()
    }

    private func scan() async throws -> [String: Any] {
        let epoch = generation
        var signals = IOSDetectors.scan(expectedBundle: config["expectedPackageName"] as? String)
        let captured = await MainActor.run { UIScreen.main.isCaptured }
        guard epoch == generation else { throw RaspError.invalid("scan superseded") }
        if captured { signals.append(IOSDetectors.signal("screenRecording", "ios.captured_display", 90, "screen is being captured")) }
        do {
            let manifest = try buildManifest()
            let measured = try BundleIntegrity.measure(root: Bundle.main.bundleURL, regions: manifest.regions)
            if !measured.matches { signals.append(IOSDetectors.signal("tamper", "ios.bundle_integrity", 100, "protected resource differs")) }
        } catch {
            if config["devMode"] as? Bool != true { signals.append(IOSDetectors.signal("tamper", "ios.integrity_unavailable", 85, "signed-build integrity configuration unavailable")) }
        }
        let threats = Set(signals.compactMap { $0["threat"] as? String })
        let defaults: [String: [String]] = ["root": ["report", "warnUser", "blockSensitive"], "emulator": ["report", "blockSensitive"], "debugger": ["report", "blockSensitive"], "hooking": ["report", "blockSensitive"], "tamper": ["report", "blockSensitive"], "screenRecording": ["report", "blockSensitive"]]
        let policy = defaults.merging(config["policy"] as? [String: [String]] ?? [:]) { _, new in new }
        let dev = config["devMode"] as? Bool == true
        let configured = threats.sorted().map { ["type": $0, "reactions": dev ? ["report"] : (policy[$0] ?? ["report"])] as [String: Any] }
        let decision = ScanDecision(signals: signals, configured: configured, previous: lastThreats, sensitive: sensitive)
        let reactions = decision.reactions
        if !dev {
            if !threats.isDisjoint(with: Set(config["wipeOnThreats"] as? [String] ?? [])) {
                degraded = true; session = nil; try store.clear()
            }
            if reactions.contains("silentDegrade") || reactions.contains("closeApp") { degraded = true; session = nil }
        }
        await MainActor.run { IOSScreenProtector.shared.setEnabled(decision.secureScreen) }
        guard epoch == generation else { throw RaspError.invalid("scan superseded") }
        let risk = !threats.isDisjoint(with: ["tamper", "hooking", "debugger", "screenRecording"]) ? "high" : threats.isEmpty ? "none" : "medium"
        let report: [String: Any] = ["riskLevel": risk, "threats": configured, "signals": signals, "timestamp": nowMillis]
        let newThreats = decision.newThreats
        lastThreats = threats
        if !newThreats.isEmpty {
            let item: [String: Any] = ["riskLevel": risk, "newThreats": newThreats.sorted(), "reactions": decision.newReactions.sorted(), "signals": decision.newSignals, "timestamp": nowMillis]
            history = Array((history + [item]).suffix(500)); try persistHistory()
            let delay = UInt64((config["reactionDelayMillis"] as? NSNumber)?.int64Value ?? 4000)
            let identifier = UUID()
            let task = Task { [weak self] in
                do { try await Task.sleep(nanoseconds: delay * 1_000_000) } catch { return }
                await self?.deliver(item, epoch: epoch, identifier: identifier)
            }
            self.reactions[identifier] = task
        }
        return report
    }

    private func deliver(_ item: [String: Any], epoch: Int, identifier: UUID) {
        reactions.removeValue(forKey: identifier)
        guard epoch == generation, started else { return }
        event(item)
    }

    private func persistHistory() throws { try JSONSerialization.data(withJSONObject: history).write(to: directory.appendingPathComponent("events.json"), options: [.atomic, .completeFileProtection]) }
    private struct BuildManifest: Decodable { let buildId: String; let buildKey: String; let regions: [IntegrityRegion] }
    private func buildManifest() throws -> BuildManifest {
        guard let url = Bundle.main.url(forResource: "RaspBuild", withExtension: "json") else { throw RaspError.invalid("RaspBuild.json required") }
        return try JSONDecoder().decode(BuildManifest.self, from: Data(contentsOf: url))
    }
    private func seal(nonce: String, signals: [[String: Any]]) throws -> [String: String] {
        let manifest = try buildManifest()
        guard let key = Data(base64Encoded: manifest.buildKey), key.count == 32 else { throw RaspError.invalid("invalid build key") }
        let measured = try BundleIntegrity.measure(root: Bundle.main.bundleURL, regions: manifest.regions)
        let derived = SymmetricKey(data: Data(HMAC<SHA256>.authenticationCode(for: measured.root, using: SymmetricKey(data: key))))
        let bytes = try JSONSerialization.data(withJSONObject: ["v": "rasp-report-1", "buildId": manifest.buildId, "nonce": nonce, "ts": nowMillis, "signals": signals], options: [.sortedKeys])
        return ["report": String(decoding: bytes, as: UTF8.self), "mac": Wire.hex(Data(HMAC<SHA256>.authenticationCode(for: bytes, using: derived)))]
    }
}
#endif
