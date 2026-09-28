import Foundation

protocol PolicyRevisionStorage {
    func read(_ scope: String) throws -> Data?
    func write(_ data: Data, scope: String) throws
}

final class PolicyRevisionFloor {
    // Serialize read/max/write across SDK instances in this process.
    private static let lock = NSLock()
    private let storage: PolicyRevisionStorage
    private let scope: String
    private(set) var revision: Int64

    init(storage: PolicyRevisionStorage, tenant: String, app: String) throws {
        self.storage = storage
        scope = Wire.hex(Wire.hash(Data("\(tenant.utf8.count):\(tenant)\(app.utf8.count):\(app)".utf8)))
        Self.lock.lock(); defer { Self.lock.unlock() }
        revision = try Self.load(storage, scope: scope)
    }
    private static func load(_ storage: PolicyRevisionStorage, scope: String) throws -> Int64 {
        guard let data = try storage.read(scope) else { return 0 }
        guard !data.isEmpty, data.count <= 19,
              data.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let revision = Int64(String(decoding: data, as: UTF8.self)), revision > 0 else {
            throw RaspError.invalid("invalid persisted policy revision")
        }
        return revision
    }
    func advance(_ next: Int64, cached: Bool) throws {
        Self.lock.lock(); defer { Self.lock.unlock() }
        let current = max(revision, try Self.load(storage, scope: scope))
        guard next > 0, next > current || (cached && next == current) else { throw RaspError.invalid("policy rollback") }
        if next > current { try storage.write(Data(String(next).utf8), scope: scope) }
        revision = next
    }
}

enum PolicyCacheFailure: Error { case persistence(Error) }

final class PolicyCache {
    private let file: URL
    private let floor: PolicyRevisionFloor
    var revision: Int64 { floor.revision }
    var bootstrapAllowed: Bool { revision == 0 }
    init(file: URL, storage: PolicyRevisionStorage, tenant: String, app: String) throws {
        self.file = file
        floor = try PolicyRevisionFloor(storage: storage, tenant: tenant, app: app)
    }
    private func envelope(_ data: Data) throws -> [String: Any] {
        guard data.count <= 131072, let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw RaspError.invalid("invalid cached policy") }
        return envelope
    }
    func load(verifier: PolicyVerifier, now: Int64, validate: ([String: Any]) throws -> Void) throws -> PolicyVerifier.Verified? {
        guard FileManager.default.fileExists(atPath: file.path) else { return nil }
        let reader = try FileHandle(forReadingFrom: file)
        defer { try? reader.close() }
        let data = try reader.read(upToCount: 131073) ?? Data()
        let verified = try verifier.verify(envelope(data), revision: revision, now: now, cached: true)
        try validate(verified.config)
        try floor.advance(verified.revision, cached: true)
        return verified
    }
    func accept(_ text: String, verifier: PolicyVerifier, now: Int64, validate: ([String: Any]) throws -> Void) throws -> PolicyVerifier.Verified {
        let data = Data(text.utf8)
        let verified = try verifier.verify(envelope(data), revision: revision, now: now)
        try validate(verified.config)
        // Persist the floor first: interruption cannot make an older cache usable.
        #if canImport(UIKit)
        let options: Data.WritingOptions = [.atomic, .completeFileProtection]
        #else
        let options: Data.WritingOptions = [.atomic]
        #endif
        do {
            try floor.advance(verified.revision, cached: false)
            try data.write(to: file, options: options)
        } catch { throw PolicyCacheFailure.persistence(error) }
        return verified
    }
}

#if canImport(Security)
struct KeychainPolicyRevisions: PolicyRevisionStorage {
    private let keychain = KeychainBox(service: "\(Bundle.main.bundleIdentifier ?? "rasp").rasp.policy-revisions")
    func read(_ scope: String) throws -> Data? { try keychain.get(scope) }
    func write(_ data: Data, scope: String) throws { try keychain.put(scope, data: data) }
}
#endif
