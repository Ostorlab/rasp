import Foundation
#if canImport(DeviceCheck) && canImport(UIKit)
import DeviceCheck
#endif

protocol AttestationService {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ key: String, hash: Data) async throws -> Data
    func assertion(_ key: String, hash: Data) async throws -> Data
}
#if canImport(DeviceCheck) && canImport(UIKit)
struct AppleAttestationService: AttestationService {
    private let service = DCAppAttestService.shared
    var isSupported: Bool { service.isSupported }
    func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { value, error in
                if let value = value { continuation.resume(returning: value) }
                else { continuation.resume(throwing: error ?? RaspError.invalid("App Attest returned no key")) }
            }
        }
    }
    func attestKey(_ key: String, hash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(key, clientDataHash: hash) { value, error in
                if let value = value { continuation.resume(returning: value) }
                else { continuation.resume(throwing: error ?? RaspError.invalid("App Attest returned no attestation")) }
            }
        }
    }
    func assertion(_ key: String, hash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(key, clientDataHash: hash) { value, error in
                if let value = value { continuation.resume(returning: value) }
                else { continuation.resume(throwing: error ?? RaspError.invalid("App Attest returned no assertion")) }
            }
        }
    }
}
#endif

final class AppAttestClient {
    private let service: AttestationService
    private let directory: URL
    private let lock = NSLock()
    private var generation = 0
    private var pendingGeneration: Int?
    init(directory: URL, service: AttestationService) { self.directory = directory; self.service = service }
    #if canImport(DeviceCheck) && canImport(UIKit)
    convenience init(directory: URL) { self.init(directory: directory, service: AppleAttestationService()) }
    #endif
    private var activeFile: URL { directory.appendingPathComponent("app-attest-key") }
    private var pendingFile: URL { directory.appendingPathComponent("pending-app-attest-key") }
    private func synchronized<T>(_ action: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try action() }
    var activeKey: String? { synchronized { try? String(contentsOf: activeFile, encoding: .utf8) } }
    private var options: Data.WritingOptions {
        #if canImport(UIKit)
        return [.atomic, .completeFileProtection]
        #else
        return [.atomic]
        #endif
    }
    func bind(nonce: String) async throws -> [String: Any] {
        guard service.isSupported else { throw RaspError.invalid("app_attest_unsupported") }
        let epoch = synchronized { generation }
        let key = try await service.generateKey()
        try synchronized { guard epoch == generation else { throw RaspError.invalid("enrollment cancelled") } }
        let attestation = try await service.attestKey(key, hash: Wire.hash(Data(nonce.utf8)))
        try synchronized {
            guard epoch == generation else { throw RaspError.invalid("enrollment cancelled") }
            try Data(key.utf8).write(to: pendingFile, options: options)
            pendingGeneration = epoch
        }
        return ["keyId": key, "attestationObject": attestation.base64EncodedString()]
    }
    func cancelEnrollment() {
        synchronized {
            generation += 1
            pendingGeneration = nil
            // Confirmation is revoked even if filesystem cleanup fails.
            try? FileManager.default.removeItem(at: pendingFile)
        }
    }
    func confirm(key: String) throws {
        try synchronized {
            guard pendingGeneration == generation else { throw RaspError.invalid("enrollment cancelled") }
            guard try String(contentsOf: pendingFile, encoding: .utf8) == key else { throw RaspError.invalid("binding confirmation key mismatch") }
            try Data(key.utf8).write(to: activeFile, options: options)
            try FileManager.default.removeItem(at: pendingFile)
            generation += 1
            pendingGeneration = nil
        }
    }
    func assertion(key: String, message: Data) async throws -> Data {
        guard service.isSupported else { throw RaspError.invalid("app_attest_unsupported") }
        return try await service.assertion(key, hash: Wire.hash(message))
    }
    func unbind() throws {
        try synchronized {
            generation += 1
            pendingGeneration = nil
            for file in [activeFile, pendingFile] where FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
        }
    }
}
