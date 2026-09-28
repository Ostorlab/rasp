#if canImport(UIKit)
import Foundation
import DeviceCheck

final class AppAttestClient {
    private let service = DCAppAttestService.shared
    private let directory: URL
    init(directory: URL) { self.directory = directory }
    private var activeFile: URL { directory.appendingPathComponent("app-attest-key") }
    private var pendingFile: URL { directory.appendingPathComponent("pending-app-attest-key") }
    var activeKey: String? { try? String(contentsOf: activeFile, encoding: .utf8) }
    func bind(nonce: String) async throws -> [String: Any] {
        guard service.isSupported else { throw RaspError.invalid("app_attest_unsupported") }
        let key: String = try await withCheckedThrowingContinuation { continuation in
            service.generateKey { key, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let key = key { continuation.resume(returning: key) }
                else { continuation.resume(throwing: RaspError.invalid("App Attest returned no key")) }
            }
        }
        let attestation: Data = try await withCheckedThrowingContinuation { continuation in
            service.attestKey(key, clientDataHash: Wire.hash(Data(nonce.utf8))) { data, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let data = data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: RaspError.invalid("App Attest returned no attestation")) }
            }
        }
        try Data(key.utf8).write(to: pendingFile, options: [.atomic, .completeFileProtection])
        return ["keyId": key, "attestationObject": attestation.base64EncodedString()]
    }
    func confirm(key: String) throws {
        guard try String(contentsOf: pendingFile, encoding: .utf8) == key else { throw RaspError.invalid("binding confirmation key mismatch") }
        try Data(key.utf8).write(to: activeFile, options: [.atomic, .completeFileProtection])
        try FileManager.default.removeItem(at: pendingFile)
    }
    func assertion(key: String, message: Data) async throws -> Data {
        guard service.isSupported else { throw RaspError.invalid("app_attest_unsupported") }
        return try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(key, clientDataHash: Wire.hash(message)) { data, error in
                if let error = error { continuation.resume(throwing: error) }
                else if let data = data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: RaspError.invalid("App Attest returned no assertion")) }
            }
        }
    }
    func unbind() throws {
        for file in [activeFile, pendingFile] where FileManager.default.fileExists(atPath: file.path) {
            try FileManager.default.removeItem(at: file)
        }
    }
}
#endif
