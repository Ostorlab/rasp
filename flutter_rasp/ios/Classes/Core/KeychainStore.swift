#if canImport(UIKit)
import Foundation
import Security
import CryptoKit

final class KeychainStore {
    private let directory: URL
    private let keychain: KeychainBox
    private let account: String
    init(directory: URL, install: String) {
        self.directory = directory
        account = "data-key-\(install)"
        keychain = KeychainBox(service: "\(Bundle.main.bundleIdentifier ?? "rasp").rasp")
    }
    private func master() throws -> SymmetricKey {
        if let data = try keychain.get(account) { return SymmetricKey(data: data) }
        let key = SymmetricKey(size: .bits256)
        try keychain.put(account, data: key.withUnsafeBytes { Data($0) })
        return key
    }
    private func entry(_ name: String) throws -> URL {
        guard !name.isEmpty, name.utf8.count <= 1024 else { throw RaspError.invalid("invalid store name") }
        return directory.appendingPathComponent(Wire.hex(Wire.hash(Data(name.utf8))))
    }
    func put(_ name: String, value: Data) throws {
        guard value.count <= SecureStoreEnvelope.maximumValueLength else { throw RaspError.invalid("value too large") }
        let aad = Data(name.utf8), dataKey = SymmetricKey(size: .bits256)
        let wrapped = try AES.GCM.seal(dataKey.withUnsafeBytes { Data($0) }, using: master(), authenticating: aad)
        let sealed = try AES.GCM.seal(value, using: dataKey, authenticating: aad)
        guard let wrappedBytes = wrapped.combined, let sealedBytes = sealed.combined else { throw RaspError.invalid("GCM framing failed") }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try SecureStoreEnvelope.encode(wrappedKey: wrappedBytes, payload: sealedBytes).write(to: entry(name), options: [.atomic, .completeFileProtection])
    }
    func get(_ name: String) throws -> Data? {
        try SecureStoreCipher.read(entry(name), master: master, aad: Data(name.utf8))
    }
    func delete(_ name: String) throws {
        let file = try entry(name)
        if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
    }
    func invalidateKey() throws { try keychain.delete(account) }
    func clear() throws {
        try invalidateKey()
        if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
    }
}
#endif
