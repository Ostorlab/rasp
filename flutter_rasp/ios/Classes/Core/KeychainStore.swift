#if canImport(UIKit)
import Foundation
import Security
import CryptoKit

final class KeychainBox {
    private let service: String
    init(service: String) { self.service = service }
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }
    func get(_ account: String) throws -> Data? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw RaspError.invalid("Keychain read failed: \(status)") }
        return data
    }
    func put(_ account: String, data: Data) throws {
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
        var status = SecItemUpdate(query(account) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound { status = SecItemAdd(query(account).merging(attributes) { _, new in new } as CFDictionary, nil) }
        guard status == errSecSuccess else { throw RaspError.invalid("Keychain write failed: \(status)") }
    }
    func delete(_ account: String) throws {
        let status = SecItemDelete(query(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw RaspError.invalid("Keychain delete failed: \(status)") }
    }
}

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
        let file = try entry(name)
        if !FileManager.default.fileExists(atPath: file.path) { return nil }
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard let length = attributes[.size] as? NSNumber, length.intValue >= SecureStoreEnvelope.minimumLength, length.intValue <= SecureStoreEnvelope.maximumLength else { throw RaspError.invalid("invalid store length") }
        let envelope = try SecureStoreEnvelope.decode(Data(contentsOf: file))
        let aad = Data(name.utf8)
        var rawKey = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.wrappedKey), using: master(), authenticating: aad)
        defer { rawKey.resetBytes(in: 0..<rawKey.count) }
        guard rawKey.count == SecureStoreEnvelope.dataKeyLength else { throw RaspError.invalid("invalid data key length") }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.payload), using: SymmetricKey(data: rawKey), authenticating: aad)
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
