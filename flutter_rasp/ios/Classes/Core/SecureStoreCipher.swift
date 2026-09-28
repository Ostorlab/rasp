import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

enum SecureStoreCipher {
    static func read(_ file: URL, master: () throws -> SymmetricKey, aad: Data) throws -> Data? {
        if !FileManager.default.fileExists(atPath: file.path) { return nil }
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard let length = attributes[.size] as? NSNumber,
              length.intValue >= SecureStoreEnvelope.minimumLength,
              length.intValue <= SecureStoreEnvelope.maximumLength else { throw RaspError.invalid("invalid store length") }
        let envelope = try SecureStoreEnvelope.decode(Data(contentsOf: file))
        // Keychain/filesystem/framing errors propagate; only failed authentication is recoverable.
        let wrappingKey = try master()
        do {
            var rawKey = try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.wrappedKey), using: wrappingKey, authenticating: aad)
            defer { rawKey.resetBytes(in: 0..<rawKey.count) }
            guard rawKey.count == SecureStoreEnvelope.dataKeyLength else { throw RaspError.invalid("invalid data key length") }
            return try AES.GCM.open(AES.GCM.SealedBox(combined: envelope.payload), using: SymmetricKey(data: rawKey), authenticating: aad)
        } catch CryptoKitError.authenticationFailure {
            try FileManager.default.removeItem(at: file)
            return nil
        }
    }
}
