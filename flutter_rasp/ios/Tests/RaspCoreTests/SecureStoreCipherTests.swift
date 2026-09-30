import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import RaspCore

final class SecureStoreCipherTests: XCTestCase {
    private func withEntry(_ action: (URL, SymmetricKey, Data, Data) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("entry")
        let master = SymmetricKey(size: .bits256), key = SymmetricKey(size: .bits256)
        let aad = Data("account".utf8), value = Data([0, 1, 255])
        let wrapped = try XCTUnwrap(AES.GCM.seal(key.withUnsafeBytes { Data($0) }, using: master, authenticating: aad).combined)
        let sealed = try XCTUnwrap(AES.GCM.seal(value, using: key, authenticating: aad).combined)
        let bytes = try SecureStoreEnvelope.encode(wrappedKey: wrapped, payload: sealed)
        try bytes.write(to: file)
        try action(file, master, aad, bytes)
    }
    func testTamperedPayloadIsDeletedAndReadsAsAbsentThenValidEntryRecovers() throws {
        try withEntry { file, master, aad, valid in
            var bytes = valid; bytes[bytes.count - 1] ^= 1
            try bytes.write(to: file)
            XCTAssertNil(try SecureStoreCipher.read(file, master: { master }, aad: aad))
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
            try valid.write(to: file)
            XCTAssertEqual(try SecureStoreCipher.read(file, master: { master }, aad: aad), Data([0, 1, 255]))
        }
    }
    func testTamperedWrappedKeyIsDeletedAndReadsAsAbsent() throws {
        try withEntry { file, master, aad, valid in
            var bytes = valid; bytes[SecureStoreEnvelope.payloadOffset - 1] ^= 1
            try bytes.write(to: file)
            XCTAssertNil(try SecureStoreCipher.read(file, master: { master }, aad: aad))
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        }
    }
    func testCiphertextLeftAfterWrappingKeyReplacementIsDeleted() throws {
        try withEntry { file, _, aad, _ in
            XCTAssertNil(try SecureStoreCipher.read(file, master: { SymmetricKey(size: .bits256) }, aad: aad))
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        }
    }
    func testKeychainErrorPropagatesWithoutDeletingCiphertext() throws {
        try withEntry { file, _, aad, _ in
            XCTAssertThrowsError(try SecureStoreCipher.read(file, master: { throw CocoaError(.fileReadNoPermission) }, aad: aad)) { error in
                XCTAssertEqual((error as NSError).code, CocoaError.fileReadNoPermission.rawValue)
            }
            XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        }
    }
    func testFramingAndFilesystemErrorsPropagateWithoutDeletingEntry() throws {
        try withEntry { file, master, aad, valid in
            var invalid = valid; invalid[0] = 2
            try invalid.write(to: file)
            XCTAssertThrowsError(try SecureStoreCipher.read(file, master: { master }, aad: aad))
            XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
            try FileManager.default.removeItem(at: file)
            try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
            XCTAssertThrowsError(try SecureStoreCipher.read(file, master: { master }, aad: aad))
            XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        }
    }
    func testAbsentEntryDoesNotAccessKeychain() throws {
        let absent = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        XCTAssertNil(try SecureStoreCipher.read(absent, master: { XCTFail("absent value accessed Keychain"); throw CocoaError(.fileReadNoPermission) }, aad: Data()))
    }
}
