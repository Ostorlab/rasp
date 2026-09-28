import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import RaspCore

final class SecureStoreEnvelopeTests: XCTestCase {
    func testVersionOneFramingRoundTripsRealAES256GCMWithoutFormatChange() throws {
        let master = SymmetricKey(size: .bits256), key = SymmetricKey(size: .bits256)
        let aad = Data("account".utf8), value = Data([0, 1, 255])
        let wrapped = try XCTUnwrap(AES.GCM.seal(key.withUnsafeBytes { Data($0) }, using: master, authenticating: aad).combined)
        let sealed = try XCTUnwrap(AES.GCM.seal(value, using: key, authenticating: aad).combined)
        let bytes = try SecureStoreEnvelope.encode(wrappedKey: wrapped, payload: sealed)
        XCTAssertEqual(bytes, Data([1]) + wrapped + sealed)
        XCTAssertEqual(wrapped.count, SecureStoreEnvelope.wrappedKeyLength)
        let decoded = try SecureStoreEnvelope.decode(bytes)
        let raw = try AES.GCM.open(AES.GCM.SealedBox(combined: decoded.wrappedKey), using: master, authenticating: aad)
        XCTAssertEqual(raw.count, SecureStoreEnvelope.dataKeyLength)
        let opened = try AES.GCM.open(AES.GCM.SealedBox(combined: decoded.payload), using: SymmetricKey(data: raw), authenticating: aad)
        XCTAssertEqual(opened, value)
    }
    func testInvalidFramingAndVersionAreRejectedBeforeCryptography() throws {
        XCTAssertThrowsError(try SecureStoreEnvelope.encode(wrappedKey: Data(count: 59), payload: Data(count: 28)))
        XCTAssertThrowsError(try SecureStoreEnvelope.encode(wrappedKey: Data(count: 60), payload: Data(count: 27)))
        XCTAssertThrowsError(try SecureStoreEnvelope.decode(Data([1]) + Data(count: 87)))
        XCTAssertThrowsError(try SecureStoreEnvelope.decode(Data([2]) + Data(count: 88)))
        let emptyValue = try SecureStoreEnvelope.encode(wrappedKey: Data(count: 60), payload: Data(count: 28))
        XCTAssertEqual(try SecureStoreEnvelope.decode(emptyValue).payload.count, 28)
    }
}
