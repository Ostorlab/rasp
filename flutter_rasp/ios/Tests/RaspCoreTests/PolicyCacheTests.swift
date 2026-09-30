import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import RaspCore

private final class MemoryRevisions: PolicyRevisionStorage {
    var values: [String: Data] = [:]
    var failRead = false
    var failWrite = false
    func read(_ scope: String) throws -> Data? {
        if failRead { throw CocoaError(.fileReadNoPermission) }
        return values[scope]
    }
    func write(_ data: Data, scope: String) throws {
        if failWrite { throw CocoaError(.fileWriteNoPermission) }
        values[scope] = data
    }
}

final class PolicyCacheTests: XCTestCase {
    private let key = P256.Signing.PrivateKey()
    private var verifier: PolicyVerifier {
        PolicyVerifier(keys: ["k": key.publicKey.derRepresentation.base64EncodedString()], tenant: "t", app: "a")
    }
    private func signed(_ revision: Int64, expires: Int64 = 2000, tenant: String = "t") throws -> String {
        let payload = try JSONSerialization.data(withJSONObject: ["tenantId": tenant, "appId": "a", "revision": revision,
                                                                 "issuedAt": 900, "expiresAt": expires, "config": ["checkIntervalSeconds": 30]])
        let envelope = ["kid": "k", "payload": Wire.url(payload), "signature": Wire.url(try key.signature(for: payload).rawRepresentation)]
        return String(decoding: try JSONSerialization.data(withJSONObject: envelope), as: UTF8.self)
    }
    private func withFile(_ action: (URL, MemoryRevisions) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try action(directory.appendingPathComponent("policy.json"), MemoryRevisions())
    }
    private func cache(_ file: URL, _ storage: MemoryRevisions) throws -> PolicyCache {
        try PolicyCache(file: file, storage: storage, tenant: "t", app: "a")
    }
    func testRestartRejectsRestoredOlderSignedCacheAndAcceptsEqualCurrentCache() throws {
        try withFile { file, storage in
            let current = try signed(2)
            _ = try cache(file, storage).accept(current, verifier: verifier, now: 1000, validate: { _ in })
            try Data(signed(1).utf8).write(to: file)
            XCTAssertThrowsError(try cache(file, storage).load(verifier: verifier, now: 1000, validate: { _ in }))
            try Data(current.utf8).write(to: file)
            let restarted = try cache(file, storage)
            XCTAssertEqual(try restarted.load(verifier: verifier, now: 1000, validate: { _ in })?.revision, 2)
            XCTAssertThrowsError(try restarted.accept(current, verifier: verifier, now: 1000, validate: { _ in }))
        }
    }
    func testExpiredOrMissingCacheRetainsFloorAndCannotEnableBootstrapTrust() throws {
        try withFile { file, storage in
            _ = try cache(file, storage).accept(signed(3, expires: 1100), verifier: verifier, now: 1000, validate: { _ in })
            let expired = try cache(file, storage)
            XCTAssertEqual(try expired.load(verifier: verifier, now: 1200, validate: { _ in })?.expiresAt, 1100)
            XCTAssertEqual(expired.revision, 3)
            try FileManager.default.removeItem(at: file)
            let missing = try cache(file, storage)
            XCTAssertNil(try missing.load(verifier: verifier, now: 1200, validate: { _ in }))
            XCTAssertFalse(missing.bootstrapAllowed)
            XCTAssertTrue(try cache(file, MemoryRevisions()).bootstrapAllowed)
        }
    }
    func testRejectedStaleCacheRecoversOnlyWithStrictlyNewerSignedPolicy() throws {
        try withFile { file, storage in
            _ = try cache(file, storage).accept(signed(2), verifier: verifier, now: 1000, validate: { _ in })
            try Data(signed(1).utf8).write(to: file)
            let recovery = try cache(file, storage)
            XCTAssertThrowsError(try recovery.load(verifier: verifier, now: 1000, validate: { _ in }))
            XCTAssertFalse(recovery.bootstrapAllowed)
            XCTAssertThrowsError(try recovery.accept(signed(2), verifier: verifier, now: 1000, validate: { _ in }))
            XCTAssertEqual(try recovery.accept(signed(3), verifier: verifier, now: 1000, validate: { _ in }).revision, 3)
            XCTAssertEqual(try cache(file, storage).load(verifier: verifier, now: 1000, validate: { _ in })?.revision, 3)
        }
    }
    func testUnverifiedAudienceOrInvalidConfigurationCannotAdvanceFloor() throws {
        try withFile { file, storage in
            let initial = try signed(1)
            let existing = try cache(file, storage)
            _ = try existing.accept(initial, verifier: verifier, now: 1000, validate: { _ in })
            var invalid = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(signed(99).utf8)) as? [String: String])
            invalid["payload"] = Wire.url(Data("{}".utf8))
            let tampered = String(decoding: try JSONSerialization.data(withJSONObject: invalid), as: UTF8.self)
            XCTAssertThrowsError(try existing.accept(tampered, verifier: verifier, now: 1000, validate: { _ in }))
            XCTAssertThrowsError(try existing.accept(signed(99, tenant: "other"), verifier: verifier, now: 1000, validate: { _ in }))
            XCTAssertThrowsError(try existing.accept(signed(99), verifier: verifier, now: 1000, validate: { _ in throw RaspError.invalid("unsupported config") }))
            XCTAssertEqual(try cache(file, storage).revision, 1)
            XCTAssertEqual(try Data(contentsOf: file), Data(initial.utf8))
        }
    }
    func testCacheWriteFailureCommitsFloorBeforeFailureAndBlocksOldRestoredCache() throws {
        try withFile { file, storage in
            let old = try signed(1), existing = try cache(file, storage)
            _ = try existing.accept(old, verifier: verifier, now: 1000, validate: { _ in })
            try FileManager.default.removeItem(at: file)
            try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
            XCTAssertThrowsError(try existing.accept(signed(2), verifier: verifier, now: 1000, validate: { _ in })) { error in
                XCTAssertNotNil(error as? PolicyCacheFailure, "missing fail-closed persistence classification")
            }
            XCTAssertEqual(try cache(file, storage).revision, 2)
            try FileManager.default.removeItem(at: file)
            try Data(old.utf8).write(to: file)
            let restarted = try cache(file, storage)
            XCTAssertThrowsError(try restarted.load(verifier: verifier, now: 1000, validate: { _ in }))
            XCTAssertEqual(try restarted.accept(signed(3), verifier: verifier, now: 1000, validate: { _ in }).revision, 3)
        }
    }
    func testFloorWriteFailurePropagatesAndPreservesExistingCache() throws {
        try withFile { file, storage in
            let old = try signed(1), existing = try cache(file, storage)
            _ = try existing.accept(old, verifier: verifier, now: 1000, validate: { _ in })
            storage.failWrite = true
            XCTAssertThrowsError(try existing.accept(signed(2), verifier: verifier, now: 1000, validate: { _ in })) { error in
                XCTAssertNotNil(error as? PolicyCacheFailure, "missing fail-closed persistence classification")
            }
            XCTAssertEqual(existing.revision, 1)
            XCTAssertEqual(try Data(contentsOf: file), Data(old.utf8))
        }
    }
    func testKeychainReadFailureOrMalformedFloorNeverDefaultsToZero() throws {
        try withFile { file, storage in
            _ = try cache(file, storage).accept(signed(1), verifier: verifier, now: 1000, validate: { _ in })
            storage.failRead = true
            XCTAssertThrowsError(try cache(file, storage))
            storage.failRead = false
            let scope = try XCTUnwrap(storage.values.keys.first)
            for invalid in ["invalid", "-1", "0", "9223372036854775808", ""] {
                storage.values[scope] = Data(invalid.utf8)
                XCTAssertThrowsError(try cache(file, storage))
            }
        }
    }
    func testTenantAppScopeAndStaleInstanceCannotLowerPersistedFloor() throws {
        let storage = MemoryRevisions()
        let olderInstance = try PolicyRevisionFloor(storage: storage, tenant: "t", app: "a")
        let newerInstance = try PolicyRevisionFloor(storage: storage, tenant: "t", app: "a")
        try newerInstance.advance(3, cached: false)
        XCTAssertThrowsError(try olderInstance.advance(2, cached: false))
        XCTAssertThrowsError(try olderInstance.advance(3, cached: false))
        try olderInstance.advance(3, cached: true)
        XCTAssertEqual(olderInstance.revision, 3)
        XCTAssertEqual(try PolicyRevisionFloor(storage: storage, tenant: "other", app: "a").revision, 0)
        XCTAssertEqual(try PolicyRevisionFloor(storage: storage, tenant: "t", app: "other").revision, 0)
    }
}
