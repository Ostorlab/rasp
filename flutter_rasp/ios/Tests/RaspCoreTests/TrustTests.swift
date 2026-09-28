import XCTest
@testable import RaspCore
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class TrustTests: XCTestCase {
    func testRequestProofSignsExactBytesAndIncrementsCounter() throws {
        let session = SessionProof()
        let first = try session.sign(method: "post", path: "/pay", body: Data([1, 2]), now: 1000)
        let next = try session.sign(method: "post", path: "/pay", body: Data([1, 2]), now: 1000)
        XCTAssertEqual(first["counter"] as? Int64, 1)
        XCTAssertEqual(next["counter"] as? Int64, 2)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Wire.decodeURL(first["sig"] as! String))
        let key = try P256.Signing.PublicKey(derRepresentation: Data(base64Encoded: first["key"] as! String)!)
        let message = Wire.request(method: "POST", path: "/pay", body: Data([1, 2]), timestamp: 1000, counter: 1)
        XCTAssertTrue(key.isValidSignature(signature, for: message))
        XCTAssertFalse(key.isValidSignature(signature, for: Wire.request(method: "POST", path: "/pay", body: Data([2, 1]), timestamp: 1000, counter: 1)))
    }
    func testSignedPolicyRejectsTamperingExpiryAndRollback() throws {
        let key = P256.Signing.PrivateKey()
        let payload = try JSONSerialization.data(withJSONObject: ["tenantId": "t", "appId": "a", "revision": 2, "issuedAt": 900, "expiresAt": 2000, "config": ["checkIntervalSeconds": 30]])
        let signed = try key.signature(for: payload).rawRepresentation
        let envelope: [String: Any] = ["kid": "k", "payload": Wire.url(payload), "signature": Wire.url(signed)]
        let verifier = PolicyVerifier(keys: ["k": key.publicKey.derRepresentation.base64EncodedString()], tenant: "t", app: "a")
        XCTAssertEqual(try verifier.verify(envelope, revision: 1, now: 1000).revision, 2)
        XCTAssertThrowsError(try verifier.verify(envelope, revision: 2, now: 1000))
        XCTAssertThrowsError(try verifier.verify(envelope, revision: 1, now: 2000))
        var changed = envelope
        changed["payload"] = Wire.url(Data("{}".utf8))
        XCTAssertThrowsError(try verifier.verify(changed, revision: 1, now: 1000))
    }
    func testCertificatePinHashesSubjectPublicKeyInfo() throws {
        let certificate = try Data(contentsOf: Bundle.module.url(forResource: "localhost", withExtension: "der")!)
        XCTAssertEqual(Wire.hash(try CertificateSPKI.extract(certificate)).base64EncodedString(), "UM8eeHmWReklDH9SnBHg18BWG/SIBLv1k3O4+jgnKWQ=")
        XCTAssertThrowsError(try CertificateSPKI.extract(Data([0x30, 0x84, 0xff])))
    }
    func testIntegrityRootChangesWhenProtectedResourceChanges() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let file = root.appendingPathComponent("code")
        try Data([1, 2, 3]).write(to: file)
        let region = IntegrityRegion(path: "code", offset: 0, length: 3, sha256: Wire.hex(Wire.hash(Data([1, 2, 3]))))
        let first = try BundleIntegrity.measure(root: root, regions: [region])
        XCTAssertTrue(first.matches)
        XCTAssertEqual(Wire.hex(first.root), "cb264d767858d97f29f903a96fcddeb62da416fd13d9bd37c989925ad9cf3463")
        try Data([1, 2, 4]).write(to: file)
        let changed = try BundleIntegrity.measure(root: root, regions: [region])
        XCTAssertFalse(changed.matches)
        XCTAssertNotEqual(first.root, changed.root)
    }
}
