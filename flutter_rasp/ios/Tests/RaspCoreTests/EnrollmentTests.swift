import Foundation
import XCTest
@testable import RaspCore

private final class PausedAttestation: AttestationService {
    let isSupported = true
    let reachedAttestation: XCTestExpectation
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ reached: XCTestExpectation) { reachedAttestation = reached }
    func generateKey() async throws -> String { "generated-key" }
    func attestKey(_ key: String, hash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { pending in
            lock.lock(); continuation = pending; lock.unlock()
            reachedAttestation.fulfill()
        }
    }
    func finish() { lock.lock(); let pending = continuation; continuation = nil; lock.unlock(); pending?.resume(returning: Data([1, 2, 3])) }
    func assertion(_ key: String, hash: Data) async throws -> Data { Data() }
}
final class EnrollmentTests: XCTestCase {
    func testCommittedBindingSucceedsAndCannotBeReconfirmedWhenPendingCleanupFails() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let reached = expectation(description: "attestation callback reached")
        let service = PausedAttestation(reached)
        let client = AppAttestClient(directory: directory, service: service, cleanupPending: { _ in
            throw CocoaError(.fileWriteNoPermission)
        })
        let pending = Task { try await client.bind(nonce: "nonce") }
        await fulfillment(of: [reached], timeout: 2)
        service.finish()
        _ = try await pending.value
        try client.confirm(key: "generated-key")
        XCTAssertEqual(client.activeKey, "generated-key")
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("pending-app-attest-key").path))
        XCTAssertThrowsError(try client.confirm(key: "generated-key"))
        client.cancelEnrollment()
        XCTAssertEqual(client.activeKey, "generated-key")
    }
    func testStopAfterAttestationRemovesPendingBindingAndRejectsConfirmation() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let reached = expectation(description: "attestation callback reached")
        let service = PausedAttestation(reached)
        let client = AppAttestClient(directory: directory, service: service)
        let pending = Task { try await client.bind(nonce: "nonce") }
        await fulfillment(of: [reached], timeout: 2)
        service.finish()
        _ = try await pending.value
        let pendingFile = directory.appendingPathComponent("pending-app-attest-key")
        XCTAssertTrue(FileManager.default.fileExists(atPath: pendingFile.path))
        client.cancelEnrollment()
        XCTAssertFalse(FileManager.default.fileExists(atPath: pendingFile.path))
        XCTAssertThrowsError(try client.confirm(key: "generated-key"))
        XCTAssertNil(client.activeKey)
        // A leftover/restored file cannot bypass the in-memory cancellation epoch.
        try Data("generated-key".utf8).write(to: pendingFile)
        XCTAssertThrowsError(try client.confirm(key: "generated-key"))
    }
    func testPendingBindingRequiresConfirmationInItsEnrollmentGeneration() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let reached = expectation(description: "attestation callback reached")
        let service = PausedAttestation(reached)
        let client = AppAttestClient(directory: directory, service: service)
        let pending = Task { try await client.bind(nonce: "nonce") }
        await fulfillment(of: [reached], timeout: 2)
        service.finish()
        _ = try await pending.value
        let restarted = AppAttestClient(directory: directory, service: service)
        XCTAssertThrowsError(try restarted.confirm(key: "generated-key"))
        try client.confirm(key: "generated-key")
        XCTAssertEqual(client.activeKey, "generated-key")
    }
    func testUnbindDuringAttestationCannotRecreatePendingBinding() async throws {
        try await cancelledEnrollment(unbind: true)
    }
    func testStopDuringAttestationCannotRecreatePendingBinding() async throws {
        try await cancelledEnrollment(unbind: false)
    }
    private func cancelledEnrollment(unbind: Bool) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let reached = expectation(description: "attestation suspended")
        let service = PausedAttestation(reached)
        let client = AppAttestClient(directory: directory, service: service)
        let pending = Task { try await client.bind(nonce: "nonce") }
        await fulfillment(of: [reached], timeout: 2)
        if unbind { try client.unbind() } else { client.cancelEnrollment() }
        service.finish()
        do { _ = try await pending.value; XCTFail("cancelled enrollment succeeded") } catch {}
        XCTAssertNil(client.activeKey)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory.appendingPathComponent("pending-app-attest-key").path))
        XCTAssertThrowsError(try client.confirm(key: "generated-key"))
    }
}
