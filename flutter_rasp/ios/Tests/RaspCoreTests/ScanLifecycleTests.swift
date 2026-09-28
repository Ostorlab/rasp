import Foundation
import XCTest
@testable import RaspCore

private final class PausedScan {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Int, Never>?
    func run(_ reached: XCTestExpectation) async -> Int {
        await withCheckedContinuation { pending in
            lock.lock(); continuation = pending; lock.unlock()
            reached.fulfill()
        }
    }
    func finish(_ value: Int) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        pending?.resume(returning: value)
    }
}

final class ScanLifecycleTests: XCTestCase {
    func testNewBindingGenerationDetachesOldScanWithoutExplicitStop() async throws {
        let flight = ScanFlight<Int>(), old = PausedScan(), replacement = PausedScan()
        let oldReached = expectation(description: "old binding scan paused")
        let oldTask = flight.task(generation: 1) { await old.run(oldReached) }
        await fulfillment(of: [oldReached], timeout: 2)
        let newReached = expectation(description: "new binding scan paused")
        let newTask = flight.task(generation: 2) { await replacement.run(newReached) }
        await fulfillment(of: [newReached], timeout: 2)
        old.finish(1)
        _ = try await oldTask.value
        let joining = flight.task(generation: 2) { XCTFail("old binding completion detached current scan"); return 3 }
        replacement.finish(2)
        let value = try await newTask.value, joined = try await joining.value
        XCTAssertEqual(value, 2); XCTAssertEqual(joined, 2)
    }
    func testSecureScreenDisableDoesNotClearSensitiveProtectionOrScanState() {
        var preferences = ScreenPreferences()
        preferences.secure = true; preferences.sensitive = true
        preferences.secure = false
        XCTAssertTrue(preferences.enabled)
        let scan = ScanDecision(signals: [], configured: [], previous: [], sensitive: preferences.appEnabled)
        XCTAssertTrue(scan.secureScreen)
        preferences.sensitive = false
        XCTAssertFalse(preferences.enabled)
    }
    func testSensitiveScreenDisableDoesNotClearSecureOrPolicyProtection() {
        var preferences = ScreenPreferences()
        preferences.secure = true; preferences.sensitive = true
        preferences.sensitive = false
        XCTAssertTrue(preferences.enabled)
        XCTAssertTrue(ScanDecision(signals: [], configured: [], previous: [], sensitive: preferences.appEnabled).secureScreen)
        preferences.secure = false; preferences.policySecure = true
        XCTAssertTrue(preferences.enabled)
        let policy = [["type": "hooking", "reactions": ["secureScreen"]]] as [[String: Any]]
        XCTAssertTrue(ScanDecision(signals: [], configured: policy, previous: [], sensitive: preferences.appEnabled).secureScreen)
    }
    func testOverlappingScansShareOneOperationAcrossSuspension() async throws {
        let flight = ScanFlight<Int>(), paused = PausedScan()
        let reached = expectation(description: "first scan paused")
        let first = flight.task { await paused.run(reached) }
        await fulfillment(of: [reached], timeout: 2)
        let second = flight.task { XCTFail("overlapping scan ran a second operation"); return 2 }
        paused.finish(1)
        let firstValue = try await first.value, secondValue = try await second.value
        XCTAssertEqual(firstValue, 1); XCTAssertEqual(secondValue, 1)
    }
    func testOldCompletionCannotClearReplacementScanAfterCancellation() async throws {
        let flight = ScanFlight<Int>(), old = PausedScan(), replacement = PausedScan()
        let oldReached = expectation(description: "old scan paused")
        let oldTask = flight.task { await old.run(oldReached) }
        await fulfillment(of: [oldReached], timeout: 2)
        flight.cancel()
        let newReached = expectation(description: "replacement scan paused")
        let newTask = flight.task { await replacement.run(newReached) }
        await fulfillment(of: [newReached], timeout: 2)
        old.finish(1)
        _ = try await oldTask.value
        let joining = flight.task { XCTFail("old completion detached replacement scan"); return 3 }
        replacement.finish(2)
        let newValue = try await newTask.value, joinedValue = try await joining.value
        XCTAssertEqual(newValue, 2); XCTAssertEqual(joinedValue, 2)
    }
    func testQueuedScreenEnableCannotOverrideStopOrClearedThreat() {
        let state = ScreenState()
        let oldScan = state.update(true)
        let stop = state.update(false)
        var applied: [Bool] = []
        state.apply(stop) { applied.append($0) }
        state.apply(oldScan) { applied.append($0) }
        XCTAssertEqual(applied, [false])
    }
    func testQueuedScreenDisableCannotOverrideNewSensitiveScreenState() {
        let state = ScreenState()
        let oldScan = state.update(false)
        let sensitive = state.update(true)
        var applied: [Bool] = []
        state.apply(oldScan) { applied.append($0) }
        state.apply(sensitive) { applied.append($0) }
        XCTAssertEqual(applied, [true])
    }
}
