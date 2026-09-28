import XCTest
@testable import RaspCore

final class StartupStateTests: XCTestCase {
    func testInitialScanFailureNeverEnablesTrustAndAllowsCleanRetry() {
        var state = StartupState()
        state.begin(1)
        XCTAssertTrue(state.scanningAllowed)
        XCTAssertFalse(state.started)
        XCTAssertTrue(state.fail(1))
        XCTAssertFalse(state.started)
        XCTAssertFalse(state.scanningAllowed)
        state.begin(2)
        XCTAssertTrue(state.complete(2))
        XCTAssertTrue(state.started)
    }
    func testOldInitialScanFailureCannotStopOrActivateReplacementStartup() {
        var state = StartupState()
        state.begin(1)
        state.stop()
        state.begin(2)
        XCTAssertFalse(state.fail(1))
        XCTAssertFalse(state.complete(1))
        XCTAssertTrue(state.scanningAllowed)
        XCTAssertFalse(state.started)
        XCTAssertTrue(state.complete(2))
        XCTAssertFalse(state.fail(1))
        XCTAssertTrue(state.started)
    }
    func testStoppedInitialScanCannotReactivateProtection() {
        var state = StartupState()
        state.begin(1)
        state.stop()
        XCTAssertFalse(state.complete(1))
        XCTAssertFalse(state.fail(1))
        XCTAssertFalse(state.started)
        XCTAssertFalse(state.scanningAllowed)
    }
}
