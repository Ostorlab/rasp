import XCTest
@testable import RaspCore

final class ScanDecisionTests: XCTestCase {
    func testSecureScreenClearsAfterThreatDisappears() {
        let active = ScanDecision(signals: [["threat": "root"]], configured: [["type": "root", "reactions": ["secureScreen"]]], previous: [], sensitive: false)
        XCTAssertTrue(active.secureScreen)
        let cleared = ScanDecision(signals: [], configured: [], previous: active.threats, sensitive: false)
        XCTAssertFalse(cleared.secureScreen)
        XCTAssertTrue(ScanDecision(signals: [], configured: [], previous: [], sensitive: true).secureScreen)
    }

    func testNewThreatEventExcludesPersistentSignalsAndReactions() {
        let signals: [[String: Any]] = [["threat": "root", "id": "persistent"], ["threat": "debugger", "id": "new"]]
        let configured: [[String: Any]] = [["type": "root", "reactions": ["warnUser", "closeApp"]], ["type": "debugger", "reactions": ["report"]]]
        let decision = ScanDecision(signals: signals, configured: configured, previous: ["root"], sensitive: false)
        XCTAssertEqual(decision.newThreats, ["debugger"])
        XCTAssertEqual(decision.newReactions, ["report"])
        XCTAssertEqual(decision.newSignals.compactMap { $0["id"] as? String }, ["new"])
        XCTAssertEqual(decision.reactions, ["report", "warnUser", "closeApp"])
        let unchanged = ScanDecision(signals: signals, configured: configured, previous: decision.threats, sensitive: false)
        XCTAssertTrue(unchanged.newThreats.isEmpty)
        XCTAssertTrue(unchanged.newSignals.isEmpty)
        XCTAssertTrue(unchanged.newReactions.isEmpty)
    }
}
