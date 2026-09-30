/// Actor-owned startup state: initial scanning is allowed before trust is enabled.
struct StartupState {
    private(set) var started = false
    private var pendingGeneration: Int?
    var scanningAllowed: Bool { started || pendingGeneration != nil }

    mutating func begin(_ generation: Int) { started = false; pendingGeneration = generation }
    mutating func complete(_ generation: Int) -> Bool {
        guard pendingGeneration == generation else { return false }
        started = true; pendingGeneration = nil
        return true
    }
    mutating func fail(_ generation: Int) -> Bool {
        guard pendingGeneration == generation else { return false }
        stop()
        return true
    }
    mutating func stop() { started = false; pendingGeneration = nil }
    mutating func activate() { started = true; pendingGeneration = nil }
}
