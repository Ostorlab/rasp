import Foundation

/// Validates queued UI work against the latest desired state, including stop.
final class ScreenState {
    private let lock = NSLock()
    private var generation = 0
    private var enabled = false

    func update(_ value: Bool) -> Int {
        lock.lock(); defer { lock.unlock() }
        generation += 1
        enabled = value
        return generation
    }
    func apply(_ token: Int, _ action: (Bool) -> Void) {
        lock.lock(); defer { lock.unlock() }
        // Keep validation and the synchronous UI mutation atomic with update.
        if token == generation { action(enabled) }
    }
}
