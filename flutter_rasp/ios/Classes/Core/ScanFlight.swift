import Foundation

/// Coalesces overlapping scans; cancellation also detaches the old generation.
final class ScanFlight<Value> {
    private let lock = NSLock()
    private var pending: (id: UUID, task: Task<Value, Error>)?

    func task(_ operation: @escaping () async throws -> Value) -> Task<Value, Error> {
        lock.lock(); defer { lock.unlock() }
        if let pending { return pending.task }
        let id = UUID()
        let task = Task {
            defer { self.finish(id) }
            try Task.checkCancellation()
            return try await operation()
        }
        pending = (id, task)
        return task
    }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        pending?.task.cancel()
        pending = nil
    }
    private func finish(_ id: UUID) {
        lock.lock(); defer { lock.unlock() }
        if pending?.id == id { pending = nil }
    }
}
