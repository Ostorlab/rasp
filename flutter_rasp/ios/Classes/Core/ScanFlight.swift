import Foundation

/// Coalesces overlapping scans; cancellation also detaches the old generation.
final class ScanFlight<Value> {
    private let lock = NSLock()
    private var pending: (id: UUID, generation: Int, task: Task<Value, Error>)?

    func task(generation: Int = 0, _ operation: @escaping () async throws -> Value) -> Task<Value, Error> {
        lock.lock(); defer { lock.unlock() }
        if let pending, pending.generation == generation { return pending.task }
        pending?.task.cancel()
        let id = UUID()
        let task = Task {
            defer { self.finish(id) }
            try Task.checkCancellation()
            return try await operation()
        }
        pending = (id, generation, task)
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
