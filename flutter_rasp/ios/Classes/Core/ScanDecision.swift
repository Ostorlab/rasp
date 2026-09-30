import Foundation

/** Separates the active scan state from the new-threat notification payload. */
struct ScanDecision {
    let threats: Set<String>
    let reactions: Set<String>
    let secureScreen: Bool
    let newThreats: Set<String>
    let newReactions: Set<String>
    let newSignals: [[String: Any]]

    init(signals: [[String: Any]], configured: [[String: Any]], previous: Set<String>, sensitive: Bool) {
        let activeThreats = Set(signals.compactMap { $0["threat"] as? String })
        let activeReactions = Set(configured.flatMap { $0["reactions"] as? [String] ?? [] })
        threats = activeThreats
        reactions = activeReactions
        secureScreen = sensitive || activeReactions.contains("secureScreen")
        let added = activeThreats.subtracting(previous)
        newThreats = added
        newSignals = signals.filter { ($0["threat"] as? String).map(added.contains) ?? false }
        newReactions = Set(configured.filter { ($0["type"] as? String).map(added.contains) ?? false }
            .flatMap { $0["reactions"] as? [String] ?? [] })
    }
}
