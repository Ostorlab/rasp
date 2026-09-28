#if canImport(UIKit)
import Foundation
import Darwin
import MachO

struct IOSDetectors {
    static func signal(_ threat: String, _ detector: String, _ confidence: Int, _ evidence: String) -> [String: Any] {
        ["threat": threat, "detector": detector, "confidence": confidence, "evidence": evidence]
    }
    static func scan(expectedBundle: String?) -> [[String: Any]] {
        var signals: [[String: Any]] = []
        #if targetEnvironment(simulator)
        signals.append(signal("emulator", "ios.simulator", 100, "simulator build target"))
        #else
        let artifacts = ["/Applications/Cydia.app", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/var/jb", "/usr/sbin/sshd", "/etc/apt"]
        if let path = artifacts.first(where: { FileManager.default.fileExists(atPath: $0) }) {
            signals.append(signal("root", "ios.jailbreak_artifact", 85, path))
        }
        let probe = URL(fileURLWithPath: "/private/rasp-probe-\(UUID().uuidString)")
        do {
            try Data([0]).write(to: probe, options: .withoutOverwriting)
            try? FileManager.default.removeItem(at: probe)
            signals.append(signal("root", "ios.sandbox_escape", 95, "write outside application sandbox succeeded"))
        } catch { /* Expected on a sandboxed device. */ }
        #endif
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let status = mib.withUnsafeMutableBufferPointer { sysctl($0.baseAddress, u_int($0.count), &info, &size, nil, 0) }
        if status == 0 {
            if info.kp_proc.p_flag & P_TRACED != 0 { signals.append(signal("debugger", "ios.traced", 95, "process traced")) }
        } else { signals.append(signal("detectorFailure", "ios.process_status", 60, "sysctl failed")) }
        for index in 0..<_dyld_image_count() {
            guard let pointer = _dyld_get_image_name(index) else { continue }
            let name = String(cString: pointer).lowercased()
            if ["frida", "substrate", "libhooker", "ellekit", "cycript"].contains(where: name.contains) {
                signals.append(signal("hooking", "ios.loaded_image", 90, name))
            }
        }
        if let expected = expectedBundle, expected != Bundle.main.bundleIdentifier {
            signals.append(signal("tamper", "ios.bundle_id", 95, Bundle.main.bundleIdentifier ?? "missing"))
        }
        if getenv("DYLD_INSERT_LIBRARIES") != nil { signals.append(signal("hooking", "ios.dyld_injection", 85, "DYLD_INSERT_LIBRARIES is set")) }
        return signals
    }
}
#endif
