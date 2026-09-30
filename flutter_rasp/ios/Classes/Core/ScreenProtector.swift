#if canImport(UIKit)
import UIKit

/** Obscures captured/background content using public APIs; does not promise screenshot prevention. */
@MainActor final class IOSScreenProtector {
    static let shared = IOSScreenProtector()
    private var enabled = false
    private var cover: UIView?
    private var observers: [NSObjectProtocol] = []
    private init() {
        for name in [UIApplication.willResignActiveNotification, UIApplication.didBecomeActiveNotification, UIScreen.capturedDidChangeNotification] {
            observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] notification in
                MainActor.assumeIsolated { self?.refresh(forceBackground: notification.name == UIApplication.willResignActiveNotification) }
            })
        }
    }
    func setEnabled(_ value: Bool) { enabled = value; refresh() }
    private func refresh(forceBackground: Bool = false) {
        guard enabled && (forceBackground || UIApplication.shared.applicationState != .active || UIScreen.main.isCaptured) else {
            cover?.removeFromSuperview(); cover = nil; return
        }
        guard cover == nil, let window = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
            .flatMap({ $0.windows }).first(where: { $0.isKeyWindow }) else { return }
        let overlay = UIView(frame: window.bounds)
        overlay.backgroundColor = .black
        overlay.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        overlay.isAccessibilityElement = true
        overlay.accessibilityLabel = "Protected content"
        window.addSubview(overlay); cover = overlay
    }
}
#endif
