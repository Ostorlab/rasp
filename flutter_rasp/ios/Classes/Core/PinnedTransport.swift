#if canImport(UIKit)
import Foundation
import Security

final class PinnedTransport: NSObject, URLSessionDataDelegate {
    private let pins: [String: [String]]
    private var session: URLSession?
    private var completion: ((Result<[String: Any], Error>) -> Void)?
    private var response: HTTPURLResponse?
    private var received = Data()
    init(pins: [String: [String]]) { self.pins = pins; super.init() }

    func request(url: String, method: String, headers: [String: String], body: Data) async throws -> [String: Any] {
        guard let address = URL(string: url), address.scheme == "https", address.user == nil, address.password == nil,
              address.fragment == nil, let host = address.host?.lowercased(), let configured = pins[host], !configured.isEmpty,
              configured.allSatisfy({ Data(base64Encoded: $0.replacingOccurrences(of: "sha256/", with: ""))?.count == 32 }),
              body.count <= 4 * 1024 * 1024,
              ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].contains(method),
              !headers.keys.contains(where: { ["host", "content-length", "transfer-encoding", "connection"].contains($0.lowercased()) }) else {
            throw RaspError.invalid("pinned HTTPS request required")
        }
        var request = URLRequest(url: address, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = method
        request.httpBody = body.isEmpty ? nil : body
        request.allHTTPHeaderFields = headers
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForResource = 30
        return try await withCheckedThrowingContinuation { continuation in
            completion = { continuation.resume(with: $0) }
            let created = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
            session = created
            created.dataTask(with: request).resume()
        }
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let configured = pins[challenge.protectionSpace.host.lowercased()],
              SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil), let leaf = SecTrustGetCertificateAtIndex(trust, 0),
              let spki = try? CertificateSPKI.extract(SecCertificateCopyData(leaf) as Data) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        let actual = Wire.hash(spki).base64EncodedString()
        guard configured.contains(where: { $0.replacingOccurrences(of: "sha256/", with: "") == actual }) else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        self.response = response as? HTTPURLResponse
        completionHandler(response.expectedContentLength > 8 * 1024 * 1024 ? .cancel : .allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if received.count + data.count > 8 * 1024 * 1024 { dataTask.cancel(); return }
        received.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        defer { completion = nil; self.session = nil; session.invalidateAndCancel() }
        if let error = error { completion?(.failure(error)); return }
        guard let response = response else { completion?(.failure(RaspError.invalid("missing HTTP response"))); return }
        var headers: [String: String] = [:]
        for (name, value) in response.allHeaderFields { headers[String(describing: name)] = String(describing: value) }
        completion?(.success(["status": response.statusCode, "headers": headers, "body": received]))
    }
}
#endif
