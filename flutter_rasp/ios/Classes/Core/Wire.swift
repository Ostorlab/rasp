import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum RaspError: LocalizedError {
    case invalid(String)
    public var errorDescription: String? { if case let .invalid(message) = self { return message }; return nil }
}

enum Wire {
    static func hash(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    static func url(_ data: Data) -> String { data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "") }
    static func decodeURL(_ value: String) throws -> Data {
        let base64 = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let data = Data(base64Encoded: base64 + String(repeating: "=", count: (4 - base64.count % 4) % 4)) else { throw RaspError.invalid("invalid base64url") }
        return data
    }
    static func request(method: String, path: String, body: Data, timestamp: Int64, counter: Int64) -> Data {
        Data("rasp-req-1\n\(method.uppercased())\n\(path)\n\(url(hash(body)))\n\(timestamp)\n\(counter)".utf8)
    }
    static func token(nonce: String, mac: String, thumbprint: String) -> Data {
        Data("rasp-token-1\n\(nonce)\n\(mac)\n\(thumbprint)".utf8)
    }
}

final class SessionProof {
    private let key = P256.Signing.PrivateKey()
    private var counter: Int64 = 0
    var publicKey: String { key.publicKey.derRepresentation.base64EncodedString() }
    var thumbprint: String {
        let raw = key.publicKey.x963Representation
        let x = Wire.url(raw.subdata(in: 1..<33))
        let y = Wire.url(raw.subdata(in: 33..<65))
        return Wire.url(Wire.hash(Data("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}".utf8)))
    }
    func sign(method: String, path: String, body: Data, now: Int64) throws -> [String: Any] {
        guard counter < Int64.max else { throw RaspError.invalid("proof counter exhausted") }
        counter += 1
        let signature = try key.signature(for: Wire.request(method: method, path: path, body: body, timestamp: now, counter: counter))
        return ["key": publicKey, "sig": Wire.url(signature.rawRepresentation), "ts": now, "counter": counter]
    }
}
