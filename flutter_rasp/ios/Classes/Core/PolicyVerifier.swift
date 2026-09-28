import Foundation
import CoreFoundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

struct PolicyVerifier {
    let keys: [String: String]
    let tenant: String
    let app: String
    struct Verified { let revision: Int64; let expiresAt: Int64; let config: [String: Any] }
    func verify(_ envelope: [String: Any], revision: Int64, now: Int64, cached: Bool = false) throws -> Verified {
        guard let kid = envelope["kid"] as? String, let encodedKey = keys[kid], let keyData = Data(base64Encoded: encodedKey),
              let encodedPayload = envelope["payload"] as? String, encodedPayload.count <= 131072,
              let encodedSignature = envelope["signature"] as? String else { throw RaspError.invalid("invalid policy envelope or unknown key") }
        let payload = try Wire.decodeURL(encodedPayload)
        let key = try P256.Signing.PublicKey(derRepresentation: keyData)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Wire.decodeURL(encodedSignature))
        guard key.isValidSignature(signature, for: payload),
              let value = try JSONSerialization.jsonObject(with: payload) as? [String: Any],
              value["tenantId"] as? String == tenant, value["appId"] as? String == app,
              let config = value["config"] as? [String: Any] else { throw RaspError.invalid("invalid policy signature or audience") }
        func integer(_ field: String) throws -> Int64 {
            guard let number = value[field] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                  !["d", "f"].contains(String(cString: number.objCType)) else { throw RaspError.invalid("policy integer required") }
            return number.int64Value
        }
        let next = try integer("revision"), issued = try integer("issuedAt"), expiry = try integer("expiresAt")
        guard next > 0, next > revision || (cached && next == revision), issued >= 0, issued <= now + 60,
              expiry > issued, cached || expiry > now else { throw RaspError.invalid("policy expired, future-dated or rollback") }
        let allowed: Set<String> = ["policy", "checkIntervalSeconds", "accessibilityAllowlist", "pins", "wipeOnThreats", "reactionDelayMillis"]
        guard Set(config.keys).isSubset(of: allowed) else { throw RaspError.invalid("unsupported policy field") }
        return Verified(revision: next, expiresAt: expiry, config: config)
    }
}
