import Foundation

/// Version 1 uses fixed AES-256-GCM framing; existing files retain this format.
enum SecureStoreEnvelope {
    static let version: UInt8 = 1
    static let dataKeyLength = 32
    static let nonceLength = 12
    static let tagLength = 16
    static let wrappedKeyLength = nonceLength + dataKeyLength + tagLength
    static let payloadOffset = 1 + wrappedKeyLength
    static let minimumLength = payloadOffset + nonceLength + tagLength
    static let maximumValueLength = 4 * 1024 * 1024
    static let maximumLength = maximumValueLength + minimumLength

    static func encode(wrappedKey: Data, payload: Data) throws -> Data {
        guard wrappedKey.count == wrappedKeyLength,
              payload.count >= nonceLength + tagLength,
              payload.count <= maximumValueLength + nonceLength + tagLength else {
            throw RaspError.invalid("invalid GCM framing")
        }
        return Data([version]) + wrappedKey + payload
    }
    static func decode(_ bytes: Data) throws -> (wrappedKey: Data, payload: Data) {
        guard bytes.count >= minimumLength, bytes.count <= maximumLength else { throw RaspError.invalid("invalid store length") }
        guard bytes.first == version else { throw RaspError.invalid("invalid store version") }
        return (bytes.subdata(in: 1..<payloadOffset), bytes.subdata(in: payloadOffset..<bytes.count))
    }
}
