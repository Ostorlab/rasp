import Foundation

/** Extracts the complete DER SubjectPublicKeyInfo from a certificate, preserving RSA/EC algorithm parameters. */
enum CertificateSPKI {
    private struct Element { let tag: UInt8; let start: Int; let body: Int; let end: Int }
    private static func element(_ bytes: [UInt8], _ offset: Int, _ limit: Int) throws -> Element {
        guard offset >= 0, offset + 2 <= limit, limit <= bytes.count else { throw RaspError.invalid("truncated DER") }
        let tag = bytes[offset]
        var cursor = offset + 2, length = Int(bytes[offset + 1])
        if length & 128 != 0 {
            let count = length & 127
            guard count > 0, count <= 4, cursor + count <= limit else { throw RaspError.invalid("invalid DER length") }
            length = 0
            for _ in 0..<count { length = length * 256 + Int(bytes[cursor]); cursor += 1 }
        }
        guard length <= limit - cursor else { throw RaspError.invalid("DER length out of bounds") }
        return Element(tag: tag, start: offset, body: cursor, end: cursor + length)
    }
    static func extract(_ certificate: Data) throws -> Data {
        let bytes = Array(certificate)
        let outer = try element(bytes, 0, bytes.count)
        guard outer.tag == 0x30, outer.end == bytes.count else { throw RaspError.invalid("invalid certificate") }
        let tbs = try element(bytes, outer.body, outer.end)
        guard tbs.tag == 0x30 else { throw RaspError.invalid("invalid certificate body") }
        var field = try element(bytes, tbs.body, tbs.end)
        if field.tag == 0xa0 { field = try element(bytes, field.end, tbs.end) }
        for _ in 0..<5 { field = try element(bytes, field.end, tbs.end) }
        guard field.tag == 0x30 else { throw RaspError.invalid("invalid SPKI") }
        return Data(bytes[field.start..<field.end])
    }
}
