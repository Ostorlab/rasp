import Foundation

struct IntegrityRegion: Codable {
    let path: String
    let offset: UInt64
    let length: Int
    let sha256: String
}

struct BundleIntegrity {
    struct Measurement { let root: Data; let matches: Bool }
    static func measure(root: URL, regions: [IntegrityRegion]) throws -> Measurement {
        guard !regions.isEmpty, regions.count <= 512 else { throw RaspError.invalid("integrity regions required") }
        let prefix = root.resolvingSymlinksInPath().standardizedFileURL.path + "/"
        var canonical = "rasp-ios-integrity-1\n"
        var matches = true
        for region in regions.sorted(by: { ($0.path, $0.offset) < ($1.path, $1.offset) }) {
            let file = root.appendingPathComponent(region.path).resolvingSymlinksInPath().standardizedFileURL
            guard file.path.hasPrefix(prefix), !region.path.contains("\n"), region.length > 0, region.length <= 16 * 1024 * 1024,
                  region.sha256.count == 64 else { throw RaspError.invalid("invalid integrity region") }
            let handle = try FileHandle(forReadingFrom: file)
            defer { try? handle.close() }
            try handle.seek(toOffset: region.offset)
            let bytes = handle.readData(ofLength: region.length)
            guard bytes.count == region.length else { throw RaspError.invalid("truncated integrity region") }
            let digest = Wire.hex(Wire.hash(bytes))
            matches = matches && digest == region.sha256.lowercased()
            canonical += "\(region.path)\n\(region.offset)\n\(region.length)\n\(digest)\n"
        }
        return Measurement(root: Wire.hash(Data(canonical.utf8)), matches: matches)
    }
}
