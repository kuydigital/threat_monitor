// THREAT MONITOR for macOS - official levels (v4.0)
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// WAR, CYB and BIO start from an authority's own rating: INFORM Severity
// (conflict crises rated Very High, compared with INFORM's record since
// 2020), CISA (exploited vulnerabilities and joint advisories) and CDC + WHO
// (travel health notices, public health emergencies). The news then moves
// that by at most 15 points either way. Same rules as threat_monitor.py.
//
// INFORM data: CC BY 4.0 - "INFORM Severity Index", https://drmkc.jrc.ec.europa.eu/inform-index

import Compression
import Foundation

enum Official {
    /// Python: with_pulse() - the official score moved by the news.
    static func withPulse(_ official: Int, _ news: Int) -> (value: Int, pulse: Double) {
        let pulse = max(-TM.pulseMax, min(TM.pulseMax, (Double(news) - TM.normalLevel) * TM.pulseShare))
        return (max(0, min(100, Py.round(Double(official) + pulse))), pulse)
    }

    /// Python: inform_median()
    static func informMedian() -> Double {
        let v = TM.informHistory.values.sorted()
        return (v[v.count / 2] + v[(v.count - 1) / 2]) / 2
    }

    /// Python: war_score_from_points() - median month -> ratio 1.0 (~35),
    /// worst month -> 3.0 (~73), best month -> 0.5.
    static func warScore(_ points: Double) -> Int {
        let values = Array(TM.informHistory.values)
        let med = informMedian()
        let lo = values.min() ?? 0, hi = values.max() ?? 0
        let ratio: Double
        if points >= med {
            ratio = 1 + 2 * (points - med) / max(hi - med, 1e-9)
        } else {
            ratio = 1 - 0.5 * (med - points) / max(med - lo, 1e-9)
        }
        return Score.fromRatio(min(TM.ratioCap, max(0.0, ratio)))
    }

    /// Python: bio_official() - CDC notice points + PHEIC.
    static func bio(_ notices: [Notice], who: [Story]) -> (points: Double, stories: [Story], detail: String) {
        var major = 0.0, routine = 0.0
        for n in notices {
            let p = TM.cdcLevelPoints[n.level] ?? 0
            if n.level >= 3 { major += p } else { routine += p }
        }
        let pheic = who.contains { $0.pheic == true }
        let points = major + min(TM.cdcRoutineCap, routine) + (pheic ? TM.pheicPoints : 0)
        let stories = notices.filter { $0.level >= 3 }.map {
            Story(sev: 3.0 + Double($0.level), date: $0.date, title: "CDC Level \($0.level) travel notice: \($0.title)", source: "CDC")
        }
        let counts = [4, 3, 2, 1].compactMap { lv -> String? in
            let n = notices.filter { $0.level == lv }.count
            return n > 0 ? "Level \(lv) x\(n)" : nil
        }
        let detail = counts.joined(separator: ", ")
            + (pheic ? "; WHO: a PHEIC is in force" : "; WHO: no PHEIC named in the last 30 days")
        return (points, stories, detail)
    }

    /// Python: cyb_official() - CISA points.
    static func cyb(kev: [Story], advisories: [Story]) -> (points: Double, stories: [Story], detail: String) {
        let ransomware = kev.filter { $0.sev > 3.0 }.count
        let points = Double(kev.count) * TM.kevPoints + Double(ransomware) * TM.kevRansomwarePoints
            + Double(advisories.count) * TM.advisoryPoints
        let detail = "\(kev.count) exploited vulnerabilities added in \(Int(TM.kevWindowDays)) days (\(ransomware) used by ransomware), "
            + "\(advisories.count) joint \(advisories.count == 1 ? "advisory" : "advisories") in \(Int(TM.advisoryWindowDays)) days"
        return (points, kev + advisories, detail)
    }

    /// Python's f"{x:g}" for the small numbers shown here.
    static func g(_ x: Double) -> String {
        x == x.rounded() && abs(x) < 1e15 ? String(Int(x)) : String(x)
    }
}

// ---- INFORM Severity: a monthly Excel workbook ---------------------------------------
/// The few parts of a .zip file an .xlsx workbook needs (stored or deflated entries).
struct ZipArchive {
    private let data: Data
    private var entries: [String: (method: UInt16, size: Int, compressed: Int, offset: Int)] = [:]

    init(_ data: Data) throws {
        self.data = data
        let bytes = [UInt8](data)
        func u16(_ i: Int) -> Int { Int(bytes[i]) | Int(bytes[i + 1]) << 8 }
        func u32(_ i: Int) -> Int { u16(i) | u16(i + 2) << 16 }
        guard bytes.count >= 22 else { throw TMError("not a zip file") }
        var eocd = -1
        var i = bytes.count - 22
        while i >= max(0, bytes.count - 65_557) {
            if bytes[i] == 0x50 && bytes[i + 1] == 0x4B && bytes[i + 2] == 5 && bytes[i + 3] == 6 { eocd = i; break }
            i -= 1
        }
        guard eocd >= 0 else { throw TMError("File is not a zip file") }
        var p = u32(eocd + 16)
        for _ in 0..<u16(eocd + 10) {
            guard p + 46 <= bytes.count, u32(p) == 0x0201_4B50 else { throw TMError("bad zip directory") }
            let nameLen = u16(p + 28), extraLen = u16(p + 30), commentLen = u16(p + 32)
            guard p + 46 + nameLen <= bytes.count else { throw TMError("bad zip directory") }
            let name = String(decoding: bytes[(p + 46)..<(p + 46 + nameLen)], as: UTF8.self)
            entries[name] = (UInt16(u16(p + 10)), u32(p + 24), u32(p + 20), u32(p + 42))
            p += 46 + nameLen + extraLen + commentLen
        }
    }

    var names: [String] { Array(entries.keys) }

    func read(_ name: String) throws -> Data {
        guard let e = entries[name] else { throw TMError("There is no item named '\(name)' in the archive") }
        let bytes = data
        func u16(_ i: Int) -> Int { Int(bytes[bytes.startIndex + i]) | Int(bytes[bytes.startIndex + i + 1]) << 8 }
        guard e.offset + 30 <= bytes.count else { throw TMError("bad zip entry \(name)") }
        let start = e.offset + 30 + u16(e.offset + 26) + u16(e.offset + 28)
        guard start + e.compressed <= bytes.count else { throw TMError("bad zip entry \(name)") }
        let raw = bytes.subdata(in: (bytes.startIndex + start)..<(bytes.startIndex + start + e.compressed))
        if e.method == 0 { return raw }
        guard e.method == 8 else { throw TMError("unsupported zip compression in \(name)") }
        var out = Data(count: e.size)
        let written = out.withUnsafeMutableBytes { dst -> Int in
            raw.withUnsafeBytes { src -> Int in
                guard let d = dst.bindMemory(to: UInt8.self).baseAddress,
                      let s = src.bindMemory(to: UInt8.self).baseAddress else { return 0 }
                return compression_decode_buffer(d, e.size, s, raw.count, nil, COMPRESSION_ZLIB)
            }
        }
        guard written == e.size else { throw TMError("could not unpack \(name)") }
        return out
    }
}

/// Collects elements of an Office XML part.
private final class OfficeXML: NSObject, XMLParserDelegate {
    enum Mode { case sheets, rels, shared, cells }
    let mode: Mode
    let sharedIn: [String]
    var sheets: [(name: String, rid: String)] = []
    var rels: [String: String] = [:]
    var shared: [String] = []
    var rows: [[String?]] = []
    private var text = ""
    private var inText = false
    private var cellRef = "", cellType = ""
    private var cellValue: String?
    private var row: [Int: String]?

    init(_ mode: Mode, shared: [String] = []) {
        self.mode = mode
        sharedIn = shared
    }

    static func parse(_ data: Data, _ mode: Mode, shared: [String] = []) throws -> OfficeXML {
        let d = OfficeXML(mode, shared: shared)
        let p = XMLParser(data: data)
        p.shouldProcessNamespaces = true
        p.shouldReportNamespacePrefixes = false
        p.shouldResolveExternalEntities = false
        p.delegate = d
        if !p.parse() { throw TMError("bad workbook XML (\(p.parserError?.localizedDescription ?? "unknown"))") }
        return d
    }

    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                qualifiedName: String?, attributes a: [String: String] = [:]) {
        switch (mode, name) {
        case (.sheets, "sheet"):
            // with namespaces on, "r:id" may arrive as "r:id" or "id"
            let rid = a["r:id"] ?? a.first { $0.key.hasSuffix(":id") }?.value ?? a["id"] ?? ""
            sheets.append((a["name"] ?? "", rid))
        case (.rels, "Relationship"):
            rels[a["Id"] ?? ""] = a["Target"] ?? ""
        case (.shared, "si"):
            text = ""
        case (.shared, "t"):
            inText = true
        case (.cells, "row"):
            row = [:]
        case (.cells, "c"):
            cellRef = a["r"] ?? ""
            cellType = a["t"] ?? ""
            cellValue = nil
        case (.cells, "v"):
            inText = true
            cellValue = cellValue ?? ""
        case (.cells, "t") where cellType == "inlineStr":
            inText = true
            cellValue = cellValue ?? ""
        default:
            break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard inText else { return }
        if mode == .shared { text += string } else { cellValue = (cellValue ?? "") + string }
    }

    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        switch (mode, name) {
        case (.shared, "si"):
            shared.append(text)
        case (_, "t"), (_, "v"):
            inText = false
        case (.cells, "c"):
            var col = 0
            for ch in cellRef.unicodeScalars {
                guard ch.value >= 65 && ch.value <= 90 else { break }
                col = col * 26 + Int(ch.value) - 64
            }
            var value = cellValue
            if cellType == "s", let v = value {
                guard let i = Int(v), i >= 0, i < sharedIn.count else { break }
                value = sharedIn[i]
            }
            row?[col - 1] = value
            if value == nil { row?[col - 1] = "\u{0}" }        // present but empty, like Python's None
        case (.cells, "row"):
            if let r = row, !r.isEmpty {
                let width = (r.keys.max() ?? -1) + 1
                rows.append((0..<width).map { i in
                    guard let v = r[i], v != "\u{0}" else { return nil }
                    return v
                })
            }
            row = nil
        default:
            break
        }
    }
}

enum Inform {
    static let linkRx = Rx(#"href="([^"]*InfoRM/Severity/(\d{4})/([^"/]*)\.xlsx)""#, ci: true)
    static let conflictRx = Rx("conflict|violence|complex crisis", ci: true)
    static let releaseRx = Rx(#"Release:\s*(?:\d+\s+)?([A-Za-z]+ \d{4})"#)
    static let crisisIdRx = Rx(#"^[A-Z]{3}\d{3}$"#)

    /// Python: xlsx_rows() - rows of the first sheet whose name matches (nil = empty cell).
    static func rows(_ data: Data, sheet pattern: String) throws -> [[String?]] {
        let zip = try ZipArchive(data)
        let rels = try OfficeXML.parse(try zip.read("xl/_rels/workbook.xml.rels"), .rels).rels
        let rx = Rx(pattern, ci: true)
        guard let sheet = try OfficeXML.parse(try zip.read("xl/workbook.xml"), .sheets).sheets.first(where: { rx.search($0.name) }),
              var target = rels[sheet.rid] else { throw TMError("no sheet matching \(pattern)") }
        while target.hasPrefix("/") { target.removeFirst() }
        if !target.hasPrefix("xl/") { target = "xl/" + target }
        var shared: [String] = []
        if zip.names.contains("xl/sharedStrings.xml") {
            shared = try OfficeXML.parse(try zip.read("xl/sharedStrings.xml"), .shared).shared
        }
        return try OfficeXML.parse(try zip.read(target), .cells, shared: shared).rows
    }

    /// Python: inform_points() - (release "Month YYYY", Very High conflict crises).
    static func points(_ rows: [[String?]]) throws -> (release: String, points: Double) {
        let first = (rows.first?.first ?? nil) ?? ""
        let ns = first as NSString
        guard let m = releaseRx.matches(first).first, let release = Rx.group(m, 1, ns) else {
            throw TMError("INFORM workbook has no release date")
        }
        let header = rows.count > 1 ? rows[1].map { ($0 ?? "").uppercased() } : []
        guard let drivers = header.firstIndex(where: { $0 == "DRIVERS" || $0 == "TYPE OF CRISIS" }),
              let category = header.firstIndex(of: "INFORM SEVERITY CATEGORY") else {
            throw TMError("INFORM workbook columns not found")
        }
        var veryHigh = 0
        for r in rows.dropFirst(4) {
            guard r.count > category, let id = r[1], crisisIdRx.search(id) else { continue }
            guard conflictRx.search((drivers < r.count ? r[drivers] : nil) ?? "") else { continue }
            guard let v = r[category].flatMap({ Double($0.trimmingCharacters(in: .whitespaces)) }), v.isFinite else { continue }
            if Int(v) == 5 { veryHigh += 1 }
        }
        if veryHigh == 0 { throw TMError("no Very High conflict crises in the INFORM workbook") }
        return (release, Double(veryHigh))
    }

    /// Python: inform_release_age_days()
    static func ageDays(_ release: String, now: Date) -> Int? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = Dates.utc
        f.dateFormat = "MMMM yyyy"
        guard let d = f.date(from: release) else { return nil }
        return Int(floor(now.timeIntervalSince(d) / 86400))
    }

    /// Newest two workbook links on the INFORM page, newest first.
    static func links(_ page: String) -> [URL] {
        let ns = page as NSString
        let found = linkRx.matches(page).compactMap { m -> (String, String, String)? in
            guard let href = Rx.group(m, 1, ns), let year = Rx.group(m, 2, ns), let name = Rx.group(m, 3, ns) else { return nil }
            return (href, year, String(name.prefix(6)))
        }
        // like Python's sorted(): stable, by (year, first 6 characters of the name)
        let sorted = found.enumerated().sorted { a, b in
            (a.element.1, a.element.2, a.offset) < (b.element.1, b.element.2, b.offset)
        }.map { $0.element.0 }
        guard let base = URL(string: TM.informPage) else { return [] }
        return sorted.suffix(2).reversed().compactMap {
            URL(string: HTMLText.unescape($0).replacingOccurrences(of: " ", with: "%20"), relativeTo: base)?.absoluteURL
        }
    }
}

/// The last INFORM result (inform_cache.json, the same file as the Python version's).
struct InformCache: Codable {
    var url: String
    var release: String
    var points: Double
    var checked: Double?
}

/// Keeps the INFORM result and refreshes it in the background: the workbook
/// is ~2 MB from a slow server, so it never holds up a sync.
final class InformStore {
    let file: URL?
    private let lock = NSLock()
    private var busy = false
    private var retryAt = 0.0
    private var memory: InformCache?
    private let queue = DispatchQueue(label: "com.kuydigital.ThreatMonitor.inform", qos: .utility)
    /// Called after a new release was read, so WAR can be scored with it straight away.
    var onNewResult: (() -> Void)?

    init(file: URL?) { self.file = file }

    func load() -> InformCache? {
        lock.lock()
        defer { lock.unlock() }
        if let file = file, let data = try? Data(contentsOf: file),
           let c = try? JSONDecoder().decode(InformCache.self, from: data), !c.release.isEmpty {
            memory = c
        }
        return memory
    }

    func store(_ c: InformCache) {
        lock.lock()
        memory = c
        lock.unlock()
        guard let file = file else { return }
        do {
            try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(c).write(to: file, options: .atomic)
        } catch {
            tmLog("WARN", "could not save \(file.lastPathComponent): \(error.localizedDescription)")
        }
    }

    var isBusy: Bool {
        lock.lock()
        defer { lock.unlock() }
        return busy
    }

    /// Python: war_official() - (score, details) from the cached result;
    /// starts a background refresh when one is due.
    func war(now: Date, refresh: Bool = true) -> (score: Int, detail: String)? {
        let cached = load()
        let due = cached == nil || wallNow() - (cached?.checked ?? 0) > TM.informRefreshDays * 86400
        if refresh && due { startRefresh() }
        guard let c = cached, let age = Inform.ageDays(c.release, now: now), age <= TM.informMaxAgeDays else { return nil }
        let hist = TM.informHistory.values
        return (Official.warScore(c.points),
                "INFORM Severity \(c.release): \(Official.g(c.points)) Very High conflict crises "
                + "(record since 2020: median \(Official.g(Official.informMedian())), worst \(Official.g(hist.max() ?? 0)))")
    }

    func startRefresh() {
        lock.lock()
        let start = !busy && wallNow() >= retryAt
        if start { busy = true }
        lock.unlock()
        if start { queue.async { self.refresh() } }
    }

    private func get(_ session: URLSession, _ url: URL) throws -> Data {
        var req = URLRequest(url: url)
        req.setValue(TM.informUserAgent, forHTTPHeaderField: "User-Agent")
        var result: Result<Data, TMError> = .failure(TMError("no answer"))
        let done = DispatchSemaphore(value: 0)
        session.dataTask(with: req) { data, response, error in
            if let error = error {
                result = .failure(TMError(error.localizedDescription))
            } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                result = .failure(TMError("HTTP \(http.statusCode)"))
            } else {
                result = .success(data ?? Data())
            }
            done.signal()
        }.resume()
        if done.wait(timeout: .now() + TM.informTimeout * 3) == .timedOut { throw TMError("no answer") }
        return try result.get()
    }

    /// Python: inform_refresh()
    private func refresh() {
        defer {
            lock.lock()
            busy = false
            lock.unlock()
        }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = TM.informTimeout
        cfg.timeoutIntervalForResource = TM.informTimeout * 3
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.httpAdditionalHeaders = ["User-Agent": TM.informUserAgent]
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        do {
            guard let pageURL = URL(string: TM.informPage) else { throw TMError("bad address") }
            let page = String(decoding: try get(session, pageURL), as: UTF8.self)
            let links = Inform.links(page)
            if links.isEmpty { throw TMError("no workbook links on the INFORM page") }
            var cached = load()
            var found = false
            var new = false
            for url in links {
                if let c = cached, c.url == url.absoluteString {
                    found = true
                    break
                }
                do {
                    let r = try Inform.points(try Inform.rows(try get(session, url), sheet: "all crises"))
                    cached = InformCache(url: url.absoluteString, release: r.release, points: r.points, checked: nil)
                    tmLog("INFO", "INFORM Severity \(r.release): \(Official.g(r.points)) Very High conflict crises")
                    found = true
                    new = true
                    break
                } catch {
                    tmLog("WARN", "INFORM workbook \(url.lastPathComponent) unusable: \(error)")
                }
            }
            guard found, var c = cached else { throw TMError("the two newest INFORM workbooks are unusable") }
            c.checked = wallNow()
            store(c)
            if new { onNewResult?() }
        } catch {
            lock.lock()
            retryAt = wallNow() + TM.informRetryHours * 3600
            lock.unlock()
            tmLog("WARN", "INFORM Severity unavailable: \(error)")
        }
    }
}
