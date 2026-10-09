// THREAT MONITOR for macOS - shared helpers
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// The Mac screensaver is a Swift port of threat_monitor.py. These helpers make
// Swift behave like the Python original where it matters for identical
// results: regular expressions, whitespace splitting, rounding, HTML text and
// dates. mac/Tests checks the port against the Python version.

import Foundation

/// A compiled regular expression that can never crash the screensaver: a
/// pattern that fails to compile is listed in `Rx.failed` (the tests check
/// that list is empty) and simply never matches.
final class Rx {
    let pattern: String
    let ci: Bool
    let re: NSRegularExpression?

    private static let lock = NSLock()
    private static var failedPatterns: [String] = []

    static var failed: [String] {
        lock.lock()
        defer { lock.unlock() }
        return failedPatterns
    }

    init(_ pattern: String, ci: Bool = false) {
        self.pattern = pattern
        self.ci = ci
        re = try? NSRegularExpression(pattern: pattern, options: ci ? [.caseInsensitive] : [])
        if re == nil {
            Rx.lock.lock()
            Rx.failedPatterns.append(pattern)
            Rx.lock.unlock()
        }
    }

    private func whole(_ s: String) -> NSRange {
        NSRange(location: 0, length: (s as NSString).length)
    }

    func search(_ s: String) -> Bool {
        guard let re = re else { return false }
        return re.firstMatch(in: s, options: [], range: whole(s)) != nil
    }

    func matches(_ s: String) -> [NSTextCheckingResult] {
        guard let re = re else { return [] }
        return re.matches(in: s, options: [], range: whole(s))
    }

    /// Python's re.sub with a replacement template ("$1" = group 1).
    func sub(_ s: String, _ template: String) -> String {
        guard let re = re else { return s }
        return re.stringByReplacingMatches(in: s, options: [], range: whole(s), withTemplate: template)
    }

    /// Python's re.sub with a function that builds each replacement.
    func sub(_ s: String, with replace: (NSTextCheckingResult, NSString) -> String) -> String {
        let ns = s as NSString
        var out = ""
        var last = 0
        for m in matches(s) {
            out += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            out += replace(m, ns)
            last = m.range.location + m.range.length
        }
        out += ns.substring(from: last)
        return out
    }

    /// Text of a capture group, or nil if the group did not take part.
    static func group(_ m: NSTextCheckingResult, _ i: Int, _ ns: NSString) -> String? {
        guard i < m.numberOfRanges else { return nil }
        let r = m.range(at: i)
        return r.location == NSNotFound ? nil : ns.substring(with: r)
    }
}

/// Python string behaviour (code points, not grapheme clusters).
enum Py {
    /// str.split() with no arguments.
    static func split(_ s: String) -> [String] {
        var parts: [String] = []
        var cur = String.UnicodeScalarView()
        for u in s.unicodeScalars {
            if u.properties.isWhitespace {
                if !cur.isEmpty {
                    parts.append(String(cur))
                    cur = String.UnicodeScalarView()
                }
            } else {
                cur.append(u)
            }
        }
        if !cur.isEmpty { parts.append(String(cur)) }
        return parts
    }

    /// " ".join(s.split())
    static func join(_ s: String) -> String {
        split(s).joined(separator: " ")
    }

    /// str.strip(chars) / lstrip / rstrip.
    static func strip(_ s: String, _ chars: String, left: Bool = true, right: Bool = true) -> String {
        let set = Set(chars.unicodeScalars)
        let scalars = Array(s.unicodeScalars)
        var start = 0
        var end = scalars.count
        if left { while start < end && set.contains(scalars[start]) { start += 1 } }
        if right { while end > start && set.contains(scalars[end - 1]) { end -= 1 } }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: scalars[start..<end])
        return String(out)
    }

    /// str.rstrip() with no arguments (whitespace).
    static func rstripSpace(_ s: String) -> String {
        let scalars = Array(s.unicodeScalars)
        var end = scalars.count
        while end > 0 && scalars[end - 1].properties.isWhitespace { end -= 1 }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: scalars[0..<end])
        return String(out)
    }

    /// len(s)
    static func len(_ s: String) -> Int {
        s.unicodeScalars.count
    }

    /// s.endswith(suffix), compared code point by code point.
    static func endsWith(_ s: String, _ suffix: String) -> Bool {
        let a = Array(s.unicodeScalars)
        let b = Array(suffix.unicodeScalars)
        return b.count <= a.count && Array(a[(a.count - b.count)...]) == b
    }

    /// s[:-n]
    static func dropLast(_ s: String, _ n: Int) -> String {
        let a = Array(s.unicodeScalars)
        var out = String.UnicodeScalarView()
        out.append(contentsOf: a[0..<max(0, a.count - n)])
        return String(out)
    }

    /// t[:1].upper() + t[1:]
    static func upperFirst(_ s: String) -> String {
        guard let first = s.unicodeScalars.first else { return s }
        var rest = String.UnicodeScalarView()
        rest.append(contentsOf: s.unicodeScalars.dropFirst())
        return String(first).uppercased() + String(rest)
    }

    /// int(round(x)) - Python rounds halves to the even number.
    static func round(_ x: Double) -> Int {
        guard x.isFinite else { return 0 }
        return Int(x.rounded(.toNearestOrEven))
    }
}

/// Text from feeds: tags removed, entities decoded, whitespace collapsed
/// (Python: " ".join(html.unescape(TAG_RE.sub(" ", text)).split())).
enum HTMLText {
    static let tag = Rx("<[^>]+>")
    static let entity = Rx("&(#[0-9]+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);")

    static func strip(_ s: String?) -> String {
        guard let s = s, !s.isEmpty else { return "" }
        return Py.join(unescape(tag.sub(s, " ")))
    }

    static func unescape(_ s: String) -> String {
        if !s.contains("&") { return s }
        return entity.sub(s) { m, ns in
            let whole = ns.substring(with: m.range)
            guard let body = Rx.group(m, 1, ns) else { return whole }
            if body.hasPrefix("#") {
                let hex = body.hasPrefix("#x") || body.hasPrefix("#X")
                let digits = String(body.dropFirst(hex ? 2 : 1))
                guard digits.count <= 8, let n = Int(digits, radix: hex ? 16 : 10) else { return "\u{FFFD}" }
                let code = cp1252[n] ?? n
                if code == 0 || code > 0x10FFFF || (0xD800...0xDFFF).contains(code) { return "\u{FFFD}" }
                guard let u = Unicode.Scalar(code) else { return "\u{FFFD}" }
                return String(Character(u))
            }
            return named[body] ?? whole
        }
    }

    /// Numeric references 0x80-0x9F mean Windows-1252 characters (as in Python).
    static let cp1252: [Int: Int] = [
        0x80: 0x20AC, 0x82: 0x201A, 0x83: 0x0192, 0x84: 0x201E, 0x85: 0x2026, 0x86: 0x2020,
        0x87: 0x2021, 0x88: 0x02C6, 0x89: 0x2030, 0x8A: 0x0160, 0x8B: 0x2039, 0x8C: 0x0152,
        0x8E: 0x017D, 0x91: 0x2018, 0x92: 0x2019, 0x93: 0x201C, 0x94: 0x201D, 0x95: 0x2022,
        0x96: 0x2013, 0x97: 0x2014, 0x98: 0x02DC, 0x99: 0x2122, 0x9A: 0x0161, 0x9B: 0x203A,
        0x9C: 0x0153, 0x9E: 0x017E, 0x9F: 0x0178,
    ]

    static let named: [String: String] = [
        "amp": "&", "lt": "<", "gt": ">", "quot": "\"", "apos": "'", "nbsp": "\u{00A0}",
        "ndash": "\u{2013}", "mdash": "\u{2014}", "lsquo": "\u{2018}", "rsquo": "\u{2019}",
        "sbquo": "\u{201A}", "ldquo": "\u{201C}", "rdquo": "\u{201D}", "bdquo": "\u{201E}",
        "hellip": "\u{2026}", "bull": "\u{2022}", "middot": "\u{00B7}", "copy": "\u{00A9}",
        "reg": "\u{00AE}", "trade": "\u{2122}", "deg": "\u{00B0}", "euro": "\u{20AC}",
        "pound": "\u{00A3}", "yen": "\u{00A5}", "cent": "\u{00A2}", "times": "\u{00D7}",
        "divide": "\u{00F7}", "laquo": "\u{00AB}", "raquo": "\u{00BB}", "lsaquo": "\u{2039}",
        "rsaquo": "\u{203A}", "prime": "\u{2032}", "Prime": "\u{2033}", "thinsp": "\u{2009}",
        "ensp": "\u{2002}", "emsp": "\u{2003}", "zwj": "\u{200D}", "zwnj": "\u{200C}",
        "lrm": "\u{200E}", "rlm": "\u{200F}", "shy": "\u{00AD}", "iexcl": "\u{00A1}",
        "iquest": "\u{00BF}", "ordm": "\u{00BA}", "ordf": "\u{00AA}", "frac12": "\u{00BD}",
        "frac14": "\u{00BC}", "frac34": "\u{00BE}", "sup2": "\u{00B2}", "sup3": "\u{00B3}",
        "minus": "\u{2212}", "plusmn": "\u{00B1}", "micro": "\u{00B5}", "para": "\u{00B6}",
        "sect": "\u{00A7}", "acute": "\u{00B4}", "uml": "\u{00A8}", "macr": "\u{00AF}",
        "aacute": "\u{00E1}", "Aacute": "\u{00C1}", "agrave": "\u{00E0}", "Agrave": "\u{00C0}",
        "acirc": "\u{00E2}", "Acirc": "\u{00C2}", "atilde": "\u{00E3}", "Atilde": "\u{00C3}",
        "auml": "\u{00E4}", "Auml": "\u{00C4}", "aring": "\u{00E5}", "Aring": "\u{00C5}",
        "aelig": "\u{00E6}", "AElig": "\u{00C6}", "ccedil": "\u{00E7}", "Ccedil": "\u{00C7}",
        "eacute": "\u{00E9}", "Eacute": "\u{00C9}", "egrave": "\u{00E8}", "Egrave": "\u{00C8}",
        "ecirc": "\u{00EA}", "Ecirc": "\u{00CA}", "euml": "\u{00EB}", "Euml": "\u{00CB}",
        "iacute": "\u{00ED}", "Iacute": "\u{00CD}", "igrave": "\u{00EC}", "Igrave": "\u{00CC}",
        "icirc": "\u{00EE}", "Icirc": "\u{00CE}", "iuml": "\u{00EF}", "Iuml": "\u{00CF}",
        "ntilde": "\u{00F1}", "Ntilde": "\u{00D1}", "oacute": "\u{00F3}", "Oacute": "\u{00D3}",
        "ograve": "\u{00F2}", "Ograve": "\u{00D2}", "ocirc": "\u{00F4}", "Ocirc": "\u{00D4}",
        "otilde": "\u{00F5}", "Otilde": "\u{00D5}", "ouml": "\u{00F6}", "Ouml": "\u{00D6}",
        "oslash": "\u{00F8}", "Oslash": "\u{00D8}", "uacute": "\u{00FA}", "Uacute": "\u{00DA}",
        "ugrave": "\u{00F9}", "Ugrave": "\u{00D9}", "ucirc": "\u{00FB}", "Ucirc": "\u{00DB}",
        "uuml": "\u{00FC}", "Uuml": "\u{00DC}", "yacute": "\u{00FD}", "Yacute": "\u{00DD}",
        "yuml": "\u{00FF}", "szlig": "\u{00DF}", "scaron": "\u{0161}", "Scaron": "\u{0160}",
        "zcaron": "\u{017E}", "Zcaron": "\u{017D}", "oelig": "\u{0153}", "OElig": "\u{0152}",
    ]
}

/// Dates in feeds: RFC 822 (RSS pubDate) and ISO 8601 (JSON APIs). Times
/// without a zone are UTC, as in the Python version.
enum Dates {
    static let utc = TimeZone(secondsFromGMT: 0) ?? TimeZone.current
    static let dayPrefix = Rx("^\\s*[A-Za-z]{2,9},\\s*")
    static let isoRx = Rx("^(\\d{4})-(\\d{1,2})-(\\d{1,2})(?:[T ](\\d{1,2}):(\\d{2})(?::(\\d{2})(?:[.,](\\d+))?)?)?\\s*(Z|[+-]\\d{2}(?::?\\d{2})?)?$", ci: true)
    static let ymdRx = Rx("^(\\d{4})-(\\d{1,2})-(\\d{1,2})$")

    private static let lock = NSLock()
    private static let rfcFormatters: [DateFormatter] = [
        "d MMM yyyy HH:mm:ss Z", "d MMM yyyy HH:mm:ss zzz", "d MMM yyyy HH:mm Z",
        "d MMM yyyy HH:mm zzz", "d MMM yyyy HH:mm:ss", "d MMM yyyy HH:mm",
    ].map { format in
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.timeZone = utc
        df.dateFormat = format
        return df
    }

    static var calendar: Calendar {
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = utc
        return cal
    }

    /// RSS pubDate, e.g. "Sat, 10 Oct 2026 12:34:56 GMT". The weekday is ignored.
    static func rfc822(_ text: String?) -> Date? {
        guard let raw = text?.trimmingCharacters(in: .whitespacesAndNewlines), !raw.isEmpty else { return nil }
        let s = dayPrefix.sub(raw, "")
        lock.lock()
        defer { lock.unlock() }
        for df in rfcFormatters {
            if let d = df.date(from: s) { return d }
        }
        return nil
    }

    /// ISO 8601, e.g. "2026-10-02T12:00:00Z", "2026-10-02T12:00:00.123+02:00".
    static func iso(_ text: String?) -> Date? {
        guard let s = text?.trimmingCharacters(in: .whitespacesAndNewlines),
              let m = isoRx.matches(s).first else { return nil }
        let ns = s as NSString
        func num(_ i: Int) -> Int? { Rx.group(m, i, ns).flatMap { Int($0) } }
        var c = DateComponents()
        c.year = num(1)
        c.month = num(2)
        c.day = num(3)
        c.hour = num(4) ?? 0
        c.minute = num(5) ?? 0
        c.second = num(6) ?? 0
        guard let month = c.month, (1...12).contains(month), let day = c.day, (1...31).contains(day),
              let hour = c.hour, hour < 24, var d = calendar.date(from: c) else { return nil }
        if let frac = Rx.group(m, 7, ns), let f = Double("0." + frac) {
            d = d.addingTimeInterval(f)
        }
        if let zone = Rx.group(m, 8, ns), zone.uppercased() != "Z" {
            let sign: Double = zone.hasPrefix("-") ? -1 : 1
            let digits = zone.dropFirst().replacingOccurrences(of: ":", with: "")
            let hh = Double(digits.prefix(2)) ?? 0
            let mm = digits.count > 2 ? (Double(digits.dropFirst(2)) ?? 0) : 0
            d = d.addingTimeInterval(-sign * (hh * 3600 + mm * 60))
        }
        return d
    }

    /// "2026-10-01" (CISA dateAdded) at midnight UTC.
    static func ymd(_ s: String) -> Date? {
        guard let m = ymdRx.matches(s).first else { return nil }
        let ns = s as NSString
        var c = DateComponents()
        c.year = Rx.group(m, 1, ns).flatMap { Int($0) }
        c.month = Rx.group(m, 2, ns).flatMap { Int($0) }
        c.day = Rx.group(m, 3, ns).flatMap { Int($0) }
        guard let month = c.month, (1...12).contains(month), let day = c.day, (1...31).contains(day) else { return nil }
        return calendar.date(from: c)
    }

    /// Midnight UTC of the day containing `d`.
    static func utcDay(_ d: Date) -> Date {
        calendar.startOfDay(for: d)
    }
}

/// "3h ago" etc. (Python: ago()).
func agoText(_ date: Date?, now: Date = Date()) -> String {
    guard let date = date else { return "" }
    let secs = now.timeIntervalSince(date)
    if secs < 90 { return "just now" }
    if secs < 3600 { return "\(Int(secs / 60))m ago" }
    if secs < 172800 { return "\(Int(secs / 3600))h ago" }
    return "\(Int(secs / 86400))d ago"
}

/// "mm:ss" for a number of seconds.
func mmss(_ secs: Double) -> String {
    let total = max(0, Int(secs.isFinite ? secs : 0))
    return String(format: "%02ld:%02ld", total / 60, total % 60)
}

/// Seconds on a clock that only moves forward and keeps counting while the
/// Mac sleeps (immune to clock changes).
func monotonicNow() -> Double {
    Double(clock_gettime_nsec_np(CLOCK_MONOTONIC)) / 1e9
}

func wallNow() -> Double {
    Date().timeIntervalSince1970
}

/// Log file (a screensaver has no console). Never raises.
final class Log {
    static let shared = Log()
    static let maxBytes = 512 * 1024

    private let lock = NSLock()
    private var fileURL: URL?
    private var echo = false
    private let fmt: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    func configure(file: URL?, echo: Bool) {
        lock.lock()
        fileURL = file
        self.echo = echo
        lock.unlock()
    }

    func write(_ level: String, _ msg: String) {
        lock.lock()
        defer { lock.unlock() }
        let line = "\(fmt.string(from: Date())) [\(level)] \(msg)\n"
        let data = Data(line.utf8)
        if echo { try? FileHandle.standardError.write(contentsOf: data) }
        guard let url = fileURL else { return }
        let fm = FileManager.default
        if let attrs = try? fm.attributesOfItem(atPath: url.path),
           let size = attrs[.size] as? NSNumber, size.intValue > Log.maxBytes {
            let old = url.appendingPathExtension("old")
            try? fm.removeItem(at: old)
            try? fm.moveItem(at: url, to: old)
        }
        if !fm.fileExists(atPath: url.path) {
            _ = fm.createFile(atPath: url.path, contents: nil)
        }
        if let h = try? FileHandle(forWritingTo: url) {
            _ = try? h.seekToEnd()
            try? h.write(contentsOf: data)
            try? h.close()
        }
    }
}

func tmLog(_ level: String, _ msg: String) {
    Log.shared.write(level, msg)
}

struct TMError: Error, CustomStringConvertible {
    let message: String
    init(_ message: String) { self.message = message }
    var description: String { message }
}
