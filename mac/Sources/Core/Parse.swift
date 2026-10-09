// THREAT MONITOR for macOS - reading the sources
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor

import Foundation

/// One story in a news feed.
struct Item {
    var title: String
    var desc: String
    var date: Date?
    var source: String
}

/// A story that counts towards a score, with its severity.
struct Story {
    var sev: Double
    var date: Date?
    var title: String
    var source: String
}

/// RSS reader: the direct children of every <item>, keyed like Python's
/// ElementTree ("title", or "{namespace}name" for namespaced elements).
final class RSSParser: NSObject, XMLParserDelegate {
    private(set) var items: [[String: String]] = []
    private var depth = 0
    private var itemDepth: Int?
    private var current: [String: String] = [:]
    private var childKey: String?
    private var childText = ""

    static func parse(_ data: Data) throws -> [[String: String]] {
        let delegate = RSSParser()
        let parser = XMLParser(data: data)
        parser.shouldProcessNamespaces = true
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        if !parser.parse() {
            let reason = parser.parserError.map { "\($0.localizedDescription)" } ?? "unknown error"
            throw TMError("not valid RSS/XML (\(reason))")
        }
        return delegate.items
    }

    private func key(_ name: String, _ ns: String?) -> String {
        if let ns = ns, !ns.isEmpty { return "{\(ns)}\(name)" }
        return name
    }

    func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
        depth += 1
        let k = key(elementName, namespaceURI)
        if let d = itemDepth {
            if depth == d + 1 {
                childKey = k
                childText = ""
            }
        } else if k == "item" {
            itemDepth = depth
            current = [:]
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if childKey != nil, let d = itemDepth, depth == d + 1 {
            childText += string
        }
    }

    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        if childKey != nil, let d = itemDepth, depth == d + 1 {
            childText += String(decoding: CDATABlock, as: UTF8.self)
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?,
                qualifiedName qName: String?) {
        if let d = itemDepth {
            if depth == d + 1, let k = childKey {
                if current[k] == nil { current[k] = childText }   // like findtext(): the first one
                childKey = nil
            } else if depth == d {
                items.append(current)
                itemDepth = nil
            }
        }
        depth -= 1
    }
}

enum Parse {
    /// Python: fetch_rss_items()
    static func rssItems(_ data: Data, label: String) throws -> [Item] {
        var out: [Item] = []
        for raw in try RSSParser.parse(data) {
            var title = HTMLText.strip(raw["title"])
            let publisher = HTMLText.strip(raw["source"])          // Google gives the publisher
            let source = publisher.isEmpty ? label : publisher
            if !source.isEmpty && Py.endsWith(title, " - " + source) {
                title = Py.rstripSpace(Py.dropLast(title, Py.len(source) + 3))
            }
            if Py.len(title) < 10 { continue }
            out.append(Item(title: title, desc: HTMLText.strip(raw["description"]),
                            date: Dates.rfc822(raw["pubDate"]), source: source))
        }
        return out
    }

    private static func json(_ data: Data) throws -> [String: Any] {
        guard let obj = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            throw TMError("unexpected JSON")
        }
        return obj
    }

    private static func number(_ v: Any?) -> Double? {
        guard let n = v as? NSNumber else { return nil }
        return n.doubleValue
    }

    private static func text(_ v: Any?) -> String {
        guard let v = v, !(v is NSNull) else { return "" }
        if let s = v as? String { return s }
        return "\(v)"
    }

    /// Python: cisa_kev_stories() - vulnerabilities added in the last 7 days.
    static func kev(_ data: Data, now: Date) throws -> [Story] {
        let root = try json(data)
        let cutoff = Dates.utcDay(now.addingTimeInterval(-TM.kevWindowDays * 86400))
        var out: [Story] = []
        for case let v as [String: Any] in (root["vulnerabilities"] as? [Any]) ?? [] {
            guard let added = Dates.ymd(text(v["dateAdded"])), added >= cutoff else { continue }
            let ransomware = (v["knownRansomwareCampaignUse"] as? String) == "Known"
            let title = Py.strip("Actively exploited: \(text(v["cveID"])) \(text(v["vulnerabilityName"]))",
                                 " \t\n\r")
            out.append(Story(sev: 3.0 + (ransomware ? 2.0 : 0.0), date: added, title: title, source: "CISA"))
        }
        return out
    }

    /// Python: who_don_stories() - one entry per outbreak, the latest notice.
    static func who(_ data: Data, now: Date) throws -> [Story] {
        let root = try json(data)
        let cutoff = now.addingTimeInterval(-TM.donWindowDays * 86400)
        var order: [String] = []
        var latest: [String: Story] = [:]
        for case let v as [String: Any] in (root["value"] as? [Any]) ?? [] {
            let title = HTMLText.strip(v["Title"] as? String)
            guard let d = Dates.iso(v["PublicationDate"] as? String), d >= cutoff, !title.isEmpty else { continue }
            if let old = latest[title] {
                if let od = old.date, d > od {
                    latest[title] = Story(sev: 5.0, date: d, title: "WHO outbreak notice: \(title)", source: "WHO")
                }
            } else {
                order.append(title)
                latest[title] = Story(sev: 5.0, date: d, title: "WHO outbreak notice: \(title)", source: "WHO")
            }
        }
        return order.compactMap { latest[$0] }
    }

    /// Python: gdacs_stories() - current GDACS alerts.
    static func gdacs(_ data: Data, now: Date) throws -> [Story] {
        let ns = "{\(TM.gdacsNS)}"
        var out: [Story] = []
        for raw in try RSSParser.parse(data) {
            func field(_ name: String) -> String {
                (raw[ns + name] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            }
            if field("iscurrent").lowercased() != "true" { continue }
            let level = field("alertlevel").lowercased()
            let etype = field("eventtype").uppercased()
            let sev: Double
            if let v = TM.gdacsLevel[level] {
                sev = v
            } else if level == "green" {
                sev = TM.gdacsGreenByType[etype] ?? 0.5
            } else {
                continue
            }
            let full = HTMLText.strip(raw["title"])
            let title = Text.tidyGdacsTitle(full.components(separatedBy: ". ").first ?? full)
            let date = Dates.rfc822(raw[ns + "datemodified"]) ?? Dates.rfc822(raw["pubDate"]) ?? now
            out.append(Story(sev: sev, date: date, title: title, source: "GDACS"))
        }
        return out
    }

    /// Python: usgs_stories() - USGS PAGER alerts (backup for GDACS).
    static func usgs(_ data: Data) throws -> [Story] {
        let root = try json(data)
        var out: [Story] = []
        for case let q as [String: Any] in (root["features"] as? [Any]) ?? [] {
            let p = (q["properties"] as? [String: Any]) ?? [:]
            let alert = ((p["alert"] as? String) ?? "").lowercased()
            var sev = TM.usgsPager[alert] ?? 0.0
            if sev == 0, let mag = number(p["mag"]), mag >= 6.5 { sev = 1.0 }
            if let t = number(p["tsunami"]), t == 1 { sev += 2.0 }
            if sev != 0 {
                let ms = number(p["time"]) ?? 0
                let t = (p["title"] as? String) ?? ""
                out.append(Story(sev: sev, date: Date(timeIntervalSince1970: ms / 1000),
                                 title: t.isEmpty ? "Earthquake" : t, source: "USGS"))
            }
        }
        return out
    }
}
