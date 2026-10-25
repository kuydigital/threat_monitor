// THREAT MONITOR for macOS - headline text
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// Headlines are shown in at most 3 lines; longer ones are condensed (labels,
// attributions and filler removed, names abbreviated, trailing clauses
// dropped) and only cut with "…" as a last resort. Same steps as Python.

import Foundation

enum Text {
    // ---- duplicate detection --------------------------------------------
    static let suffixRx = Rx(#"\s+[-|–]\s+[^-|–]{2,40}$"#)
    static let normRx = Rx("[^a-z0-9 ]+")

    /// Python: normalize_title() - drop a " - Publisher" suffix, punctuation, case.
    static func normalizeTitle(_ title: String) -> String {
        let base = suffixRx.sub(title, "")
        return Py.join(normRx.sub(base.lowercased(), " "))
    }

    // ---- GDACS titles -----------------------------------------------------
    static let quakeMagRx = Rx(#"\bearthquake \(Magnitude\s*([\d.]+)\s*M?[^)]*\)"#)
    static let magRx = Rx(#"\(Magnitude\s*([\d.]+)\s*M?[^)]*\)"#)
    static let gdacsDateRx = Rx(#"\s+\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(:\d{2})?\s*UTC"#)
    static let unknownRx = Rx(#",?\s*\[unknown\]"#)
    static let mmiRx = Rx(#"\b(Few people affected|\d[\d.,]*(?: thousand| million)?)\s+\(?in MMI\s*(>=)?\s*([IVX]+)\b\)?"#, ci: true)
    static let noPeopleRx = Rx(#"\bNo people affected in (\d+)\s*km\b"#)
    static let cycloneRx = Rx(#"^(\w+) notification for tropical cyclone ([A-Z0-9-]+?)(?:-\d{2})?$"#)
    static let hurricaneRx = Rx(#"Category 1 \(120 km/h\) wind speeds or higher is (\d[\d.,]*(?: thousand| million)?)"#)
    static let stormRx = Rx(#"\((\d[\d.,]*(?: thousand| million)?) in Tropical Storm\)"#)
    static let usgsMagRx = Rx(#"^M ([\d.]+) - "#)           // USGS "M 5.9 - 218 km ENE of Nagqu, China"
    static let placesRx = Rx(#"^(.*?\bin )([A-Z][^,]*(?:, [A-Z][^,]*){3,}),?\s*$"#)
    static let mmiWords: [String: String] = [
        "I": "unfelt", "II": "weak", "III": "weak", "IV": "light", "V": "moderate",
        "VI": "strong", "VII": "very strong", "VIII": "severe", "IX": "violent", "X": "extreme",
    ]

    /// Python: people_number().
    static func peopleNumber(_ text: String) -> Double {
        let parts = text.components(separatedBy: " ")
        let unit = parts.count > 1 ? parts[1] : ""
        return (Double(parts[0].replacingOccurrences(of: ",", with: "")) ?? 0)
            * (unit == "thousand" ? 1e3 : unit == "million" ? 1e6 : 1)
    }

    /// '0.291 million' -> '291 thousand', '7.514 million' -> '7.5 million'. Python: people_count().
    static func peopleCount(_ text: String) -> String {
        let n = peopleNumber(text)
        if n >= 1e6 {
            var s = String(format: "%.1f", n / 1e6)
            if s.hasSuffix(".0") { s.removeLast(2) }
            return s + " million"
        }
        if n >= 1e3 { return "\(Int((n / 1e3).rounded(.toNearestOrEven))) thousand" }
        return "\(Int(n))"
    }

    /// Plain words for GDACS codes. Python: tidy_gdacs_title(), e.g.
    /// 'Red earthquake (Magnitude 7M, Depth:18km) in China 22/10/2026 14:33 UTC, 10 thousand (in MMI>=VII).'
    ///   -> 'Red magnitude 7 earthquake in China, 10 thousand people in at least very strong shaking'
    static func tidyGdacsTitle(_ title: String) -> String {
        var t = title
        var rest = ""
        if let r = title.range(of: ". ") {
            t = String(title[..<r.lowerBound])
            rest = String(title[r.upperBound...])
        }
        t = quakeMagRx.sub(t, "magnitude $1 earthquake")
        t = magRx.sub(t, "magnitude $1")
        t = gdacsDateRx.sub(t, "")
        t = unknownRx.sub(t, "")                            // no population estimate yet
        t = mmiRx.sub(t) { m, ns in
            let who = Rx.group(m, 1, ns) ?? ""
            let atLeast = Rx.group(m, 2, ns) != nil
            let level = Rx.group(m, 3, ns) ?? ""
            let people = who.lowercased().hasPrefix("few") ? "few people" : "\(who) people"
            return "\(people) in \(atLeast ? "at least " : "")\(mmiWords[level.uppercased()] ?? "level " + level) shaking"
        }
        t = noPeopleRx.sub(t, "no people within $1 km")
        if let m = cycloneRx.matches(t).first {          // "IN-FA-26" -> "In-Fa" (the -26 is the year)
            let ns = t as NSString
            let level = Rx.group(m, 1, ns) ?? ""
            let name = (Rx.group(m, 2, ns) ?? "").components(separatedBy: "-")
                .map { $0.prefix(1).uppercased() + $0.dropFirst().lowercased() }.joined(separator: "-")
            t = "\(level) tropical cyclone \(name)"
            let rns = rest as NSString
            let hurricane = hurricaneRx.matches(rest).first.flatMap { Rx.group($0, 1, rns) }
            let storm = stormRx.matches(rest).first.flatMap { Rx.group($0, 1, rns) }
            if let h = hurricane, peopleNumber(h) > 0 {
                t += ", \(peopleCount(h)) people in winds over 120 km/h"
            } else if let s = storm, peopleNumber(s) > 0 {
                t += ", \(peopleCount(s)) people in tropical storm winds"
            }
        }
        // "Drought is on going in Austria, Belgium, ... Ukraine," (29 countries) ->
        // "Drought is on going in Austria, Belgium and 27 more countries"
        if let m = placesRx.matches(t).first {
            let ns = t as NSString
            let lead = Rx.group(m, 1, ns) ?? ""
            let places = (Rx.group(m, 2, ns) ?? "").components(separatedBy: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            if places.count >= 4 {
                t = "\(lead)\(places[0]), \(places[1]) and \(places.count - 2) more countries"
            }
        }
        return Py.strip(Py.join(t), ". ", left: false)
    }

    // ---- condensing -------------------------------------------------------
    static let labelRx = Rx(#"^(live|breaking( news)?|watch|video|photos?|exclusive|updated?|analysis|opinion|explainer|in pictures|listen|just in)\s*[:|–—-]\s*"#, ci: true)
    static let bracketRx = Rx(#"\s*[(\[][^)\]]{0,80}[)\]]"#)
    static let tailRxs: [Rx] = [
        Rx(#"\s*[|–—-]\s*(live( updates| blog)?|as it happened|latest( updates)?|report|video|photos|opinion|analysis|explainer)\s*$"#, ci: true),
        Rx(#",?\s+according to [^,;]+$"#, ci: true),
        Rx(#"\s+\|\s+[^|]{2,40}$"#),                         // "... | Newswise"
        Rx(#",\s+(\S+\s+){0,3}(says?|said|reports?|reported|claims?|claimed|warns?|warned|confirms?|confirmed|announces?|announced)\s*$"#, ci: true),
    ]
    static let leadAttrRx = Rx(#"^(officials?|police|authorities|reports?|sources|witnesses|experts?|analysts?|scientists|researchers|state media|residents)\s+(say|said|warn|warned|fear|believe|confirm|confirmed)\s+(that\s+)?"#, ci: true)
    static let abbreviations: [(rx: Rx, template: String)] = [
        (Rx(#"\bDemocratic Republic of (the )?Congo\b"#), "DR Congo"),
        (Rx(#"\bUnited States( of America)?\b"#), "US"),
        (Rx(#"\bUnited Kingdom\b"#), "UK"),
        (Rx(#"\bUnited Nations\b"#), "UN"),
        (Rx(#"\bEuropean Union\b"#), "EU"),
        (Rx(#"\bWorld Health Organi[sz]ation\b"#), "WHO"),
        (Rx(#"\bUnited Arab Emirates\b"#), "UAE"),
        (Rx(#"\b(\d+(?:\.\d+)?) thousand\b"#), "$1k"),
        (Rx(#"\b(\d+(?:\.\d+)?) million\b"#), "$1m"),
        (Rx(#"\b(\d+(?:\.\d+)?) billion\b"#), "$1bn"),
        (Rx(#"(\d) ?(per ?cent|percent)\b"#), "$1%"),
        (Rx(#"(?i)\bapproximately\b"#), "about"),
        (Rx(#"(?i)\bmore than\b"#), "over"),
        (Rx(#"(?i)\bin order to\b"#), "to"),
        (Rx(#"(?i)\bfollowing\b"#), "after"),
        (Rx(#"(?i)\btelecommunications\b"#), "telecoms"),
        (Rx(#"(?i)\bgovernment\b"#), "govt"),
        (Rx(#"\bVulnerability\b"#), "flaw"),
    ]
    static let codesRx = Rx(#"\bCVE-\d{4}-\d+:?\s*|\s*\([A-Z]{2,6}\)"#)   // CISA: "CVE-2026-1234", "(XSS)"
    static let fillerRx = Rx(#"\b(a|an|the|reportedly|currently)\s+"#, ci: true)
    /// Where a trailing clause can be dropped.
    static let clauseRx = Rx(#"(;\s|,\s(?=(?:as|after|while|amid|with|despite|which|who|but|before|including|where|when|days|weeks|hours|months)\b)|,\s(?=[a-z][a-z-]*ing\b)|\s(?=(?:as|after|amid|while|despite|ahead of|that|which|days after|weeks after|hours after)\s))"#, ci: true)
    /// " - DR Congo": often a place, so cut last.
    static let dashRx = Rx(#"\s[–—-]\s"#)
    /// Last resort before "…": any natural break, longest summary first.
    static let cutRx = Rx(#"(:\s|(?:(?<=\w\w[?!])|(?<=[a-z]{3}\.))\s|,\s|\s(?=(?:[Aa]nd|[Ww]ith|[Ww]ithout|[Nn]ear|[Oo]ver|[Ff]or|[Ff]rom|[Ii]nto|[Vv]ia|[Tt]o|[Ii]n [Hh]onou?r [Oo]f)\s))"#)
    static let clauseMinWords = 6
    static let dangling: Set<String> = [
        "a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "for", "with", "by", "from",
        "as", "after", "amid", "while", "but", "that", "its", "their", "his", "her", "is", "are", "was",
        "were", "be", "been", "has", "have", "had", "will", "would", "could", "can", "may", "between",
        "into", "over", "under", "about", "against", "across", "near", "than", "more", "most", "less",
        "very", "this", "these", "those", "who", "which", "not", "no",
    ]

    static func tidy(_ t: String) -> String {
        Py.upperFirst(Py.strip(Py.join(t), " ,;:-–—|"))
    }

    /// Progressively shorter versions of a headline, gentlest first; the
    /// original is always first. Also returns the fully condensed text without
    /// clause cuts (for the "…" fallback). Python: condense_steps().
    static func condenseSteps(_ text: String) -> (steps: [String], condensed: String) {
        var seen: [String] = []
        func emit(_ s: String) {
            let t = tidy(s)
            if !t.isEmpty && !seen.contains(t) { seen.append(t) }
        }
        func clauseCuts(_ s: String, _ rx: Rx) {
            let ns = s as NSString
            for m in rx.matches(s).reversed() {
                let head = ns.substring(to: m.range.location)
                if Py.split(head).count >= clauseMinWords { emit(head) }
            }
        }

        var t = codesRx.sub(text, "")                     // codes mean little on screen, so never shown
        emit(t)
        // 1. drop "LIVE:"-style labels, (brackets), and "..., officials say" attributions
        t = bracketRx.sub(labelRx.sub(t, ""), "")
        for rx in tailRxs { t = rx.sub(t, "") }
        t = leadAttrRx.sub(t, "")
        emit(t)
        // 2. shorter names and numbers
        for a in abbreviations { t = a.rx.sub(t, a.template) }
        emit(t)
        // 3. headline style: no articles or filler words
        t = fillerRx.sub(t, "")
        emit(t)
        // 4. drop trailing clauses, last one first, keeping the main statement
        clauseCuts(t, clauseRx)
        // 5. drop a short "Topic:" prefix, then try the clause cuts again,
        //    this time also at " - "
        if let r = t.range(of: ": ") {
            let head = String(t[..<r.lowerBound])
            let rest = String(t[r.upperBound...])
            if Py.split(head).count <= 4 && Py.split(rest).count >= 4 {
                t = rest
                emit(t)
                clauseCuts(t, clauseRx)
            }
        }
        clauseCuts(t, dashRx)
        // 6. last resort: the longest part that ends at any natural break
        clauseCuts(t, cutRx)
        return (seen, tidy(t))
    }

    /// Longest word-boundary prefix of `text` + "…" for which `fits` is true,
    /// not ending on a dangling word like "and" or "of". Python: truncate_words().
    static func truncateWords(_ fits: (String) -> Bool, _ text: String) -> String {
        let words = Py.split(text)
        func cut(_ n: Int) -> String {
            Py.strip(words[0..<n].joined(separator: " "), " ,;:-–—", left: false) + "…"
        }
        var lo = 0
        var hi = words.count
        while lo < hi {
            let mid = (lo + hi + 1) / 2
            if fits(cut(mid)) { lo = mid } else { hi = mid - 1 }
        }
        var keep = lo
        while keep > 1 && dangling.contains(Py.strip(words[keep - 1].lowercased(), ",;:")) {
            keep -= 1
        }
        return cut(keep)
    }

    /// Every pattern used for headlines (the tests compare them with Python).
    static var allRx: [Rx] {
        [suffixRx, normRx, quakeMagRx, magRx, gdacsDateRx, unknownRx, mmiRx, noPeopleRx, cycloneRx, hurricaneRx, stormRx,
         usgsMagRx, placesRx, labelRx, bracketRx, leadAttrRx, codesRx, fillerRx, clauseRx, dashRx, cutRx]
            + tailRxs + abbreviations.map { $0.rx }
    }
}
