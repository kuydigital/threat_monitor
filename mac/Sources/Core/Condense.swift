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
    static let magRx = Rx(#"\(Magnitude\s*([\d.]+)\s*M?[^)]*\)"#)
    static let gdacsDateRx = Rx(#"\s+\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(:\d{2})?\s*UTC"#)
    static let mmiRx = Rx(#"\b(Few people affected|\d[\d.,]*(?: thousand| million)?)\s+in MMI ([IVX]+)\b"#, ci: true)
    static let mmiWords: [String: String] = [
        "I": "unfelt", "II": "weak", "III": "weak", "IV": "light", "V": "moderate",
        "VI": "strong", "VII": "very strong", "VIII": "severe", "IX": "violent", "X": "extreme",
    ]

    /// 'Green earthquake (Magnitude 5.9M, Depth:45.951km) in Indonesia 03/10/2026
    /// 22:55 UTC, 130 thousand in MMI V.' -> 'Green earthquake M5.9 in Indonesia,
    /// 130 thousand people in moderate shaking'
    static func tidyGdacsTitle(_ title: String) -> String {
        var t = magRx.sub(title, "M$1")
        t = gdacsDateRx.sub(t, "")
        t = mmiRx.sub(t) { m, ns in
            let who = Rx.group(m, 1, ns) ?? ""
            let level = Rx.group(m, 2, ns) ?? ""
            let people = who.lowercased().hasPrefix("few") ? "few people" : "\(who) people"
            return "\(people) in \(mmiWords[level.uppercased()] ?? "MMI " + level) shaking"
        }
        return Py.strip(Py.join(t), ". ", left: false)
    }

    // ---- condensing -------------------------------------------------------
    static let labelRx = Rx(#"^(live|breaking( news)?|watch|video|photos?|exclusive|updated?|analysis|opinion|explainer|in pictures|listen|just in)\s*[:|–—-]\s*"#, ci: true)
    static let bracketRx = Rx(#"\s*[(\[][^)\]]{0,80}[)\]]"#)
    static let tailRxs: [Rx] = [
        Rx(#"\s*[|–—-]\s*(live( updates| blog)?|as it happened|latest( updates)?|report|video|photos|opinion|analysis|explainer)\s*$"#, ci: true),
        Rx(#",?\s+according to [^,;]+$"#, ci: true),
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
    static let fillerRx = Rx(#"\b(a|an|the|reportedly|currently)\s+"#, ci: true)
    /// Where a trailing clause can be dropped.
    static let clauseRx = Rx(#"(;\s|,\s(?=(?:as|after|while|amid|with|despite|which|who|but|before|including|where|when|days|weeks|hours|months)\b)|,\s(?=[a-z][a-z-]*ing\b)|\s(?=(?:as|after|amid|while|despite|ahead of|that|which|days after|weeks after|hours after)\s))"#, ci: true)
    /// " - DR Congo": often a place, so cut last.
    static let dashRx = Rx(#"\s[–—-]\s"#)
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

        var t = text
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
        [suffixRx, normRx, magRx, gdacsDateRx, mmiRx, labelRx, bracketRx, leadAttrRx, fillerRx, clauseRx, dashRx]
            + tailRxs + abbreviations.map { $0.rx }
    }
}
