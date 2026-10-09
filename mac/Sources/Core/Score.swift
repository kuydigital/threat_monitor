// THREAT MONITOR for macOS - scoring
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// News categories (WAR, CYB, BIO) compare each source with its own 30-day
// median: an ordinary day reads ~35 (GUARDED), twice the usual ~58, three
// times ~73. DIS uses official GDACS alert levels (USGS as a fallback). The
// Global Threat Index is the weighted root-mean-square of the four.

import Foundation

/// The download of one source: its bytes, or why it failed.
enum Fetched {
    case ok(Data)
    case failed(String)
}

/// How one source of a news category was scored (shown by --check).
struct Component {
    var key: String
    var label: String
    var kind: String          // "feed", "headlines" (Google: shown, not scored) or "extra"
    var ok = false
    var note = ""
    var items = 0             // stories in the feed
    var recent = 0            // ... inside its time window
    var hits = 0              // ... about this threat
    var raw = 0.0             // average severity per recent story
    var learned: Bool?
    var normal: Double?
    var ratio: Double?

    init(key: String, label: String, kind: String) {
        self.key = key
        self.label = label
        self.kind = kind
    }
}

struct CatResult {
    let score: Int
    let stories: [Story]
}

/// Learned "normal" per source: hourly samples of its raw level.
struct Calibration: Codable {
    var version: Int
    var samples: [String: [[Double]]]

    static func empty() -> Calibration {
        Calibration(version: TM.calibVersion, samples: [:])
    }

    static func load(from url: URL) -> Calibration {
        guard let data = try? Data(contentsOf: url),
              let cal = try? JSONDecoder().decode(Calibration.self, from: data),
              cal.version == TM.calibVersion else { return .empty() }
        var clean: [String: [[Double]]] = [:]
        for (key, rows) in cal.samples where Config.componentKeys.contains(key) {
            clean[key] = rows.filter { $0.count == 2 && $0[0].isFinite && $0[1].isFinite }
                .sorted { $0[0] != $1[0] ? $0[0] < $1[0] : $0[1] < $1[1] }
        }
        return Calibration(version: TM.calibVersion, samples: clean)
    }

    func save(to url: URL) {
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(),
                                                    withIntermediateDirectories: true)
            try JSONEncoder().encode(self).write(to: url, options: .atomic)
        } catch {
            tmLog("WARN", "could not save \(url.lastPathComponent): \(error.localizedDescription)")
        }
    }

    /// Median raw level of one source over the last 30 days, or nil while it
    /// has fewer than calibMinSamples hours of history.
    func median(_ key: String) -> Double? {
        let values = (samples[key] ?? []).compactMap { $0.count == 2 ? $0[1] : nil }.sorted()
        if values.count < TM.calibMinSamples { return nil }
        return values[values.count / 2]
    }

    mutating func record(_ key: String, _ raw: Double, _ nowTs: Double) {
        var hist = (samples[key] ?? []).filter { $0.count == 2 && nowTs - $0[0] < TM.calibDays * 86400 }
        if let last = hist.last {
            if nowTs - last[0] >= TM.calibSampleGap { hist.append([nowTs, raw]) }
        } else {
            hist.append([nowTs, raw])
        }
        samples[key] = hist
    }

    /// Hours of history behind the learned normals (slowest category).
    func baselineHours() -> Int {
        var perCat: [Int] = []
        for name in TM.newsCats {
            let keys = Config.componentKeys.filter { $0.hasPrefix(name + ":") }
            perCat.append(keys.map { samples[$0]?.count ?? 0 }.max() ?? 0)
        }
        return perCat.min() ?? 0
    }
}

enum Score {
    /// Map an unbounded value onto 0-100 with diminishing returns.
    static func saturate(_ raw: Double, _ scale: Double) -> Int {
        let v = 100 * (1 - exp(-raw / scale))
        guard v.isFinite else { return raw > 0 ? 100 : 0 }
        return max(0, min(100, Py.round(v)))
    }

    static func fromRatio(_ ratio: Double) -> Int {
        saturate(ratio, 1 / TM.normalK)
    }

    /// Weighted root-mean-square of the categories shown (needs at least 3).
    static func gti(_ scores: [String: Int]) -> Int? {
        let avail = TM.cats.filter { scores[$0] != nil }
        if avail.count < 3 { return nil }
        var wsum = 0.0
        var total = 0.0
        for c in avail {
            let w = TM.gtiWeights[c] ?? 0
            let s = Double(scores[c] ?? 0)
            wsum += w
            total += w * s * s
        }
        guard wsum > 0 else { return nil }
        return Py.round((total / wsum).squareRoot())
    }

    static func level(_ v: Int?) -> String {
        guard let v = v else { return "NO DATA" }
        for l in TM.levels where v < l.limit { return l.name }
        return TM.levels[TM.levels.count - 1].name
    }

    /// A story's severity: its highest matching rule weight.
    static func severity(_ cfg: Category, _ title: String, _ desc: String) -> Double {
        let text = cfg.exclude.sub("\(title) . \(desc)", " ")
        var best = 0.0
        for rule in cfg.rules where rule.weight > best && rule.rx.search(text) {
            best = rule.weight
        }
        return best
    }

    /// Most severe, then newest, skipping near-duplicates of the same story.
    static func pickHeadlines(_ stories: [Story], n: Int = 3) -> [Story] {
        let order = stories.indices.sorted { a, b in
            let x = stories[a], y = stories[b]
            if x.sev != y.sev { return x.sev > y.sev }
            let dx = x.date ?? .distantPast, dy = y.date ?? .distantPast
            if dx != dy { return dx > dy }
            return a < b
        }
        var chosen: [Story] = []
        var wordSets: [Set<String>] = []
        for i in order {
            let s = stories[i]
            let words = Set(Py.split(Text.normalizeTitle(s.title)))
            let duplicate = wordSets.contains { w in
                Double(words.intersection(w).count) / Double(max(1, words.union(w).count)) > 0.5
            }
            if duplicate { continue }
            chosen.append(s)
            wordSets.append(words)
            if chosen.count == n { break }
        }
        return chosen
    }
}

/// Turns downloaded sources into scores. Keeps the learned calibration and
/// the last good CISA/WHO result (reused for a day if a fetch fails).
final class Scorer {
    var calibration: Calibration
    private var extraCache: [String: (time: Double, stories: [Story])] = [:]

    init(calibration: Calibration) {
        self.calibration = calibration
    }

    /// Python: use_extra()
    func useExtra(_ name: String, _ result: Result<[Story], TMError>) -> [Story]? {
        let now = wallNow()
        switch result {
        case .success(let stories):
            extraCache[name] = (now, stories)
            return stories
        case .failure(let error):
            if let hit = extraCache[name], now - hit.time < TM.extraCacheHours * 3600 {
                tmLog("WARN", "\(name) failed (\(error)); using result from \(Int((now - hit.time) / 60)) min ago")
                return hit.stories
            }
            tmLog("WARN", "\(name) unavailable: \(error)")
            return nil
        }
    }

    /// Python: fetch_category() - score each source of a news category.
    func category(_ name: String, now: Date, fetched: [String: Fetched]) -> (comps: [Component], stories: [Story]) {
        guard let cfg = Config.categories[name] else { return ([], []) }
        var comps: [Component] = []
        var stories: [Story] = []
        for f in cfg.feeds {
            var c = Component(key: f.key, label: f.label, kind: f.scored ? "feed" : "headlines")
            var items: [Item] = []
            switch fetched["\(name):\(f.key)"] ?? .failed("not fetched") {
            case .failed(let message):
                c.note = "failed: \(message)"
                tmLog("WARN", "\(name) \(f.label) failed: \(message)")
                comps.append(c)
                continue
            case .ok(let data):
                do {
                    items = try Parse.rssItems(data, label: f.label)
                } catch {
                    c.note = "failed: \(error)"
                    tmLog("WARN", "\(name) \(f.label) failed: \(error)")
                    comps.append(c)
                    continue
                }
            }
            let cutoff = now.addingTimeInterval(-f.windowHours * 3600)
            var seen = Set<String>()
            var sevSum = 0.0
            var newest: Date?
            c.items = items.count
            for it in items {
                if let d = it.date {
                    newest = max(newest ?? d, d)
                    if d < cutoff { continue }
                }
                let key = Text.normalizeTitle(it.title)
                if key.isEmpty || seen.contains(key) { continue }
                seen.insert(key)
                c.recent += 1
                let sev = Score.severity(cfg, it.title, it.desc)
                if sev > 0 {
                    c.hits += 1
                    sevSum += sev
                    stories.append(Story(sev: sev, date: it.date ?? now, title: it.title, source: it.source))
                }
            }
            if c.kind == "headlines" {
                c.ok = true
                comps.append(c)
                continue
            }
            c.raw = sevSum / Double(max(c.recent, TM.feedMinDenominator))
            if c.recent >= TM.minFeedStories {
                c.ok = true
            } else {                                   // never read "no stories" as "no threat"
                if items.isEmpty {
                    c.note = "feed returned no stories"
                } else if let n = newest, n < cutoff {
                    c.note = "newest story is \(agoText(n)) - check the clock and timezone"
                } else {
                    c.note = "only \(c.recent) recent stories"
                }
                tmLog("WARN", "\(name) \(f.label): \(c.note); not used")
            }
            comps.append(c)
        }
        if let ename = cfg.extra {
            var c = Component(key: ename, label: ename, kind: "extra")
            var parsed: Result<[Story], TMError> = .failure(TMError("not fetched"))
            switch fetched["\(name):\(ename)"] ?? .failed("not fetched") {
            case .failed(let message):
                parsed = .failure(TMError(message))
            case .ok(let data):
                do {
                    if ename == "CISA" {
                        parsed = .success(try Parse.kev(data, now: now))
                    } else {
                        parsed = .success(try Parse.who(data, now: now))
                    }
                } catch {
                    parsed = .failure(TMError("\(error)"))
                }
            }
            if let extra = useExtra(ename, parsed) {
                let n = Set(extra.map { $0.title }).count
                let wc = Config.extraWeight(ename)
                c.ok = true
                c.items = n
                c.recent = n
                c.hits = n
                c.raw = min(wc.cap, wc.weight * Double(n))
                stories.append(contentsOf: extra)
            } else {
                c.note = "unavailable"
            }
            comps.append(c)
        }
        return (comps, stories)
    }

    /// Python: combine() - average of each working source's level relative
    /// to its own normal.
    func combine(_ name: String, _ comps: inout [Component]) throws -> Double {
        if !comps.contains(where: { $0.ok && $0.kind == "feed" }) {
            throw TMError("no news feed returned enough recent stories")
        }
        var total = 0.0
        var count = 0
        for i in comps.indices where comps[i].ok && comps[i].kind != "headlines" {
            let key = comps[i].key
            let med = calibration.median("\(name):\(key)")
            let base = med ?? (TM.defaultNormal[name]?[key] ?? 0.5)
            let floor = comps[i].kind == "feed" ? TM.feedNormalFloor : Config.extraWeight(key).weight
            // 1.0 = this source's usual level. Measured as distance from
            // normal, so a source that is usually ~0 also reads 1.0 on an
            // ordinary day instead of dragging the average down.
            let ratio = min(TM.ratioCap, max(0.0, 1 + (comps[i].raw - base) / max(base, floor)))
            comps[i].learned = med != nil
            comps[i].normal = base
            comps[i].ratio = ratio
            total += ratio
            count += 1
        }
        return total / Double(max(1, count))
    }

    /// Python: score_disasters()
    func disasters(now: Date, fetched: [String: Fetched]) throws -> (score: Int, stories: [Story]) {
        var stories: [Story] = []
        do {
            stories = try Scorer.parseDis("DIS:GDACS", fetched) { try Parse.gdacs($0, now: now) }
        } catch {
            tmLog("WARN", "GDACS failed, using USGS instead: \(error)")
            do {
                stories = try Scorer.parseDis("DIS:USGS", fetched) { try Parse.usgs($0) }
            } catch {
                throw TMError("GDACS and USGS both unavailable (\(error))")
            }
        }
        var routine = 0.0
        var major = 0.0
        for s in stories {
            if s.sev <= TM.disRoutineMax { routine += s.sev } else { major += s.sev }
        }
        return (Score.saturate(major + min(TM.disRoutineCap, routine), TM.disScale), stories)
    }

    private static func parseDis(_ key: String, _ fetched: [String: Fetched],
                                 _ parse: (Data) throws -> [Story]) throws -> [Story] {
        switch fetched[key] ?? .failed("not fetched") {
        case .failed(let message): throw TMError(message)
        case .ok(let data): return try parse(data)
        }
    }

    /// One whole sync: every category from the downloaded sources.
    func process(now: Date, fetched: [String: Fetched], record: Bool)
        -> (results: [String: CatResult], errors: [String], comps: [String: [Component]]) {
        var results: [String: CatResult] = [:]
        var errors: [String] = []
        var allComps: [String: [Component]] = [:]
        let nowTs = now.timeIntervalSince1970
        for c in TM.cats {
            if c == "DIS" {
                do {
                    let r = try disasters(now: now, fetched: fetched)
                    results[c] = CatResult(score: r.score, stories: r.stories)
                    tmLog("INFO", "DIS -> \(r.score)  (\(r.stories.count) current alerts)")
                } catch {
                    tmLog("ERROR", "\(c) failed: \(error)")
                    errors.append("\(c): \(error)")
                }
                continue
            }
            let r = category(c, now: now, fetched: fetched)
            var comps = r.comps
            do {
                let value = Score.fromRatio(try combine(c, &comps))
                if record {
                    for comp in comps where comp.ok && comp.kind != "headlines" {
                        calibration.record("\(c):\(comp.key)", comp.raw, nowTs)
                    }
                }
                let parts = comps.compactMap { x in x.ratio.map { "\(x.label) \(String(format: "%.2f", $0))x" } }
                tmLog("INFO", "\(c) -> \(value)  (\(parts.joined(separator: ", ")))")
                results[c] = CatResult(score: value, stories: r.stories)
            } catch {
                tmLog("ERROR", "\(c) failed: \(error)")
                errors.append("\(c): \(error)")
            }
            allComps[c] = comps
        }
        return (results, errors, allComps)
    }
}
