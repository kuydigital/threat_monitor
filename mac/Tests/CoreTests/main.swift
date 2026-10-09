// THREAT MONITOR for macOS - core tests
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// The Swift port must give the same results as threat_monitor.py. The
// reference comes from mac/Tests/make_golden.py, which downloads every source
// once and records what the Python version makes of those exact files.
//
//   core-tests GOLDEN_FOLDER     compare with the Python reference
//   core-tests --live            fetch every source now and explain the scores

import Foundation

setvbuf(stdout, nil, _IOLBF, 0)
let args = CommandLine.arguments
if args.contains("--live") {
    print(CheckReport.run())
    exit(0)
}
guard args.count >= 2 else {
    print("usage: core-tests GOLDEN_FOLDER | core-tests --live")
    exit(2)
}

let folder = URL(fileURLWithPath: args[1])
guard let goldenData = try? Data(contentsOf: folder.appendingPathComponent("golden.json")),
      let golden = (try? JSONSerialization.jsonObject(with: goldenData, options: [])) as? [String: Any] else {
    print("FAIL cannot read golden.json in \(folder.path)")
    exit(1)
}

// ---- tiny test framework -------------------------------------------------------
var counts: [String: [Int]] = [:]
var sections: [String] = []
func expect(_ section: String, _ ok: Bool, _ detail: @autoclosure () -> String) {
    if counts[section] == nil {
        counts[section] = [0, 0]
        sections.append(section)
    }
    var c = counts[section] ?? [0, 0]
    if ok {
        c[0] += 1
    } else {
        c[1] += 1
        if c[1] <= 10 { print("  FAIL [\(section)] \(detail())") }
    }
    counts[section] = c
}

func num(_ v: Any?) -> Double? { (v as? NSNumber)?.doubleValue }
func str(_ v: Any?) -> String? { v as? String }
func arr(_ v: Any?) -> [Any] { (v as? [Any]) ?? [] }
func obj(_ v: Any?) -> [String: Any] { (v as? [String: Any]) ?? [:] }
func intOrNil(_ v: Any?) -> Int? { num(v).map { Int($0) } }

func close(_ a: Double?, _ b: Double?, _ tol: Double = 1e-9) -> Bool {
    if let x = a, let y = b { return abs(x - y) <= tol }
    return a == nil && b == nil
}

func q(_ s: String?) -> String {
    guard let s = s else { return "nil" }
    return "\"\(s)\""
}

/// Compare JSON-like values (numbers with a tolerance).
func same(_ a: Any?, _ b: Any?) -> Bool {
    if a == nil || a is NSNull { return b == nil || b is NSNull }
    if let x = a as? String { return (b as? String) == x }
    if let x = a as? NSNumber, let y = b as? NSNumber { return abs(x.doubleValue - y.doubleValue) < 1e-9 }
    if let x = a as? [Any], let y = b as? [Any] {
        return x.count == y.count && zip(x, y).allSatisfy { same($0, $1) }
    }
    if let x = a as? [String: Any], let y = b as? [String: Any] {
        return Set(x.keys) == Set(y.keys) && x.allSatisfy { same($0.value, y[$0.key]) }
    }
    return false
}

/// A Swift value as JSON would read it back (so it can be compared with the reference).
func asJSON(_ v: Any) -> Any? {
    guard let d = try? JSONSerialization.data(withJSONObject: ["v": v], options: []),
          let o = (try? JSONSerialization.jsonObject(with: d, options: [])) as? [String: Any] else { return nil }
    return o["v"]
}

let now = Date(timeIntervalSince1970: num(golden["now"]) ?? 0)
print("Reference made with Python \(str(golden["python"]) ?? "?") at \(now)")

// ---- 1. every pattern compiles -----------------------------------------------------
_ = Config.categories
_ = Config.componentKeys
_ = Text.allRx
_ = [HTMLText.tag, HTMLText.entity, Dates.dayPrefix, Dates.isoRx, Dates.ymdRx]
expect("regex", Rx.failed.isEmpty, "patterns that don't compile: \(Rx.failed)")

// ---- 2. configuration is identical to the Python version ----------------------------
let gp = obj(golden["patterns"])
for name in TM.newsCats {
    guard let cfg = Config.categories[name] else {
        expect("patterns", false, "missing category \(name)")
        continue
    }
    let rules = arr(obj(gp[name])["rules"])
    expect("patterns", rules.count == cfg.rules.count, "\(name): \(cfg.rules.count) rules, Python has \(rules.count)")
    for (i, r) in rules.enumerated() where i < cfg.rules.count {
        let row = arr(r)
        let mine = cfg.rules[i]
        expect("patterns", str(row.first) == mine.rx.pattern, "\(name) rule \(i): \(q(mine.rx.pattern)) vs Python \(q(str(row.first)))")
        expect("patterns", close(num(row.count > 1 ? row[1] : nil), mine.weight), "\(name) rule \(i) weight")
        expect("patterns", (row.count > 2 ? row[2] as? Bool : nil) == mine.rx.ci, "\(name) rule \(i) case flag")
    }
    let ex = arr(obj(gp[name])["exclude"])
    expect("patterns", str(ex.first) == cfg.exclude.pattern, "\(name) exclusions differ:\n    swift  \(cfg.exclude.pattern)\n    python \(str(ex.first) ?? "")")
    expect("patterns", (ex.count > 1 ? ex[1] as? Bool : nil) == cfg.exclude.ci, "\(name) exclusion case flag")
}
let cp = obj(golden["condense_patterns"])
func checkPattern(_ label: String, _ rx: Rx, _ ref: Any?) {
    let row = arr(ref)
    expect("patterns", str(row.first) == rx.pattern, "\(label): \(q(rx.pattern)) vs Python \(q(str(row.first)))")
    expect("patterns", (row.count > 1 ? row[1] as? Bool : nil) == rx.ci, "\(label) case flag")
}
checkPattern("label", Text.labelRx, cp["label"])
checkPattern("bracket", Text.bracketRx, cp["bracket"])
checkPattern("lead", Text.leadAttrRx, cp["lead"])
checkPattern("filler", Text.fillerRx, cp["filler"])
checkPattern("clause", Text.clauseRx, cp["clause"])
checkPattern("dash", Text.dashRx, cp["dash"])
let tails = arr(cp["tails"])
expect("patterns", tails.count == Text.tailRxs.count, "tail pattern count")
for (i, t) in tails.enumerated() where i < Text.tailRxs.count { checkPattern("tail \(i)", Text.tailRxs[i], t) }
let abbrev = arr(cp["abbrev"])
expect("patterns", abbrev.count == Text.abbreviations.count, "abbreviation count")
for (i, a) in abbrev.enumerated() where i < Text.abbreviations.count {
    let row = arr(a)
    let mine = Text.abbreviations[i]
    expect("patterns", str(row.first) == mine.rx.pattern, "abbreviation \(i): \(q(mine.rx.pattern)) vs \(q(str(row.first)))")
    expect("patterns", (row.count > 1 ? str(row[1]) : nil) == mine.template, "abbreviation \(i) replacement")
    expect("patterns", (row.count > 2 ? row[2] as? Bool : nil) == mine.rx.ci, "abbreviation \(i) case flag")
}

let gf = obj(golden["feeds"])
for name in TM.newsCats {
    guard let cfg = Config.categories[name] else { continue }
    let ref = arr(gf[name])
    expect("feeds", ref.count == cfg.feeds.count, "\(name) feed count")
    for (i, r) in ref.enumerated() where i < cfg.feeds.count {
        let f = obj(r)
        let mine = cfg.feeds[i]
        let refParams: [[String]] = arr(f["params"]).map { arr($0).compactMap { $0 as? String } }
        let myParams: [[String]] = mine.params.map { [$0.0, $0.1] }
        let sameNames = str(f["key"]) == mine.key && str(f["label"]) == mine.label
        let sameWindow = close(num(f["window"]), mine.windowHours) && (f["scored"] as? Bool) == mine.scored
        let sameURL = str(f["url"]) == mine.base && refParams == myParams
        expect("feeds", sameNames && sameWindow && sameURL, "\(name) feed \(i) (\(mine.key)) differs from Python")
        if let url = mine.url {
            expect("feeds", url.absoluteString.hasPrefix(mine.base), "\(name) \(mine.key) url \(url)")
        } else {
            expect("feeds", false, "\(name) \(mine.key): no URL")
        }
    }
    let refExtra: String? = obj(golden["extras"])[name] as? String
    expect("feeds", refExtra == cfg.extra, "\(name) extra source")
}

let swiftConstants: [String: Any] = [
    "SYNC_DEADLINE": TM.syncDeadline, "REFRESH_OK": TM.refreshOK, "REFRESH_RETRY_MIN": TM.refreshRetryMin,
    "NEWS_WINDOW_HOURS": TM.newsWindowHours, "KEV_WINDOW_DAYS": TM.kevWindowDays,
    "DON_WINDOW_DAYS": TM.donWindowDays, "EXTRA_CACHE_HOURS": TM.extraCacheHours,
    "NORMAL_LEVEL": TM.normalLevel, "NORMAL_K": TM.normalK, "RATIO_CAP": TM.ratioCap,
    "MIN_FEED_STORIES": TM.minFeedStories, "FEED_MIN_DENOMINATOR": TM.feedMinDenominator,
    "FEED_NORMAL_FLOOR": TM.feedNormalFloor, "STATE_MAX_AGE": TM.stateMaxAge, "CALIB_VERSION": TM.calibVersion,
    "CALIB_DAYS": TM.calibDays, "CALIB_MIN_SAMPLES": TM.calibMinSamples, "CALIB_SETTLED": TM.calibSettled,
    "CALIB_SAMPLE_GAP": TM.calibSampleGap, "KEV_WEIGHT": TM.kevWeight, "KEV_CAP": TM.kevCap,
    "DON_WEIGHT": TM.donWeight, "DON_CAP": TM.donCap, "DIS_ROUTINE_MAX": TM.disRoutineMax,
    "DIS_ROUTINE_CAP": TM.disRoutineCap, "DIS_SCALE": TM.disScale, "MAIN_SECS": TM.mainSecs,
    "CAT_SECS": TM.catSecs, "FADE_SECS": TM.fadeSecs, "HEADLINE_MAX_LINES": TM.headlineMaxLines,
    "CLAUSE_MIN_WORDS": Text.clauseMinWords, "WHO_DON_URL": TM.whoDonURL, "CISA_KEV_URL": TM.cisaKevURL,
    "GOOGLE_NEWS": TM.googleNews, "GTI_WEIGHTS": TM.gtiWeights, "DEFAULT_NORMAL": TM.defaultNormal,
    "GDACS_GREEN_BY_TYPE": TM.gdacsGreenByType, "GDACS_LEVEL": TM.gdacsLevel, "USGS_PAGER": TM.usgsPager,
    "CAT_NAMES": TM.catNames, "EMPTY_MSG": TM.emptyMsg, "MMI_WORDS": Text.mmiWords, "CATS": TM.cats,
    "HEADLINE_SIZES": [TM.headlineSizes.big, TM.headlineSizes.small],
    "DANGLING": Array(Text.dangling).sorted(), "COMPONENT_KEYS": Config.componentKeys.sorted(),
]
var gc = obj(golden["constants"])
if let levels = gc["LEVELS"] as? [Any] {                 // colours are checked by the screenshots
    gc["LEVELS"] = levels.map { Array(arr($0).prefix(2)) }
}
let myLevels: [Any] = TM.levels.map { [$0.limit, $0.name] as [Any] }
expect("constants", same(asJSON(myLevels), gc["LEVELS"]), "LEVELS differ")
for (key, mine) in swiftConstants.sorted(by: { $0.key < $1.key }) {
    expect("constants", same(asJSON(mine), gc[key]), "\(key): swift \(asJSON(mine) ?? "?") vs python \(gc[key] ?? "missing")")
}
for key in gc.keys where swiftConstants[key] == nil && key != "LEVELS" {
    expect("constants", false, "Python constant \(key) is not checked")
}

// ---- 3. numbers -----------------------------------------------------------------------
for r in arr(golden["ratio_scores"]) {
    let row = arr(r)
    guard row.count == 2, let ratio = num(row[0]), let ref = intOrNil(row[1]) else { continue }
    expect("numbers", Score.fromRatio(ratio) == ref, "score_from_ratio(\(ratio)) = \(Score.fromRatio(ratio)), Python \(ref)")
}
expect("numbers", Score.fromRatio(1.0) == 35, "an ordinary day (ratio 1.0) must read 35")
for r in arr(golden["saturate"]) {
    let row = arr(r)
    guard row.count == 3, let raw = num(row[0]), let scale = num(row[1]), let ref = intOrNil(row[2]) else { continue }
    expect("numbers", Score.saturate(raw, scale) == ref, "saturate(\(raw), \(scale))")
}
for c in arr(golden["gti"]) {
    let o = obj(c)
    var scores: [String: Int] = [:]
    for (k, v) in obj(o["scores"]) { if let n = intOrNil(v) { scores[k] = n } }
    expect("numbers", Score.gti(scores) == intOrNil(o["gti"]), "compute_gti(\(scores)) = \(String(describing: Score.gti(scores)))")
}

// ---- 4. text handling ---------------------------------------------------------------------
for r in arr(golden["strip_html"]) {
    let row = arr(r)
    guard row.count == 2, let input = str(row[0]), let ref = str(row[1]) else { continue }
    expect("text", HTMLText.strip(input) == ref, "strip_html(\(q(input))) = \(q(HTMLText.strip(input))), Python \(q(ref))")
}
for r in arr(golden["dates"]) {
    let row = arr(r)
    guard row.count == 2, let input = str(row[0]) else { continue }
    let mine = Dates.rfc822(input)?.timeIntervalSince1970
    expect("dates", close(mine, num(row[1]), 0.001), "parse_date(\(q(input))) = \(String(describing: mine)), Python \(String(describing: num(row[1])))")
}
for r in arr(golden["iso"]) {
    let row = arr(r)
    guard row.count == 2, let input = str(row[0]) else { continue }
    let mine = Dates.iso(input)?.timeIntervalSince1970
    expect("dates", close(mine, num(row[1]), 0.001), "parse_iso(\(q(input))) = \(String(describing: mine)), Python \(String(describing: num(row[1])))")
}
for r in arr(golden["normalize"]) {
    let row = arr(r)
    guard row.count == 2, let input = str(row[0]), let ref = str(row[1]) else { continue }
    expect("text", Text.normalizeTitle(input) == ref, "normalize_title(\(q(input))) = \(q(Text.normalizeTitle(input))), Python \(q(ref))")
}
for r in arr(golden["gdacs_titles"]) {
    let row = arr(r)
    guard row.count == 2, let input = str(row[0]), let ref = str(row[1]) else { continue }
    expect("text", Text.tidyGdacsTitle(input) == ref, "tidy_gdacs_title(\(q(input))) = \(q(Text.tidyGdacsTitle(input))), Python \(q(ref))")
}
for c in arr(golden["condense"]) {
    let o = obj(c)
    guard let input = str(o["in"]) else { continue }
    let mine = Text.condenseSteps(input)
    let refSteps = arr(o["steps"]).compactMap { $0 as? String }
    expect("condense", mine.steps == refSteps, "condense_steps(\(q(input))):\n    swift  \(mine.steps)\n    python \(refSteps)")
    expect("condense", mine.condensed == str(o["condensed"]), "condensed(\(q(input))) = \(q(mine.condensed)), Python \(q(str(o["condensed"])))")
    for (n, ref) in obj(o["trunc"]) {
        guard let limit = Int(n) else { continue }
        let cut = Text.truncateWords({ Py.len($0) <= limit }, mine.condensed)
        expect("condense", cut == str(ref), "truncate_words(\(limit), \(q(mine.condensed))) = \(q(cut)), Python \(q(str(ref)))")
    }
}

// ---- 5. keyword severity on every story in the downloaded feeds ------------------------------
for r in arr(golden["severity"]) {
    let o = obj(r)
    guard let t = str(o["t"]), let d = str(o["d"]) else { continue }
    for name in TM.newsCats {
        guard let cfg = Config.categories[name] else { continue }
        let mine = Score.severity(cfg, t, d)
        expect("severity", close(mine, num(o[name])), "\(name) severity of \(q(t)) = \(mine), Python \(num(o[name]) ?? -1)")
    }
}

// ---- 6. parsing the downloaded files ------------------------------------------------------------
let status = obj(golden["status"])
var fetched: [String: Fetched] = [:]
for (key, value) in status {
    let file = folder.appendingPathComponent("fixtures").appendingPathComponent(key.replacingOccurrences(of: ":", with: "_") + ".dat")
    if str(value) == "ok", let data = try? Data(contentsOf: file) {
        fetched[key] = .ok(data)
    } else {
        fetched[key] = .failed(str(value) ?? "missing")
    }
}
let okSources = status.values.filter { str($0) == "ok" }.count
print("Sources downloaded for the reference: \(okSources) of \(status.count)")
expect("sources", okSources >= status.count - 3, "only \(okSources) of \(status.count) sources could be downloaded on the build machine")

func label(for key: String) -> String {
    let parts = key.split(separator: ":").map(String.init)
    guard parts.count == 2, let cfg = Config.categories[parts[0]] else { return "" }
    return cfg.feeds.first { $0.key == parts[1] }?.label ?? parts[1]
}

for (key, ref) in obj(golden["items"]) {
    guard case .ok(let data)? = fetched[key] else {
        expect("parse", false, "\(key): no saved file")
        continue
    }
    do {
        let mine = try Parse.rssItems(data, label: label(for: key))
        let refItems = arr(ref).map { obj($0) }
        expect("parse", mine.count == refItems.count, "\(key): \(mine.count) stories, Python \(refItems.count)")
        for (a, b) in zip(mine, refItems) {
            expect("parse", a.title == str(b["title"]), "\(key) title \(q(a.title)) vs \(q(str(b["title"])))")
            expect("parse", a.desc == str(b["desc"]), "\(key) description of \(q(a.title)):\n    swift  \(q(a.desc))\n    python \(q(str(b["desc"])))")
            expect("parse", a.source == str(b["source"]), "\(key) source \(q(a.source)) vs \(q(str(b["source"])))")
            expect("parse", close(a.date?.timeIntervalSince1970, num(b["date"]), 1), "\(key) date of \(q(a.title)): \(String(describing: a.date)) vs \(String(describing: num(b["date"])))")
        }
    } catch {
        expect("parse", false, "\(key): could not read (\(error)); Python could")
    }
}
for (key, ref) in obj(golden["stories"]) {
    guard case .ok(let data)? = fetched[key] else { continue }
    do {
        let mine: [Story]
        switch key {
        case "CYB:CISA": mine = try Parse.kev(data, now: now)
        case "BIO:WHO": mine = try Parse.who(data, now: now)
        case "DIS:GDACS": mine = try Parse.gdacs(data, now: now)
        default: mine = try Parse.usgs(data)
        }
        let refStories = arr(ref).map { obj($0) }
        expect("parse", mine.count == refStories.count, "\(key): \(mine.count) items, Python \(refStories.count)")
        for (a, b) in zip(mine, refStories) {
            expect("parse", a.title == str(b["title"]) && close(a.sev, num(b["sev"])) && a.source == str(b["source"])
                    && close(a.date?.timeIntervalSince1970, num(b["date"]), 1),
                   "\(key): \(q(a.title)) sev \(a.sev) vs Python \(q(str(b["title"]))) sev \(num(b["sev"]) ?? -1)")
        }
    } catch {
        expect("parse", false, "\(key): could not read (\(error)); Python could")
    }
}
for (key, err) in obj(golden["parse_errors"]) {
    if case .ok(let data)? = fetched[key] {
        let failed: Bool
        switch key {
        case "CYB:CISA": failed = (try? Parse.kev(data, now: now)) == nil
        case "BIO:WHO": failed = (try? Parse.who(data, now: now)) == nil
        case "DIS:GDACS": failed = (try? Parse.gdacs(data, now: now)) == nil
        case "DIS:USGS": failed = (try? Parse.usgs(data)) == nil
        default: failed = (try? Parse.rssItems(data, label: "")) == nil
        }
        expect("parse", failed, "\(key): Python could not read it (\(str(err) ?? "")) but Swift could")
    }
}

// ---- 7. the whole pipeline -------------------------------------------------------------------------
let pipeline = obj(golden["pipeline"])
let scorer = Scorer(calibration: .empty())
let result = scorer.process(now: now, fetched: fetched, record: false)
var myScores: [String: Int] = [:]
var report: [String] = []
for c in TM.cats {
    let ref = obj(pipeline[c])
    let mine = result.results[c]
    if let m = mine { myScores[c] = m.score }
    report.append("\(c) \(mine.map { String($0.score) } ?? "--")/\(intOrNil(ref["score"]).map { String($0) } ?? "--")")
    expect("pipeline", mine?.score == intOrNil(ref["score"]), "\(c) score \(String(describing: mine?.score)), Python \(String(describing: intOrNil(ref["score"])))")
    let myHeadlines = Score.pickHeadlines(mine?.stories ?? []).map { $0.title }
    let refHeadlines = arr(ref["headlines"]).compactMap { $0 as? String }
    expect("pipeline", myHeadlines == refHeadlines, "\(c) headlines:\n    swift  \(myHeadlines)\n    python \(refHeadlines)")
    if c == "DIS" { continue }
    let comps = result.comps[c] ?? []
    let refComps = arr(ref["components"]).map { obj($0) }
    expect("pipeline", comps.count == refComps.count, "\(c): \(comps.count) components, Python \(refComps.count)")
    for (a, b) in zip(comps, refComps) {
        let sameKind = str(b["key"]) == a.key && str(b["kind"]) == a.kind && (b["ok"] as? Bool) == a.ok
        let sameCounts = intOrNil(b["items"]) == a.items && intOrNil(b["recent"]) == a.recent && intOrNil(b["hits"]) == a.hits
        let sameLevels = close(num(b["raw"]), a.raw) && close(num(b["ratio"]), a.ratio) && close(num(b["normal"]), a.normal)
        expect("pipeline", sameKind && sameCounts && sameLevels, "\(c) \(a.key): swift ok=\(a.ok) items=\(a.items) recent=\(a.recent) hits=\(a.hits) raw=\(a.raw) ratio=\(String(describing: a.ratio)); python \(b)")
    }
}
expect("pipeline", Score.gti(myScores) == intOrNil(pipeline["gti"]), "GTI \(String(describing: Score.gti(myScores))), Python \(String(describing: intOrNil(pipeline["gti"])))")
print("Scores, Swift/Python: " + report.joined(separator: "  ") + "  GTI \(Score.gti(myScores).map { String($0) } ?? "--")/\(intOrNil(pipeline["gti"]).map { String($0) } ?? "--")")

// ---- 8. engine: schedule, retries, saved values, rotation ------------------------------------------
let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("tm-test-\(UUID().uuidString)", isDirectory: true)
let engine = Engine(dataDir: tmp)
var snap = engine.snapshot()
expect("engine", Rotator().tick(wallNow(), snap) == nil, "loading screen until the first attempt")
let all4: [String: CatResult] = [
    "WAR": CatResult(score: 40, stories: [Story(sev: 4, date: Date(), title: "Missile strikes hit city", source: "BBC")]),
    "DIS": CatResult(score: 30, stories: []), "CYB": CatResult(score: 35, stories: []), "BIO": CatResult(score: 36, stories: []),
]
engine.finishSync(all4, error: nil)
snap = engine.snapshot()
expect("engine", snap.attempts == 1 && !snap.syncing && snap.failStreak == 0 && snap.lastSync != nil, "after a good sync")
expect("engine", abs(snap.nextSync - wallNow() - TM.refreshOK) < 5, "next sync in 15 minutes")
expect("engine", snap.gti == Score.gti(["WAR": 40, "DIS": 30, "CYB": 35, "BIO": 36]), "GTI after a sync")
expect("engine", snap.slot("WAR").headlines.first?.title == "Missile strikes hit city", "headline kept")
engine.finishSync(["WAR": CatResult(score: 45, stories: [])], error: "DIS: down")
snap = engine.snapshot()
expect("engine", snap.slot("WAR").score == 45 && snap.slot("WAR").prev == 40 && !snap.slot("WAR").stale, "updated category")
expect("engine", snap.slot("DIS").score == 30 && snap.slot("DIS").stale, "failed category keeps its last value, marked stale")
expect("engine", snap.failStreak == 1 && abs(snap.nextSync - wallNow() - 60) < 5, "first retry after 1 minute")
engine.finishSync([:], error: "offline")
snap = engine.snapshot()
expect("engine", snap.failStreak == 2 && abs(snap.nextSync - wallNow() - 120) < 5, "second retry after 2 minutes")
let again = Engine(dataDir: tmp)
expect("engine", again.loadSavedState(), "saved values load")
let snap2 = again.snapshot()
expect("engine", snap2.slot("WAR").score == 45 && snap2.slot("DIS").score == 30 && snap2.attempts == 1 && !snap2.syncing,
       "saved values: WAR \(String(describing: snap2.slot("WAR").score)) DIS \(String(describing: snap2.slot("DIS").score))")
expect("engine", abs(snap2.nextSync - wallNow() - TM.refreshOK) < 10, "fresh saved values wait for the next sync")

let rot = Rotator()
let t0 = 1_000_000.0
var views: [String] = []
var t = t0
for _ in 0..<12 {
    if let v = rot.tick(t, snap) { views.append("\(v.screen)\(v.index)") }
    t += 0.5
    while let v = rot.tick(t, snap), v.frac > 0.01 { t += 0.5 }
}
expect("engine", views.prefix(7) == ["MAIN0", "WAR0", "DIS0", "CYB0", "BIO0", "MAIN0", "WAR1"],
       "rotation order: \(views)")

engine.loadDemo()
snap = engine.snapshot()
expect("engine", snap.gti == Score.gti(["WAR": 41, "DIS": 22, "CYB": 37, "BIO": 52]) && snap.slot("CYB").stale, "sample data")

var cal = Calibration.empty()
for h in 0..<7 { cal.record("WAR:BBC", Double(h) / 10, Double(h) * 3600) }
cal.record("WAR:BBC", 9, 6 * 3600 + 60)                     // too soon after the last sample: ignored
expect("engine", cal.samples["WAR:BBC"]?.count == 7 && close(cal.median("WAR:BBC"), 0.3), "calibration samples and median")
expect("engine", cal.median("WAR:NPR") == nil && cal.baselineHours() == 0, "calibration needs every category")
try? FileManager.default.removeItem(at: tmp)

// ---- summary ------------------------------------------------------------------------------------------
var failures = 0
print("")
for s in sections {
    let c = counts[s] ?? [0, 0]
    failures += c[1]
    print("\(c[1] == 0 ? "PASS" : "FAIL")  \(s.padding(toLength: 10, withPad: " ", startingAt: 0)) \(c[0]) passed, \(c[1]) failed")
}
print(failures == 0 ? "\nAll core tests passed." : "\n\(failures) core test(s) failed.")
exit(failures == 0 ? 0 : 1)
