// THREAT MONITOR for macOS - background updates and shared state
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// One Engine per process, shared by every screen's view. It downloads all
// sources at once with a hard time limit (45 s), every 15 minutes, retrying
// sooner after a failure. The last values are saved so the screensaver shows
// them instantly next time; nothing here can leave the screen stuck on
// "Contacting sources".

import Foundation

struct CatSlot {
    var score: Int?
    var prev: Int?
    var headlines: [Story] = []
    var stale = false
}

struct Snapshot {
    var cats: [String: CatSlot]
    var gti: Int?
    var gtiPrev: Int?
    var lastSync: Double?         // wall clock (seconds since 1970) of the last sync with any data
    var syncing: Bool
    var failStreak: Int
    var baseline: Int
    var attempts: Int
    var lastError: String?
    var nextSync: Double          // wall clock

    func slot(_ c: String) -> CatSlot {
        cats[c] ?? CatSlot()
    }
}

/// Downloads every source at once.
enum Sources {
    struct Job {
        let key: String           // "WAR:BBC", "CYB:CISA", "DIS:GDACS", ...
        let url: URL?
    }

    static func jobs() -> [Job] {
        var out: [Job] = []
        for name in TM.newsCats {
            guard let cfg = Config.categories[name] else { continue }
            for f in cfg.feeds { out.append(Job(key: "\(name):\(f.key)", url: f.url)) }
            if let e = cfg.extra { out.append(Job(key: "\(name):\(e)", url: URL(string: Config.extraURL(e)))) }
        }
        out.append(Job(key: "DIS:GDACS", url: URL(string: TM.gdacsURL)))
        out.append(Job(key: "DIS:USGS", url: URL(string: TM.usgsURL)))
        return out
    }

    static func makeSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = TM.requestTimeout
        cfg.timeoutIntervalForResource = TM.syncDeadline - 5
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.waitsForConnectivity = false
        cfg.httpAdditionalHeaders = ["User-Agent": TM.userAgent]
        return URLSession(configuration: cfg)
    }

    /// Fetch everything in parallel and wait at most `timeout` seconds in
    /// total; a source that hangs is abandoned, never waited on.
    /// Collects the answers (filled in from URLSession's own threads).
    private final class Answers: @unchecked Sendable {
        private let lock = NSLock()
        private var results: [String: Fetched] = [:]
        func set(_ key: String, _ value: Fetched) {
            lock.lock()
            results[key] = value
            lock.unlock()
        }
        func all() -> [String: Fetched] {
            lock.lock()
            defer { lock.unlock() }
            return results
        }
    }

    static func fetchAll(session: URLSession, timeout: Double) -> [String: Fetched] {
        let group = DispatchGroup()
        let answers = Answers()
        var tasks: [URLSessionDataTask] = []
        for job in jobs() {
            guard let url = job.url else {
                answers.set(job.key, .failed("bad address"))
                continue
            }
            var req = URLRequest(url: url)
            req.setValue(TM.userAgent, forHTTPHeaderField: "User-Agent")
            let key = job.key
            group.enter()
            let task = session.dataTask(with: req) { data, response, error in
                if let error = error {
                    answers.set(key, .failed(error.localizedDescription))
                } else if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                    answers.set(key, .failed("HTTP \(http.statusCode)"))
                } else {
                    answers.set(key, .ok(data ?? Data()))
                }
                group.leave()
            }
            tasks.append(task)
            task.resume()
        }
        _ = group.wait(timeout: .now() + timeout)
        var out = answers.all()
        for task in tasks where task.state == .running { task.cancel() }
        for job in jobs() where out[job.key] == nil {
            out[job.key] = .failed("no answer within \(Int(timeout))s")
        }
        return out
    }
}

/// The values saved between runs (threat_state.json).
struct SavedState: Codable {
    struct SavedStory: Codable {
        var sev: Double
        var date: Double?
        var title: String
        var source: String
    }
    struct SavedCat: Codable {
        var score: Int?
        var prev: Int?
        var headlines: [SavedStory]
    }
    var version: Int
    var gti: Int?
    var gti_prev: Int?
    var last_sync: Double?
    var cats: [String: SavedCat]
}

final class Engine {
    static let shared = Engine()

    let dataDir: URL
    var calibURL: URL { dataDir.appendingPathComponent("threat_calibration.json") }
    var stateURL: URL { dataDir.appendingPathComponent("threat_state.json") }
    var logURL: URL { dataDir.appendingPathComponent("screensaver.log") }

    private let lock = NSLock()
    private var cats: [String: CatSlot] = [:]
    private var gti: Int?
    private var gtiPrev: Int?
    private var nextDue: Double = 0           // monotonic time of the next sync
    private var lastSync: Double?
    private var syncing = true
    private var failStreak = 0
    private var baseline = 0
    private var attempts = 0
    private var lastError: String?
    private var activeViews = 0
    private var demo = false
    private var booted = false

    private let queue = DispatchQueue(label: "com.kuydigital.ThreatMonitor.engine", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var clockOffset: Double = 0
    private let scorer = Scorer(calibration: .empty())
    private lazy var session: URLSession = Sources.makeSession()

    init(dataDir: URL? = nil) {
        if let dir = dataDir {
            self.dataDir = dir
        } else if let env = ProcessInfo.processInfo.environment["THREAT_MONITOR_DATA"], !env.isEmpty {
            self.dataDir = URL(fileURLWithPath: env, isDirectory: true)
        } else {
            // Inside the screensaver's sandbox this is its own container folder.
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
            self.dataDir = support.appendingPathComponent("ThreatMonitor", isDirectory: true)
        }
        for c in TM.cats { cats[c] = CatSlot() }
    }

    // ---- lifetime -----------------------------------------------------------
    /// A screensaver view started: load saved data and start updating.
    func viewStarted() {
        lock.lock()
        activeViews += 1
        let first = !booted
        booted = true
        lock.unlock()
        if first { queue.async { self.boot() } }
    }

    /// A view stopped; updates pause while no view is showing.
    func viewStopped() {
        lock.lock()
        activeViews = max(0, activeViews - 1)
        lock.unlock()
    }

    private func boot() {
        try? FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
        Log.shared.configure(file: logURL, echo: false)
        tmLog("INFO", "Threat Monitor \(TM.version) screensaver starting (data folder \(dataDir.path))")
        scorer.calibration = Calibration.load(from: calibURL)
        lock.lock()
        let isDemo = demo
        baseline = scorer.calibration.baselineHours()
        lock.unlock()
        if !isDemo { _ = loadSavedState() }
        clockOffset = wallNow() - monotonicNow()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: 5.0, leeway: .seconds(1))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    /// Every 5 s: sync when due, or right after the clock was changed.
    private func tick() {
        lock.lock()
        let active = activeViews > 0
        let isDemo = demo
        var due = nextDue - monotonicNow() <= 0
        lock.unlock()
        if !active || isDemo { return }
        let offset = wallNow() - monotonicNow()
        if abs(offset - clockOffset) > 300 {
            tmLog("INFO", "system clock changed; syncing now")
            clockOffset = offset
            due = true
        }
        if due { syncNow() }
    }

    /// Download and score everything once (runs on the engine's queue, or
    /// directly from the tests).
    func syncNow() {
        lock.lock()
        syncing = true
        lock.unlock()
        let now = Date()
        let fetched = Sources.fetchAll(session: session, timeout: TM.syncDeadline)
        let out = scorer.process(now: now, fetched: fetched, record: true)
        scorer.calibration.save(to: calibURL)
        finishSync(out.results, error: out.errors.isEmpty ? nil : out.errors.joined(separator: "; "))
    }

    /// Record the outcome of a sync attempt so the display always moves on.
    func finishSync(_ results: [String: CatResult], error: String?) {
        lock.lock()
        for c in TM.cats {
            var slot = cats[c] ?? CatSlot()
            if let r = results[c] {
                slot.prev = slot.score
                slot.score = r.score
                slot.headlines = Score.pickHeadlines(r.stories)
                slot.stale = false
            } else {
                slot.stale = slot.score != nil            // keep the last good value
            }
            cats[c] = slot
        }
        gtiPrev = gti
        gti = Score.gti(currentScores())
        baseline = scorer.calibration.baselineHours()
        attempts += 1
        lastError = error
        if !results.isEmpty { lastSync = wallNow() }
        let delay: Double
        if results.count == TM.cats.count {
            failStreak = 0
            delay = TM.refreshOK
        } else {
            failStreak += 1
            delay = min(TM.refreshOK, TM.refreshRetryMin * pow(2, Double(min(failStreak - 1, 20))))
        }
        nextDue = monotonicNow() + delay
        syncing = false
        lock.unlock()
        if !results.isEmpty { saveState() }
    }

    private func currentScores() -> [String: Int] {
        var s: [String: Int] = [:]
        for c in TM.cats { if let v = cats[c]?.score { s[c] = v } }
        return s
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(cats: cats, gti: gti, gtiPrev: gtiPrev, lastSync: lastSync, syncing: syncing,
                        failStreak: failStreak, baseline: baseline, attempts: attempts, lastError: lastError,
                        nextSync: wallNow() + max(0, nextDue - monotonicNow()))
    }

    // ---- saved values (instant start) -----------------------------------------
    func saveState() {
        lock.lock()
        var saved: [String: SavedState.SavedCat] = [:]
        for c in TM.cats {
            let slot = cats[c] ?? CatSlot()
            saved[c] = SavedState.SavedCat(score: slot.score, prev: slot.prev, headlines: slot.headlines.map {
                SavedState.SavedStory(sev: $0.sev, date: $0.date?.timeIntervalSince1970, title: $0.title, source: $0.source)
            })
        }
        let state = SavedState(version: TM.calibVersion, gti: gti, gti_prev: gtiPrev, last_sync: lastSync, cats: saved)
        lock.unlock()
        do {
            try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
            try JSONEncoder().encode(state).write(to: stateURL, options: .atomic)
        } catch {
            tmLog("WARN", "could not save \(stateURL.lastPathComponent): \(error.localizedDescription)")
        }
    }

    /// Show the last saved values straight away. Values younger than one sync
    /// interval are used as they are; older ones are shown while a fresh sync runs.
    @discardableResult
    func loadSavedState() -> Bool {
        guard let data = try? Data(contentsOf: stateURL),
              let saved = try? JSONDecoder().decode(SavedState.self, from: data),
              saved.version == TM.calibVersion, let last = saved.last_sync else { return false }
        let age = wallNow() - last
        guard age >= 0 && age <= TM.stateMaxAge else { return false }
        var loaded: [String: CatSlot] = [:]
        for c in TM.cats {
            guard let s = saved.cats[c] else { return false }
            loaded[c] = CatSlot(score: s.score, prev: s.prev, headlines: s.headlines.map {
                Story(sev: $0.sev, date: $0.date.map { Date(timeIntervalSince1970: $0) }, title: $0.title, source: $0.source)
            }, stale: false)
        }
        let fresh = age < TM.refreshOK
        lock.lock()
        attempts += 1
        cats = loaded
        gti = Score.gti(currentScores())
        gtiPrev = saved.gti_prev
        lastSync = last
        nextDue = monotonicNow() + (fresh ? TM.refreshOK - age : 0)
        syncing = !fresh
        baseline = scorer.calibration.baselineHours()
        lock.unlock()
        tmLog("INFO", "loaded values from \(Int(age / 60)) min ago (\(fresh ? "current" : "refreshing now"))")
        return true
    }

    // ---- sample data (tests and the README screenshots) ---------------------------
    func loadDemo() {
        let now = Date()
        func h(_ hours: Double) -> Date { now.addingTimeInterval(-hours * 3600) }
        let demoData: [(String, Int, Int, Story)] = [
            ("WAR", 41, 37, Story(sev: 4, date: h(2), title: "Missile strikes hit eastern city overnight as air defences intercept drones", source: "BBC")),
            ("DIS", 22, 22, Story(sev: 1, date: h(5), title: "Green notification for tropical cyclone KOGUMA-26", source: "GDACS")),
            ("CYB", 37, 45, Story(sev: 5, date: h(3), title: "Hospital network hit by ransomware attack, appointments cancelled", source: "Reuters")),
            ("BIO", 52, 48, Story(sev: 5, date: h(290), title: "WHO outbreak notice: Ebola disease caused by Bundibugyo virus - Democratic Republic of the Congo", source: "WHO")),
        ]
        lock.lock()
        demo = true
        var now_: [String: Int] = [:]
        var prev: [String: Int] = [:]
        for (c, score, before, story) in demoData {
            cats[c] = CatSlot(score: score, prev: before, headlines: [story], stale: c == "CYB")
            now_[c] = score
            prev[c] = before
        }
        gti = Score.gti(now_)
        gtiPrev = Score.gti(prev)
        lastSync = wallNow() - 120
        nextDue = monotonicNow() + 780
        syncing = false
        failStreak = 0
        baseline = 9
        attempts = 1
        lastError = nil
        lock.unlock()
    }

    /// The current state as JSON (read by mac/Tests/saver_check.m).
    func statusJSON() -> String {
        let s = snapshot()
        func j(_ v: Int?) -> Any { v.map { $0 as Any } ?? NSNull() }
        var cats: [String: Any] = [:]
        for c in TM.cats {
            let slot = s.slot(c)
            let entry: [String: Any] = [
                "score": j(slot.score), "prev": j(slot.prev), "stale": slot.stale,
                "headlines": slot.headlines.map { "\($0.title) [\($0.source)]" },
            ]
            cats[c] = entry
        }
        let obj: [String: Any] = [
            "cats": cats, "gti": j(s.gti), "attempts": s.attempts, "syncing": s.syncing,
            "failStreak": s.failStreak, "baseline": s.baseline,
            "lastSync": s.lastSync.map { $0 as Any } ?? NSNull(),
            "lastError": s.lastError.map { $0 as Any } ?? NSNull(),
            "dataDir": dataDir.path, "version": TM.version,
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }
}

/// Which screen is showing: MAIN, then each category, on a timer. Shared by
/// every screen so they all show the same thing.
struct RotView {
    let screen: String
    let index: Int
    let frac: Double
}

final class Rotator {
    static let shared = Rotator()

    let screens = ["MAIN"] + TM.cats
    private(set) var idx = 0
    private(set) var tSwitch = wallNow()
    private var rot: [String: Int] = [:]
    private var loaded = false

    init() {
        for c in TM.cats { rot[c] = -1 }
    }

    func go(_ step: Int, _ now: Double) {
        guard loaded else { return }
        idx = ((idx + step) % screens.count + screens.count) % screens.count
        let name = screens[idx]
        if let r = rot[name] { rot[name] = r + 1 }
        tSwitch = now
    }

    private func duration() -> Double {
        screens[idx] == "MAIN" ? TM.mainSecs : TM.catSecs
    }

    /// nil while the very first sync is running; after any attempt - even a
    /// failed one - the dashboard is shown, with "--" where there is no data.
    func tick(_ now: Double, _ snap: Snapshot) -> RotView? {
        if snap.lastSync == nil && snap.attempts == 0 { return nil }
        if !loaded {
            loaded = true
            idx = 0
            tSwitch = now
        }
        if now - tSwitch >= duration() { go(1, now) }
        let name = screens[idx]
        return RotView(screen: name, index: max(0, rot[name] ?? 0), frac: (now - tSwitch) / duration())
    }
}

/// Fetch every source once and explain each score (like threat_monitor.py
/// --check). Changes nothing on disk.
enum CheckReport {
    static func run() -> String {
        var out: [String] = []
        let now = Date()
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "en_US_POSIX")
        fmt.timeZone = Dates.utc
        fmt.dateFormat = "yyyy-MM-dd HH:mm"
        let engine = Engine()
        let scorer = Scorer(calibration: Calibration.load(from: engine.calibURL))
        out.append("Threat Monitor \(TM.version) (macOS) source check - clock \(fmt.string(from: now)) UTC")
        out.append("Data folder: \(engine.dataDir.path)   learned history: \(scorer.calibration.baselineHours()) h")
        out.append("Fetching all sources (up to \(Int(TM.syncDeadline)) s)...\n")
        let t0 = monotonicNow()
        let fetched = Sources.fetchAll(session: Sources.makeSession(), timeout: TM.syncDeadline)
        func pad(_ s: String, _ n: Int) -> String { s.count >= n ? s : s + String(repeating: " ", count: n - s.count) }
        func rpad(_ s: String, _ n: Int) -> String { s.count >= n ? s : String(repeating: " ", count: n - s.count) + s }
        for name in TM.newsCats {
            let r = scorer.category(name, now: now, fetched: fetched)
            var comps = r.comps
            var result: String
            do {
                result = "\(Score.fromRatio(try scorer.combine(name, &comps)))"
            } catch {
                result = "--  (\(error))"
            }
            out.append("\(name)  ->  \(result)")
            for c in comps {
                if c.kind == "headlines" {
                    out.append("   \(pad(c.label, 12)) " + (c.note.isEmpty ? "\(c.hits) matching headlines (shown on screen, not scored)" : c.note))
                } else if !c.ok {
                    out.append("   \(pad(c.label, 12)) NOT USED: \(c.note)  (\(c.items) stories in feed)")
                } else {
                    var line = "   \(pad(c.label, 12)) \(rpad("\(c.recent)", 3)) recent, \(rpad("\(c.hits)", 2)) threat-related, level \(String(format: "%.2f", c.raw))"
                    if let ratio = c.ratio, let normal = c.normal {
                        line += "  vs normal \(String(format: "%.2f", normal)) (\(c.learned == true ? "learned" : "starting guess")) = \(String(format: "%.2f", ratio))x"
                    }
                    out.append(line)
                }
            }
            for h in Score.pickHeadlines(r.stories) {
                out.append("      - \(String(h.title.prefix(100)))  [\(h.source)]")
            }
            out.append("")
        }
        for key in ["DIS:GDACS", "DIS:USGS"] {
            let label = String(key.dropFirst(4))
            switch fetched[key] ?? .failed("not fetched") {
            case .failed(let m):
                out.append("   \(pad(label, 12)) failed: \(m)")
            case .ok(let data):
                var parsed: [Story]?
                if key == "DIS:GDACS" {
                    parsed = try? Parse.gdacs(data, now: now)
                } else {
                    parsed = try? Parse.usgs(data)
                }
                out.append("   \(pad(label, 12)) " + (parsed.map { "\($0.count) current events" } ?? "failed: could not read the data"))
            }
        }
        do {
            let d = try scorer.disasters(now: now, fetched: fetched)
            out.append("DIS  ->  \(d.score)")
            for h in Score.pickHeadlines(d.stories) {
                out.append("      - \(String(h.title.prefix(100)))  [\(h.source)]")
            }
        } catch {
            out.append("DIS  ->  --  (\(error))")
        }
        out.append("\nDone in \(String(format: "%.1f", monotonicNow() - t0)) s.")
        return out.joined(separator: "\n")
    }
}
