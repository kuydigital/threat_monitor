// THREAT MONITOR for macOS - configuration
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// Every value and keyword rule here is copied from threat_monitor.py; the
// tests in mac/Tests compare them with the Python version so the two can't
// drift apart.

import Foundation

enum TM {
    static let version = "3.4"
    static let syncDeadline: Double = 45          // a whole sync never takes longer
    static let requestTimeout: Double = 15        // seconds to wait for data, per request
    static let clockCheckSecs: Double = 60
    static let userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ThreatMonitor/3.4"

    static let refreshOK: Double = 900            // seconds between syncs when every source worked
    static let refreshRetryMin: Double = 60       // first retry after a failure; doubles up to refreshOK
    static let newsWindowHours: Double = 48
    static let kevWindowDays: Double = 7
    static let donWindowDays: Double = 30
    static let extraCacheHours: Double = 24

    static let gtiWeights: [String: Double] = ["WAR": 0.35, "CYB": 0.25, "DIS": 0.20, "BIO": 0.20]

    static let normalLevel: Double = 35
    static let normalK: Double = -log(1 - normalLevel / 100)   // ratio 1.0 -> normalLevel
    static let ratioCap: Double = 4.0
    static let minFeedStories = 5
    static let feedMinDenominator = 8
    static let feedNormalFloor: Double = 0.15
    static let defaultNormal: [String: [String: Double]] = [
        "WAR": ["BBC": 0.55, "ALJAZEERA": 0.8, "NPR": 0.5],
        "CYB": ["BBC": 0.3, "NPR": 0.2, "CISA": 0.3],
        "BIO": ["BBC": 0.4, "NPR": 0.35, "WHO": 0.5],
    ]

    static let stateMaxAge: Double = 6 * 3600
    static let calibVersion = 4
    static let calibDays: Double = 30
    static let calibMinSamples = 6
    static let calibSettled = 24
    static let calibSampleGap: Double = 55 * 60

    static let kevWeight = 0.05, kevCap = 1.0
    static let donWeight = 0.25, donCap = 1.0

    static let disRoutineMax = 1.0
    static let disRoutineCap = 5.0
    static let disScale = 20.0

    static let googleNews = "https://news.google.com/rss/search"
    static let googleParams: [(String, String)] = [("hl", "en-US"), ("gl", "US"), ("ceid", "US:en")]
    static let whoDonURL = "https://www.who.int/api/news/diseaseoutbreaknews?$orderby=PublicationDate%20desc&$top=20&$select=Title,PublicationDate,DonId"
    static let cisaKevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    static let gdacsURL = "https://www.gdacs.org/xml/rss.xml"
    static let usgsURL = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_week.geojson"

    static let gdacsGreenByType: [String: Double] = ["EQ": 0.5, "TC": 1.0, "FL": 0.5, "VO": 0.5, "DR": 0.5, "WF": 0.2]
    static let gdacsLevel: [String: Double] = ["orange": 6.0, "red": 15.0]
    static let usgsPager: [String: Double] = ["green": 0.5, "yellow": 3.0, "orange": 6.0, "red": 15.0]
    static let gdacsNS = "http://www.gdacs.org"

    static let cats = ["WAR", "DIS", "CYB", "BIO"]
    static let newsCats = ["WAR", "CYB", "BIO"]
    static let catNames: [String: String] = [
        "WAR": "WAR NEWS ALERT", "DIS": "DIS NEWS ALERT", "CYB": "CYB NEWS ALERT", "BIO": "BIO NEWS ALERT",
    ]
    static let emptyMsg: [String: String] = [
        "WAR": "No recent war alerts", "DIS": "No current disaster alerts",
        "CYB": "No recent cyber alerts", "BIO": "No recent bio alerts",
    ]

    // display
    static let mainSecs: Double = 12
    static let catSecs: Double = 8
    static let fadeSecs: Double = 0.25
    static let headlineMaxLines = 3
    static let headlineSizes: (big: Int, small: Int) = (21, 16)
    static let levels: [(limit: Int, name: String)] = [
        (30, "LOW"), (45, "GUARDED"), (60, "ELEVATED"), (75, "HIGH"), (101, "SEVERE"),
    ]
}

/// A news feed. Scored feeds are general news: the share of threat stories
/// in them is what gets measured. Google News is shown, never scored.
struct Feed {
    let key: String
    let base: String
    let params: [(String, String)]
    let label: String
    let windowHours: Double
    let scored: Bool

    init(key: String, base: String, params: [(String, String)] = [], label: String,
         windowHours: Double = TM.newsWindowHours, scored: Bool = true) {
        self.key = key
        self.base = base
        self.params = params
        self.label = label
        self.windowHours = windowHours
        self.scored = scored
    }

    var url: URL? {
        if params.isEmpty { return URL(string: base) }
        var c = URLComponents(string: base)
        c?.queryItems = params.map { URLQueryItem(name: $0.0, value: $0.1) }
        return c?.url
    }

    static func bbc(_ section: String) -> Feed {
        Feed(key: "BBC", base: "https://feeds.bbci.co.uk/news/\(section)/rss.xml", label: "BBC")
    }

    /// NPR posts fewer stories a day, so it gets a longer window.
    static func npr(_ code: Int, _ windowHours: Double) -> Feed {
        Feed(key: "NPR", base: "https://feeds.npr.org/\(code)/rss.xml", label: "NPR", windowHours: windowHours)
    }

    static func google(_ query: String) -> Feed {
        Feed(key: "GOOGLE", base: TM.googleNews, params: TM.googleParams + [("q", query)],
             label: "Google News", scored: false)
    }

    static let aljazeera = Feed(key: "ALJAZEERA", base: "https://www.aljazeera.com/xml/rss/all.xml", label: "Al Jazeera")
}

/// A news category. A story's severity is its HIGHEST matching rule weight;
/// exclusions are blanked out of the text before the rules run.
struct Category {
    let name: String
    let feeds: [Feed]
    let extra: String?
    let rules: [(rx: Rx, weight: Double)]
    let exclude: Rx

    init(_ name: String, feeds: [Feed], extra: String? = nil, rules: [(String, Double)], exclude: [String]) {
        self.name = name
        self.feeds = feeds
        self.extra = extra
        self.rules = rules.map { (rx: Rx($0.0, ci: true), weight: $0.1) }
        self.exclude = Rx(exclude.joined(separator: "|"), ci: true)
    }
}

enum Config {
    private static let warFeeds: [Feed] = [Feed.bbc("world"), Feed.aljazeera, Feed.npr(1004, 72),
            Feed.google("war OR airstrike OR missile OR invasion OR shelling when:1d")]
    private static let warRules: [(String, Double)] = [
        (#"\bnuclear (strike|attack|weapons? test|threat)s?\b"#, 6),
        (#"\b(invasion|invades?|invaded|massacres?)\b"#, 5),
        (#"\b(air ?strikes?|drone strikes?|drone attacks?|missile (strikes?|attacks?)|ballistic missiles?|rocket (fire|attacks?))\b"#, 4),
        (#"\b(shelling|bombardment|bombing|bombed|war crimes?)\b"#, 4),
        (#"\b(war|wars|warfare|missiles?)\b"#, 3),
        (#"\b(fighting|clashes|genocide|insurgency)\b"#, 3),
        (#"\bstrikes? (on|in|against|kill|kills|killed|hit|hits)\b"#, 3),
        (#"\b(troops|soldiers?|offensive|front ?line|ceasefire|cease-fire|hostages?|gunmen|militias?|armed groups?|drones?|displaced|wounded|settlers?)\b"#, 2),
        (#"\b(hamas|hezbollah|houthis?|taliban|islamic state|isis|al-shabab|boko haram|wagner group)\b"#, 2),
        (#"\b(attacks?|attacked)\b"#, 2),
        (#"\b(military|army|navy|armed forces|militants?|insurgents?|rebels?|warships?|killed)\b"#, 1),
    ]
    private static let warExclude: [String] = [
        #"\bstar wars\b"#, #"\b(price|trade|tariff|bidding|console|streaming|talent|format) wars?\b"#,
        #"\bculture wars?\b"#, #"\bwar of words\b"#, #"\bwar chest\b"#,
        #"\bwar on (drugs|poverty|cancer|waste|obesity)\b"#,
        #"\bwar (film|movie|drama|game|memorial|museum|veteran|anniversary)s?\b"#,
        #"\bworld war (i|ii|one|two|1|2)\b"#,
        #"\boffensive (remarks?|comments?|language|jokes?|posts?|tweets?|content|messages?|chants?|coordinator|line|lineman)\b"#,
        #"\bfront ?-?line (workers?|staff|nurses?|doctors?|services?|health|care)\b"#,
        #"\bshelling out\b"#,
        // labour strikes, not military strikes
        #"\b(rail|train|tube|bus|teachers?|doctors?|nurses?|workers?|union|general|hunger|labou?r|national|postal|port|dock|airline|pilots?|staff) strikes?\b"#,
        #"\bon strike\b"#, #"\bstrikes? (action|ballot|vote|over (pay|wages|pensions))\b"#,
        // non-military attacks
        #"\b(heart|panic|shark|dog|bear|asthma|anxiety|cyber|ransomware|hacker|phishing|personal|verbal|online|racist|scathing|bitter|acid)[ -]attacks?\b"#,
        #"\battack(s|ed)?( on| against)? (the )?(media|press|critics?|opponents?|democrats|republicans|rivals?|judges?|reporters?)\b"#,
        #"\b(attacking|attack) (midfielder|player|football|play|third|line)\b"#,
        #"\bfighting (fit|chance|spirit|talk|inflation|crime|fires?|wildfires?|cancer|corruption|poverty|obesity|fraud)\b"#,
        #"\bmilitary (service exemptions?|exemptions?|parade|band|academy|school|history|museum|style|grade|tattoo)\b"#,
        #"\bdrones? (delivery|deliveries|show|light show|photography|racing|footage)\b"#,
        #"\bkilled (in|by) (a |an |the )?(bus |car |train |road |plane |motorway )?(crash|accident|fire|flood|landslide|avalanche|storm|lightning|collision|stampede)\b"#,
    ]

    private static let cybFeeds: [Feed] = [Feed.bbc("technology"), Feed.npr(1019, 168),
            Feed.google(#"cyberattack OR ransomware OR "data breach" OR "zero-day" when:1d"#)]
    private static let cybRules: [(String, Double)] = [
        (#"\bransomware\b"#, 5),
        (#"\bzero[- ]?days?\b"#, 5),
        (#"\bcyber[- ]?attacks?\b"#, 5),
        (#"\b(data breach(es)?|breached)\b"#, 4),
        (#"\b(actively exploited|exploited in the wild)\b"#, 4),
        (#"\b(hack|hacked|hackers?|hacking)\b"#, 3),
        (#"\b(malware|botnets?|spyware|ddos|phishing|wiper)\b"#, 3),
        (#"\b(vulnerabilit(y|ies)|cve-\d{4}-\d+)\b"#, 1.5),
        (#"\bcyber ?security\b"#, 1),
    ]
    private static let cybExclude: [String] = [
        #"\b(life|growth|productivity|budget|travel|kitchen) hacks?\b"#,
        #"\bhacks? (for|to)\b"#,
        #"\bbreached (the )?(rules?|contract|agreement|code|guidelines|terms|law|regulations|covenants?|duty)\b"#,
        #"\b(windscreen|windshield) wipers?\b"#,
    ]

    private static let bioFeeds: [Feed] = [Feed.bbc("health"), Feed.npr(1128, 168),
            Feed.google("outbreak OR epidemic OR pandemic OR ebola OR cholera OR H5N1 OR mpox when:2d")]
    private static let bioRules: [(String, Double)] = [
        (#"\bpublic health emergency\b"#, 6),
        (#"\b(ebola|marburg|nipah|plague|anthrax)\b"#, 5),
        (#"\bpandemic\b"#, 4),
        (#"\b(outbreaks?)\b"#, 4),
        (#"\b(mpox|monkeypox|cholera|h5n\d|bird flu|avian (flu|influenza)|polio)\b"#, 4),
        (#"\bepidemic\b"#, 3),
        (#"\b(measles|dengue|meningitis|diphtheria|yellow fever)\b"#, 3),
        (#"\b(pathogens?|novel virus|new (variant|strain))\b"#, 3),
        (#"\b(flu|influenza|covid(-19)?|coronavirus|rsv|norovirus|tuberculosis|malaria|whooping cough|mers|sars)\b"#, 2),
        (#"\b(virus|infections?)\b"#, 1),
    ]
    private static let bioExclude: [String] = [
        #"\b(post|pre)-pandemic\b"#, #"\b(since|during|after|before)( the)?( covid)? pandemic\b"#,
        #"\bpandemic[- ]era\b"#,
        #"\boutbreaks? of (violence|fighting|war|protests?|unrest)\b"#,
        #"\b(opioid|loneliness|obesity|vaping|gun violence|misinformation) epidemic\b"#,
        #"\bcomputer virus\b"#,
        #"\bnew strain (on|for)\b"#,
    ]

    static let categories: [String: Category] = [
        "WAR": Category("WAR", feeds: warFeeds, rules: warRules, exclude: warExclude),
        "CYB": Category("CYB", feeds: cybFeeds, extra: "CISA", rules: cybRules, exclude: cybExclude),
        "BIO": Category("BIO", feeds: bioFeeds, extra: "WHO", rules: bioRules, exclude: bioExclude),
    ]

    /// Weight per item and cap of the official extra sources.
    static func extraWeight(_ name: String) -> (weight: Double, cap: Double) {
        name == "CISA" ? (TM.kevWeight, TM.kevCap) : (TM.donWeight, TM.donCap)
    }

    static func extraURL(_ name: String) -> String {
        name == "CISA" ? TM.cisaKevURL : TM.whoDonURL
    }

    /// Calibration keys, e.g. "WAR:BBC" (scored feeds and extra sources).
    static let componentKeys: [String] = {
        var keys: [String] = []
        for name in TM.newsCats {
            guard let cfg = categories[name] else { continue }
            for f in cfg.feeds where f.scored { keys.append("\(name):\(f.key)") }
            if let e = cfg.extra { keys.append("\(name):\(e)") }
        }
        return keys
    }()
}
