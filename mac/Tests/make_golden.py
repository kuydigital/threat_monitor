#!/usr/bin/env python3
"""Reference results for the macOS screensaver's tests.

Downloads every source once, then records what threat_monitor.py (the
original Python version) makes of exactly those downloads: parsed stories,
keyword severities, condensed headlines, components and scores. The Swift
tests (mac/Tests/CoreTests/main.swift) run the port on the same files and
must agree. Run from the repository root:

    python3 mac/Tests/make_golden.py OUTPUT_FOLDER

Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, os.getcwd())
import requests                    # noqa: E402
import threat_monitor as tm        # noqa: E402

tm.LOG_STDOUT = False
OUT = sys.argv[1]
FIX = os.path.join(OUT, "fixtures")
os.makedirs(FIX, exist_ok=True)


def jobs():
    out = []
    for name, cfg in tm.CATEGORIES.items():
        for f in cfg["feeds"]:
            out.append((f"{name}:{f['key']}", f["url"], f["params"]))
        if cfg.get("extra"):
            out.append((f"{name}:{cfg['extra']}", {"CISA": tm.CISA_KEV_URL, "WHO": tm.WHO_DON_URL}[cfg["extra"]], None))
    out.append(("DIS:GDACS", "https://www.gdacs.org/xml/rss.xml", None))
    out.append(("DIS:USGS", "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_week.geojson", None))
    return out


def fixture(key):
    return os.path.join(FIX, key.replace(":", "_") + ".dat")


# ---- 1. download every source once ------------------------------------------
status, by_request = {}, {}
for key, url, params in jobs():
    try:
        r = requests.get(url, params=params, headers=tm.HEADERS, timeout=tm.TIMEOUT)
        r.raise_for_status()
        with open(fixture(key), "wb") as f:
            f.write(r.content)
        status[key] = "ok"
    except Exception as e:
        status[key] = f"error: {e}"
    by_request[(url, json.dumps(params, sort_keys=True))] = key
    print(f"{key:<15} {status[key][:90]}", flush=True)

now = datetime.now(timezone.utc).replace(microsecond=0)


class Saved:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        pass

    def json(self):
        return json.loads(self.content)


def saved_get(url, params=None, headers=None, timeout=None):
    key = by_request[(url, json.dumps(params, sort_keys=True))]
    if status[key] != "ok":
        raise RuntimeError(status[key])
    with open(fixture(key), "rb") as f:
        return Saved(f.read())


tm.requests.get = saved_get       # from here on, everything reads the saved files


def ts(d):
    return d.timestamp() if d else None


def flags(rx):
    return bool(rx.flags & re.I)


g = {"now": now.timestamp(), "status": status, "python": sys.version.split()[0]}

# ---- 2. configuration (so the two versions can't drift apart) ---------------
g["patterns"] = {
    name: {"rules": [[rx.pattern, w, flags(rx)] for rx, w in cfg["rules"]],
           "exclude": [cfg["exclude"].pattern, flags(cfg["exclude"])]}
    for name, cfg in tm.CATEGORIES.items()}
g["condense_patterns"] = {
    "label": [tm._LABEL_RE.pattern, flags(tm._LABEL_RE)],
    "bracket": [tm._BRACKET_RE.pattern, flags(tm._BRACKET_RE)],
    "tails": [[r.pattern, flags(r)] for r in tm._TAIL_RES],
    "lead": [tm._LEAD_ATTR_RE.pattern, flags(tm._LEAD_ATTR_RE)],
    "abbrev": [[r.pattern, re.sub(r"\\(\d)", r"$\1", repl), flags(r)] for r, repl in tm._ABBREVIATIONS],
    "filler": [tm._FILLER_RE.pattern, flags(tm._FILLER_RE)],
    "clause": [tm._CLAUSE_RE.pattern, flags(tm._CLAUSE_RE)],
    "dash": [tm._DASH_RE.pattern, flags(tm._DASH_RE)],
}
g["feeds"] = {name: [{"key": f["key"], "label": f["label"], "window": f["window"], "scored": f["scored"],
                      "url": f["url"], "params": [[k, v] for k, v in (f["params"] or {}).items()]}
                     for f in cfg["feeds"]]
              for name, cfg in tm.CATEGORIES.items()}
g["extras"] = {name: cfg.get("extra") for name, cfg in tm.CATEGORIES.items()}
g["constants"] = {k: getattr(tm, k) for k in [
    "SYNC_DEADLINE", "REFRESH_OK", "REFRESH_RETRY_MIN", "NEWS_WINDOW_HOURS", "KEV_WINDOW_DAYS",
    "DON_WINDOW_DAYS", "EXTRA_CACHE_HOURS", "NORMAL_LEVEL", "NORMAL_K", "RATIO_CAP", "MIN_FEED_STORIES",
    "FEED_MIN_DENOMINATOR", "FEED_NORMAL_FLOOR", "STATE_MAX_AGE", "CALIB_VERSION", "CALIB_DAYS",
    "CALIB_MIN_SAMPLES", "CALIB_SETTLED", "CALIB_SAMPLE_GAP", "KEV_WEIGHT", "KEV_CAP", "DON_WEIGHT",
    "DON_CAP", "DIS_ROUTINE_MAX", "DIS_ROUTINE_CAP", "DIS_SCALE", "MAIN_SECS", "CAT_SECS", "FADE_SECS",
    "HEADLINE_MAX_LINES", "CLAUSE_MIN_WORDS", "WHO_DON_URL", "CISA_KEV_URL", "GOOGLE_NEWS",
    "GTI_WEIGHTS", "DEFAULT_NORMAL", "GDACS_GREEN_BY_TYPE", "GDACS_LEVEL", "USGS_PAGER", "CAT_NAMES",
    "EMPTY_MSG", "MMI_WORDS", "CATS"]}
g["constants"]["HEADLINE_SIZES"] = list(tm.HEADLINE_SIZES)
g["constants"]["LEVELS"] = [[limit, name, list(color)] for limit, name, color in tm.LEVELS]
g["constants"]["DANGLING"] = sorted(tm._DANGLING)
g["constants"]["COMPONENT_KEYS"] = sorted(tm.COMPONENT_KEYS)

# ---- 3. parsing ---------------------------------------------------------------
fetched = tm.fetch_sources(now)
g["items"], g["stories"], g["parse_errors"] = {}, {}, {}
for (name, key), (st, val) in fetched.items():
    k = f"{name}:{key}"
    if st != "ok":
        if status[k] == "ok":
            g["parse_errors"][k] = str(val)
        continue
    if k in ("CYB:CISA", "BIO:WHO", "DIS:GDACS", "DIS:USGS"):
        g["stories"][k] = [{"sev": s["sev"], "date": ts(s["date"]), "title": s["title"], "source": s["source"]}
                           for s in val]
    else:
        g["items"][k] = [{"title": i["title"], "desc": i["desc"], "date": ts(i["date"]), "source": i["source"]}
                         for i in val]

# ---- 4. text handling on every headline -----------------------------------------
titles, pairs = [], []
for items in g["items"].values():
    for i in items:
        titles.append(i["title"])
        pairs.append((i["title"], i["desc"]))
for stories in g["stories"].values():
    titles.extend(s["title"] for s in stories)
CRAFTED_TITLES = [
    "LIVE: Russia-Ukraine war latest - missile strikes hit Kyiv as air defences intercept drones, officials say",
    "Ebola disease caused by Bundibugyo virus - Democratic Republic of the Congo",
    "WHO outbreak notice: Marburg virus disease - United Republic of Tanzania (updated situation report)",
    "Analysis: Why the United States and the United Kingdom are approximately 5 thousand troops apart in order to keep the peace",
    "Breaking: Government confirms 2.5 million people displaced following floods, according to the United Nations",
    "Hackers breach telecommunications giant; data of more than 40 per cent of customers exposed, company says",
    "Police say that a man was killed in a car crash; road closed for hours after the accident near the motorway",
    "Israel strikes Gaza, killing dozens, as ceasefire talks stall amid pressure from the European Union and the United Arab Emirates",
    "Short headline",
    "A very long headline with lots of words that keeps going and going without any natural place to cut it at all because it has no commas or clauses and it never ends",
]
titles.extend(CRAFTED_TITLES)
titles = list(dict.fromkeys(t for t in titles if t))

g["normalize"] = [[t, tm.normalize_title(t)] for t in titles]
g["condense"] = []
for t in titles:
    steps, condensed = tm.condense_steps(t)
    g["condense"].append({"in": t, "steps": steps, "condensed": condensed,
                          "trunc": {str(n): tm.truncate_words(lambda s, n=n: len(s) <= n, condensed)
                                    for n in (30, 50, 70)}})

CRAFTED_SEVERITY = [
    ("Rail strikes planned over pay as unions vote", ""), ("Star Wars film breaks box office records", ""),
    ("Missile strikes hit Kyiv overnight", ""), ("Heart attack risk rises in winter", ""),
    ("Ransomware attack on hospital cancels appointments", ""), ("Life hacks for travel this summer", ""),
    ("Outbreak of violence in the capital", ""), ("Ebola outbreak declared in Uganda", ""),
    ("Post-pandemic recovery slows", ""), ("Since the covid pandemic, offices are empty", ""),
    ("Troops killed in drone attack on base", ""), ("Teachers' strike called off", ""),
    ("World War Two veteran turns 100", ""), ("Zero-day exploited in the wild, CISA warns", ""),
    ("Bird flu H5N1 found in dairy cattle", ""), ("Measles cases rise", "new variant spreading"),
    ("Price war hits supermarkets", ""), ("Opioid epidemic deaths fall", ""),
    ("Man killed in a bus crash", ""), ("Hamas and Israel agree ceasefire", ""),
]
seen = set()
g["severity"] = []
for t, d in pairs + CRAFTED_SEVERITY:
    if (t, d) in seen:
        continue
    seen.add((t, d))
    g["severity"].append({"t": t, "d": d, **{c: tm.story_severity(tm.CATEGORIES[c], t, d) for c in ("WAR", "CYB", "BIO")}})

gdacs_raw = []
if status.get("DIS:GDACS") == "ok":
    try:
        root = ET.fromstring(open(fixture("DIS:GDACS"), "rb").read())
        gdacs_raw = [tm.strip_html(i.findtext("title")).split(". ")[0] for i in root.iter("item")]
    except ET.ParseError:
        pass
gdacs_raw += [
    "Green earthquake (Magnitude 5.9M, Depth:45.951km) in Indonesia 03/10/2026 22:55 UTC, 130 thousand in MMI V",
    "Orange earthquake (Magnitude 6.8M, Depth:10km) in Japan 1/2/2026 3:04:05 UTC, Few people affected in MMI VII",
    "Red earthquake (Magnitude 7.4M, Depth:33km) in Chile 12/12/2026 10:00 UTC, 1.2 million in MMI IX",
]
g["gdacs_titles"] = [[t, tm.tidy_gdacs_title(t)] for t in dict.fromkeys(gdacs_raw)]

g["strip_html"] = [[s, tm.strip_html(s)] for s in [
    "<p>Hello&nbsp;<b>world</b> &amp; &#8217;quotes&#x2019; &rsquo;</p>", "  multiple   spaces\n\tnewline ",
    "&lt;tag&gt;", "&#146;", "", "A &unknown; entity", "&#0;", "Caf&eacute; &mdash; na&iuml;ve &hellip;",
    "<img src='x.png'/>Text after image<br/>more"]]
g["dates"] = [[s, ts(tm.parse_date(s))] for s in [
    "Sat, 10 Oct 2026 12:34:56 GMT", "Sat, 10 Oct 2026 12:34:56 +0000", "Sat, 10 Oct 2026 08:34:56 -0400",
    "10 Oct 2026 12:34:56 GMT", "Sat, 10 Oct 2026 12:34 GMT", "Sat, 10 Oct 2026 12:34:56 EST",
    "Mon, 10 Oct 2026 12:34:56 GMT", "Fri, 2 Oct 2026 07:05:00 +0200", "garbage", ""]]
g["iso"] = [[s, ts(tm.parse_iso(s))] for s in [
    "2026-10-02T12:00:00Z", "2026-10-02T12:00:00.123Z", "2026-10-02T12:00:00+02:00",
    "2026-10-02T12:00:00", "2026-10-02", "bad", "2026-10-02T12:00:00.123456Z"]]
g["ratio_scores"] = [[i * 0.05, tm.score_from_ratio(i * 0.05)] for i in range(0, 101)]
g["saturate"] = [[r, s, tm.saturate(r, s)] for r in (0, 0.5, 1, 2.5, 5, 10, 30, 100) for s in (1, 20, 1 / tm.NORMAL_K)]
GTI_CASES = [{"WAR": 35, "DIS": 22, "CYB": 35, "BIO": 35}, {"WAR": 80, "DIS": 10, "CYB": 30, "BIO": 40},
             {"WAR": None, "DIS": 22, "CYB": 35, "BIO": 35}, {"WAR": None, "DIS": None, "CYB": 35, "BIO": 35},
             {"WAR": 100, "DIS": 100, "CYB": 100, "BIO": 100}, {"WAR": 0, "DIS": 0, "CYB": 0, "BIO": 1},
             {"WAR": 41, "DIS": 22, "CYB": 37, "BIO": 52}]
g["gti"] = [{"scores": c, "gti": tm.compute_gti(c)} for c in GTI_CASES]

# ---- 5. the whole pipeline: components and scores ---------------------------
cal = {"version": tm.CALIB_VERSION, "samples": {}}
tm._extra_cache.clear()
pipe, scores = {}, {}
for c in tm.CATS:
    if c == "DIS":
        try:
            v, st = tm.score_disasters(now, fetched)
            pipe[c] = {"score": v, "headlines": [h["title"] for h in tm.pick_headlines(st)], "stories": len(st)}
        except Exception as e:
            pipe[c] = {"score": None, "error": str(e)}
    else:
        comps, st = tm.fetch_category(c, now, fetched)
        try:
            ratio = tm.combine(c, comps, cal)
            v = tm.score_from_ratio(ratio)
        except RuntimeError:
            ratio = v = None
        pipe[c] = {"score": v, "ratio": ratio, "stories": len(st),
                   "headlines": [h["title"] for h in tm.pick_headlines(st)],
                   "components": [{k: x.get(k) for k in ("key", "kind", "ok", "items", "recent", "hits", "raw",
                                                          "ratio", "normal")} for x in comps]}
    scores[c] = pipe[c]["score"]
pipe["gti"] = tm.compute_gti(scores)
g["pipeline"] = pipe

with open(os.path.join(OUT, "golden.json"), "w", encoding="utf-8") as f:
    json.dump(g, f, indent=1)
print(f"\nPython reference: " + ", ".join(f"{c} {pipe[c]['score']}" for c in tm.CATS) + f", GTI {pipe['gti']}")
print(f"{len(g['severity'])} keyword cases, {len(g['condense'])} headlines, "
      f"{sum(len(v) for v in g['items'].values())} feed stories")
