# SYSTEM THREAT MONITOR  v3.3
# Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
# Revised: Friday, October 9, 2026
#
# Run:   python3 threat_monitor.py                    (fullscreen, live data)
#        python3 threat_monitor.py --windowed 320x240 (in a window)
#        python3 threat_monitor.py --demo             (sample data, no network)
#        python3 threat_monitor.py --check            (test every news source)
# Keys:  Esc/Q quit · Right/Space/tap next screen · Left previous · R sync now
# Windows screensaver: see threat_screensaver.py (imports this file).
# Works with pygame or pygame-ce (pip install pygame-ce on newer Python versions).
#
# How the numbers work (details in NOTES at the bottom):
#   * Each category is 0-100. News categories (WAR, CYB, BIO) are measured
#     against their own recent normal: an ordinary day reads ~35 (GUARDED).
#   * DIS uses official GDACS alert levels (USGS as a fallback).
#   * Threat levels: LOW <30, GUARDED 30-44, ELEVATED 45-59, HIGH 60-74,
#     SEVERE 75+.
#   * No random numbers and no cosmetic animation of the values themselves.
#   * v3.3: sources are fetched in parallel with a hard time limit, a failed
#     or crashed sync can never leave the screen on "Contacting sources", the
#     background fetcher restarts itself if it ever stops, and everything is
#     logged to threat_monitor.log next to this script.
#   * Headlines are shown in at most 3 lines; longer ones are condensed
#     (labels, attributions and filler removed, names abbreviated, trailing
#     clauses dropped) and only cut with "…" as a last resort.
# -----------------------------------------------------------------------------

import argparse
import html
import json
import math
import os
import re
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import requests

# =============================================================================
# CONFIGURATION
# =============================================================================
TIMEOUT = (6, 15)         # seconds to connect / to wait for data, per request
SYNC_DEADLINE = 45        # a whole sync never takes longer; slower sources count as failed
CLOCK_CHECK_SECS = 60     # how often the fetcher checks for system clock changes
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux armv7l) ThreatMonitor/3.0"}

REFRESH_OK = 900          # seconds between syncs when every source worked
REFRESH_RETRY_MIN = 60    # first retry after a failure; doubles up to REFRESH_OK
NEWS_WINDOW_HOURS = 48    # only stories published in this window count
KEV_WINDOW_DAYS = 7       # CISA "known exploited" additions in this window
DON_WINDOW_DAYS = 30      # WHO outbreak notices in this window
EXTRA_CACHE_HOURS = 24    # reuse the last good CISA/WHO result if a fetch fails

# Weight of each category in the Global Threat Index (sums to 1.0).
GTI_WEIGHTS = {"WAR": 0.35, "CYB": 0.25, "DIS": 0.20, "BIO": 0.20}

# News categories are relative to their own recent history. Every source is
# compared with its own 30-day median ("normal"); a category reads NORMAL_LEVEL
# when its sources are at their usual level, ~58 at twice it, ~73 at three
# times. DEFAULT_NORMAL is only used until a source has a few hours of history.
NORMAL_LEVEL = 35
NORMAL_K = -math.log(1 - NORMAL_LEVEL / 100)   # ratio 1.0 -> NORMAL_LEVEL
RATIO_CAP = 4.0               # one unusual source can't max out a category alone
MIN_FEED_STORIES = 5          # a feed with fewer recent stories is not used
FEED_MIN_DENOMINATOR = 8      # steadier averages for feeds with few stories
FEED_NORMAL_FLOOR = 0.15      # avoids huge ratios for feeds that are usually ~0
DEFAULT_NORMAL = {
    "WAR": {"BBC": 0.55, "ALJAZEERA": 0.8, "NPR": 0.5},
    "CYB": {"BBC": 0.3, "NPR": 0.2, "CISA": 0.3},
    "BIO": {"BBC": 0.4, "NPR": 0.35, "WHO": 0.5},
}


def _data_dir():
    """Where calibration and the last-known state are kept. Windows: per-user
    %APPDATA%\\ThreatMonitor. Elsewhere: next to this script."""
    if os.environ.get("THREAT_MONITOR_DATA"):
        return os.environ["THREAT_MONITOR_DATA"]
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "ThreatMonitor")
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


DATA_DIR = _data_dir()
CALIB_FILE = os.path.join(DATA_DIR, "threat_calibration.json")
STATE_FILE = os.path.join(DATA_DIR, "threat_state.json")   # last values, for instant start
STATE_MAX_AGE = 6 * 3600                                    # ignore saved values older than this
CALIB_VERSION = 4             # bump when scoring changes so old samples are dropped
CALIB_DAYS = 30
CALIB_MIN_SAMPLES = 6         # hours of history before the learned baseline is used
CALIB_SETTLED = 24            # shown as "BASELINE n/24" on screen until reached
CALIB_SAMPLE_GAP = 55 * 60    # at most one sample per hour

KEV_WEIGHT, KEV_CAP = 0.05, 1.0   # per newly listed exploited vulnerability
DON_WEIGHT, DON_CAP = 0.25, 1.0   # per distinct WHO outbreak notice

# Disasters: absolute. Routine events (GDACS Green, small USGS events) count
# up to a cap; each significant alert counts in full.
DIS_ROUTINE_MAX = 1.0
DIS_ROUTINE_CAP = 5.0
DIS_SCALE = 20.0              # quiet ~22, one Orange ~42, one Red ~63

GOOGLE_NEWS = "https://news.google.com/rss/search"
GOOGLE_PARAMS = {"hl": "en-US", "gl": "US", "ceid": "US:en"}
WHO_DON_URL = ("https://www.who.int/api/news/diseaseoutbreaknews"
               "?$orderby=PublicationDate%20desc&$top=20&$select=Title,PublicationDate,DonId")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def feed(key, url, label, window_h=NEWS_WINDOW_HOURS, params=None, scored=True):
    """A news feed. Scored feeds are general news: the share of threat stories
    in them is what gets measured."""
    return {"key": key, "url": url, "label": label, "window": window_h,
            "params": params, "scored": scored}


def bbc(section):
    return feed("BBC", f"https://feeds.bbci.co.uk/news/{section}/rss.xml", "BBC")


def npr(code, window_h):
    """NPR posts fewer stories a day, so it gets a longer window."""
    return feed("NPR", f"https://feeds.npr.org/{code}/rss.xml", "NPR", window_h)


def google_news(query):
    """Google News search ('when:Nd' = last N days). Headlines only: every
    result matches the query by design, so its volume says nothing."""
    return feed("GOOGLE", GOOGLE_NEWS, "Google News", params=dict(GOOGLE_PARAMS, q=query), scored=False)


ALJAZEERA = feed("ALJAZEERA", "https://www.aljazeera.com/xml/rss/all.xml", "Al Jazeera")


# Each rule is (regex, weight). A story's severity is its HIGHEST matching
# weight, so one story is never counted twice. Exclusions are blanked out of
# the text before the rules run.
CATEGORIES = {
    "WAR": {
        "feeds": [bbc("world"), ALJAZEERA, npr(1004, 72),
                  google_news("war OR airstrike OR missile OR invasion OR shelling when:1d")],
        "rules": [
            (r"\bnuclear (strike|attack|weapons? test|threat)s?\b", 6),
            (r"\b(invasion|invades?|invaded|massacres?)\b", 5),
            (r"\b(air ?strikes?|drone strikes?|drone attacks?|missile (strikes?|attacks?)|ballistic missiles?|"
             r"rocket (fire|attacks?))\b", 4),
            (r"\b(shelling|bombardment|bombing|bombed|war crimes?)\b", 4),
            (r"\b(war|wars|warfare|missiles?)\b", 3),
            (r"\b(fighting|clashes|genocide|insurgency)\b", 3),
            (r"\bstrikes? (on|in|against|kill|kills|killed|hit|hits)\b", 3),
            (r"\b(troops|soldiers?|offensive|front ?line|ceasefire|cease-fire|hostages?|gunmen|militias?|"
             r"armed groups?|drones?|displaced|wounded|settlers?)\b", 2),
            (r"\b(hamas|hezbollah|houthis?|taliban|islamic state|isis|al-shabab|boko haram|wagner group)\b", 2),
            (r"\b(attacks?|attacked)\b", 2),
            (r"\b(military|army|navy|armed forces|militants?|insurgents?|rebels?|warships?|killed)\b", 1),
        ],
        "exclude": [
            r"\bstar wars\b", r"\b(price|trade|tariff|bidding|console|streaming|talent|format) wars?\b",
            r"\bculture wars?\b", r"\bwar of words\b", r"\bwar chest\b",
            r"\bwar on (drugs|poverty|cancer|waste|obesity)\b",
            r"\bwar (film|movie|drama|game|memorial|museum|veteran|anniversary)s?\b",
            r"\bworld war (i|ii|one|two|1|2)\b",
            r"\boffensive (remarks?|comments?|language|jokes?|posts?|tweets?|content|messages?|chants?|coordinator|line|lineman)\b",
            r"\bfront ?-?line (workers?|staff|nurses?|doctors?|services?|health|care)\b",
            r"\bshelling out\b",
            # labour strikes, not military strikes
            r"\b(rail|train|tube|bus|teachers?|doctors?|nurses?|workers?|union|general|hunger|labou?r|national|"
            r"postal|port|dock|airline|pilots?|staff) strikes?\b",
            r"\bon strike\b", r"\bstrikes? (action|ballot|vote|over (pay|wages|pensions))\b",
            # non-military attacks
            r"\b(heart|panic|shark|dog|bear|asthma|anxiety|cyber|ransomware|hacker|phishing|personal|verbal|"
            r"online|racist|scathing|bitter|acid)[ -]attacks?\b",
            r"\battack(s|ed)?( on| against)? (the )?(media|press|critics?|opponents?|democrats|republicans|"
            r"rivals?|judges?|reporters?)\b",
            r"\b(attacking|attack) (midfielder|player|football|play|third|line)\b",
            r"\bfighting (fit|chance|spirit|talk|inflation|crime|fires?|wildfires?|cancer|corruption|poverty|"
            r"obesity|fraud)\b",
            r"\bmilitary (service exemptions?|exemptions?|parade|band|academy|school|history|museum|style|"
            r"grade|tattoo)\b",
            r"\bdrones? (delivery|deliveries|show|light show|photography|racing|footage)\b",
            r"\bkilled (in|by) (a |an |the )?(bus |car |train |road |plane |motorway )?(crash|accident|fire|"
            r"flood|landslide|avalanche|storm|lightning|collision|stampede)\b",
        ],
    },
    "CYB": {
        "feeds": [bbc("technology"), npr(1019, 168),
                  google_news('cyberattack OR ransomware OR "data breach" OR "zero-day" when:1d')],
        "extra": "CISA",
        "rules": [
            (r"\bransomware\b", 5),
            (r"\bzero[- ]?days?\b", 5),
            (r"\bcyber[- ]?attacks?\b", 5),
            (r"\b(data breach(es)?|breached)\b", 4),
            (r"\b(actively exploited|exploited in the wild)\b", 4),
            (r"\b(hack|hacked|hackers?|hacking)\b", 3),
            (r"\b(malware|botnets?|spyware|ddos|phishing|wiper)\b", 3),
            (r"\b(vulnerabilit(y|ies)|cve-\d{4}-\d+)\b", 1.5),
            (r"\bcyber ?security\b", 1),
        ],
        "exclude": [
            r"\b(life|growth|productivity|budget|travel|kitchen) hacks?\b",
            r"\bhacks? (for|to)\b",
            r"\bbreached (the )?(rules?|contract|agreement|code|guidelines|terms|law|regulations|covenants?|duty)\b",
            r"\b(windscreen|windshield) wipers?\b",
        ],
    },
    "BIO": {
        "feeds": [bbc("health"), npr(1128, 168),
                  google_news("outbreak OR epidemic OR pandemic OR ebola OR cholera OR H5N1 OR mpox when:2d")],
        "extra": "WHO",
        "rules": [
            (r"\bpublic health emergency\b", 6),
            (r"\b(ebola|marburg|nipah|plague|anthrax)\b", 5),
            (r"\bpandemic\b", 4),
            (r"\b(outbreaks?)\b", 4),
            (r"\b(mpox|monkeypox|cholera|h5n\d|bird flu|avian (flu|influenza)|polio)\b", 4),
            (r"\bepidemic\b", 3),
            (r"\b(measles|dengue|meningitis|diphtheria|yellow fever)\b", 3),
            (r"\b(pathogens?|novel virus|new (variant|strain))\b", 3),
            (r"\b(flu|influenza|covid(-19)?|coronavirus|rsv|norovirus|tuberculosis|malaria|whooping cough|"
             r"mers|sars)\b", 2),
            (r"\b(virus|infections?)\b", 1),
        ],
        "exclude": [
            r"\b(post|pre)-pandemic\b", r"\b(since|during|after|before)( the)?( covid)? pandemic\b",
            r"\bpandemic[- ]era\b",
            r"\boutbreaks? of (violence|fighting|war|protests?|unrest)\b",
            r"\b(opioid|loneliness|obesity|vaping|gun violence|misinformation) epidemic\b",
            r"\bcomputer virus\b",
            r"\bnew strain (on|for)\b",
        ],
    },
}

for _cfg in CATEGORIES.values():
    _cfg["rules"] = [(re.compile(p, re.I), w) for p, w in _cfg["rules"]]
    _cfg["exclude"] = re.compile("|".join(_cfg["exclude"]), re.I)

GDACS_GREEN_BY_TYPE = {"EQ": 0.5, "TC": 1.0, "FL": 0.5, "VO": 0.5, "DR": 0.5, "WF": 0.2}
GDACS_LEVEL = {"orange": 6.0, "red": 15.0}
USGS_PAGER = {"green": 0.5, "yellow": 3.0, "orange": 6.0, "red": 15.0}
GDACS_NS = "{http://www.gdacs.org}"

# =============================================================================
# PARSING HELPERS
# =============================================================================
TAG_RE = re.compile(r"<[^>]+>")
NORM_RE = re.compile(r"[^a-z0-9 ]+")


LOG_FILE = None            # set by main() / the screensaver to also keep a log file
LOG_STDOUT = True
LOG_MAX_BYTES = 512 * 1024
_log_lock = threading.Lock()


def log(level, msg):
    """Print and file a log line. Never raises: a closed terminal or a full
    disk must not stop the monitor (in v3.2 it could)."""
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {msg}"
    if LOG_STDOUT:
        try:
            print(line, flush=True)
        except Exception:
            pass
    if LOG_FILE:
        with _log_lock:
            try:
                if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
                    os.replace(LOG_FILE, LOG_FILE + ".old")
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass


def strip_html(text):
    return " ".join(html.unescape(TAG_RE.sub(" ", text or "")).split())


def parse_date(text):
    if not text:
        return None
    try:
        dt = parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_iso(text):
    try:
        dt = datetime.fromisoformat((text or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize_title(title):
    """For duplicate detection: drop a ' - Publisher' suffix, punctuation, case."""
    base = re.sub(r"\s+[-|–]\s+[^-|–]{2,40}$", "", title)
    return " ".join(NORM_RE.sub(" ", base.lower()).split())


def story(sev, date, title, source):
    return {"sev": float(sev), "date": date, "title": title, "source": source}


def fetch_rss_items(url, params=None, label=""):
    r = requests.get(url, params=params, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    items = []
    for item in root.iter("item"):
        title = strip_html(item.findtext("title"))
        source = strip_html(item.findtext("source")) or label   # Google gives the publisher
        if source and title.endswith(" - " + source):
            title = title[: -len(source) - 3].rstrip()
        if len(title) < 10:
            continue
        items.append({"title": title, "desc": strip_html(item.findtext("description")),
                      "date": parse_date(item.findtext("pubDate")), "source": source})
    return items


def story_severity(cfg, title, desc):
    text = cfg["exclude"].sub(" ", f"{title} . {desc}")
    return max((w for rx, w in cfg["rules"] if rx.search(text)), default=0.0)


def saturate(raw, scale):
    """Map an unbounded value onto 0-100 with diminishing returns."""
    return max(0, min(100, int(round(100 * (1 - math.exp(-raw / scale))))))


def pick_headlines(stories, n=3):
    """Most severe, then newest, skipping near-duplicates of the same story."""
    chosen, word_sets = [], []
    for s in sorted(stories, key=lambda s: (s["sev"], s["date"]), reverse=True):
        words = set(normalize_title(s["title"]).split())
        if any(len(words & w) / max(1, len(words | w)) > 0.5 for w in word_sets):
            continue
        chosen.append(s)
        word_sets.append(words)
        if len(chosen) == n:
            break
    return chosen


# =============================================================================
# EXTRA OFFICIAL SOURCES (cached so one failed fetch doesn't shift the score)
# =============================================================================
def cisa_kev_stories(now):
    r = requests.get(CISA_KEV_URL, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    cutoff = (now - timedelta(days=KEV_WINDOW_DAYS)).date()
    out = []
    for v in r.json().get("vulnerabilities", []):
        try:
            added = datetime.strptime(v.get("dateAdded", ""), "%Y-%m-%d").date()
        except ValueError:
            continue
        if added < cutoff:
            continue
        sev = 3.0 + (2.0 if v.get("knownRansomwareCampaignUse") == "Known" else 0.0)
        title = f"Actively exploited: {v.get('cveID', '')} {v.get('vulnerabilityName', '')}".strip()
        out.append(story(sev, datetime(added.year, added.month, added.day, tzinfo=timezone.utc),
                         title, "CISA"))
    return out


def who_don_stories(now):
    r = requests.get(WHO_DON_URL, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    cutoff = now - timedelta(days=DON_WINDOW_DAYS)
    latest = {}                                   # one entry per outbreak (title)
    for v in r.json().get("value", []):
        d = parse_iso(v.get("PublicationDate"))
        title = strip_html(v.get("Title"))
        if d is None or d < cutoff or not title:
            continue
        if title not in latest or d > latest[title]["date"]:
            latest[title] = story(5.0, d, f"WHO outbreak notice: {title}", "WHO")
    return list(latest.values())


EXTRAS = {   # name -> (fetcher, weight per distinct item, cap)
    "CISA": (cisa_kev_stories, KEV_WEIGHT, KEV_CAP),
    "WHO": (who_don_stories, DON_WEIGHT, DON_CAP),
}
_extra_cache = {}


def use_extra(name, result):
    """result is ("ok", stories) or ("error", exception). On failure the last
    good result is reused for up to EXTRA_CACHE_HOURS."""
    status, value = result
    if status == "ok":
        _extra_cache[name] = (time.time(), value)
        return value
    hit = _extra_cache.get(name)
    if hit and time.time() - hit[0] < EXTRA_CACHE_HOURS * 3600:
        log("WARN", f"{name} failed ({value}); using result from {int((time.time() - hit[0]) / 60)} min ago")
        return hit[1]
    log("WARN", f"{name} unavailable: {value}")
    return None


# =============================================================================
# FETCHING (all sources at once, with a hard time limit)
# =============================================================================
def run_parallel(jobs, timeout):
    """Run {key: function} in background threads and wait at most `timeout`
    seconds in total. Returns {key: ("ok", result) | ("error", exception)}.
    A source that hangs (slow server, stuck DNS) is abandoned, never waited on."""
    results = {}

    def run(key, fn):
        try:
            results[key] = ("ok", fn())
        except Exception as e:
            results[key] = ("error", e)

    threads = [threading.Thread(target=run, args=(k, fn), daemon=True) for k, fn in jobs.items()]
    for t in threads:
        t.start()
    end = time.monotonic() + timeout
    for t in threads:
        t.join(max(0.0, end - time.monotonic()))
    return {k: results.get(k, ("error", TimeoutError(f"no answer within {timeout}s"))) for k in jobs}


def fetch_sources(now, timeout=None):
    """Download every source once. Keys: (category, source key)."""
    timeout = timeout or SYNC_DEADLINE
    jobs = {}
    for name, cfg in CATEGORIES.items():
        for f in cfg["feeds"]:
            jobs[(name, f["key"])] = lambda f=f: fetch_rss_items(f["url"], f["params"], f["label"])
        if cfg.get("extra"):
            jobs[(name, cfg["extra"])] = lambda e=cfg["extra"]: EXTRAS[e][0](now)
    jobs[("DIS", "GDACS")] = lambda: gdacs_stories(now)
    jobs[("DIS", "USGS")] = lambda: usgs_stories(now)
    return run_parallel(jobs, timeout)


# =============================================================================
# CATEGORY SCORERS
# =============================================================================
def _component(key, label, kind):
    return {"key": key, "label": label, "kind": kind, "ok": False, "note": "",
            "items": 0, "recent": 0, "hits": 0, "raw": 0.0}


def fetch_category(name, now, fetched):
    """Score each source of a news category from the downloaded data.
    Returns (components, stories). A feed component holds: stories in the
    feed, recent stories in its window, threat-related ones, and raw = their
    average severity."""
    cfg = CATEGORIES[name]
    comps, stories = [], []
    for f in cfg["feeds"]:
        c = _component(f["key"], f["label"], "feed" if f["scored"] else "headlines")
        comps.append(c)
        status, items = fetched[(name, f["key"])]
        if status != "ok":
            c["note"] = f"failed: {items}"
            log("WARN", f"{name} {f['label']} failed: {items}")
            continue
        cutoff = now - timedelta(hours=f["window"])
        seen, sev_sum, newest = set(), 0.0, None
        c["items"] = len(items)
        for it in items:
            if it["date"] is not None:
                newest = it["date"] if newest is None else max(newest, it["date"])
                if it["date"] < cutoff:
                    continue
            key = normalize_title(it["title"])
            if not key or key in seen:
                continue
            seen.add(key)
            c["recent"] += 1
            sev = story_severity(cfg, it["title"], it["desc"])
            if sev > 0:
                c["hits"] += 1
                sev_sum += sev
                stories.append(story(sev, it["date"] or now, it["title"], it["source"]))
        if c["kind"] == "headlines":
            c["ok"] = True
            continue
        c["raw"] = sev_sum / max(c["recent"], FEED_MIN_DENOMINATOR)
        if c["recent"] >= MIN_FEED_STORIES:
            c["ok"] = True
        else:                                   # never read "no stories" as "no threat"
            if not items:
                c["note"] = "feed returned no stories"
            elif newest is not None and newest < cutoff:
                c["note"] = f"newest story is {ago(newest)} - check the clock and timezone"
            else:
                c["note"] = f"only {c['recent']} recent stories"
            log("WARN", f"{name} {f['label']}: {c['note']}; not used")
    if cfg.get("extra"):
        ename = cfg["extra"]
        _, weight, cap = EXTRAS[ename]
        c = _component(ename, ename, "extra")
        comps.append(c)
        extra = use_extra(ename, fetched[(name, ename)])
        if extra is None:
            c["note"] = "unavailable"
        else:
            n = len({x["title"] for x in extra})
            c.update(ok=True, items=n, recent=n, hits=n, raw=min(cap, weight * n))
            stories.extend(extra)
    return comps, stories


def combine(name, comps, cal):
    """Average of each working source's level relative to its own normal."""
    used = [c for c in comps if c["ok"] and c["kind"] != "headlines"]
    if not any(c["kind"] == "feed" for c in used):
        raise RuntimeError("no news feed returned enough recent stories")
    for c in used:
        med = calibrated_median(cal, f"{name}:{c['key']}")
        c["learned"] = med is not None
        base = med if c["learned"] else DEFAULT_NORMAL[name][c["key"]]
        floor = FEED_NORMAL_FLOOR if c["kind"] == "feed" else EXTRAS[c["key"]][1]
        c["normal"] = base
        # 1.0 = this source's usual level. Measured as distance from normal, so
        # a source that is usually ~0 (e.g. a tech feed with no cyber stories)
        # also reads 1.0 on an ordinary day instead of dragging the average down.
        c["ratio"] = min(RATIO_CAP, max(0.0, 1 + (c["raw"] - base) / max(base, floor)))
    return sum(c["ratio"] for c in used) / len(used)


def score_from_ratio(ratio):
    return saturate(ratio, 1 / NORMAL_K)


MMI_WORDS = {"I": "unfelt", "II": "weak", "III": "weak", "IV": "light", "V": "moderate",
             "VI": "strong", "VII": "very strong", "VIII": "severe", "IX": "violent", "X": "extreme"}


def tidy_gdacs_title(title):
    """'Green earthquake (Magnitude 5.9M, Depth:45.951km) in Indonesia 03/10/2026
    22:55 UTC, 130 thousand in MMI V.' -> 'Green earthquake M5.9 in Indonesia,
    130 thousand people in moderate shaking'"""
    t = re.sub(r"\(Magnitude\s*([\d.]+)\s*M?[^)]*\)", r"M\1", title)
    t = re.sub(r"\s+\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}(:\d{2})?\s*UTC", "", t)

    def mmi(m):
        who = "few people" if m.group(1).lower().startswith("few") else f"{m.group(1)} people"
        return f"{who} in {MMI_WORDS.get(m.group(2).upper(), 'MMI ' + m.group(2))} shaking"
    t = re.sub(r"\b(Few people affected|\d[\d.,]*(?: thousand| million)?)\s+in MMI ([IVX]+)\b", mmi, t, flags=re.I)
    return " ".join(t.split()).rstrip(". ")


def gdacs_stories(now):
    r = requests.get("https://www.gdacs.org/xml/rss.xml", headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    out = []
    for item in root.iter("item"):
        if (item.findtext(GDACS_NS + "iscurrent") or "").strip().lower() != "true":
            continue
        level = (item.findtext(GDACS_NS + "alertlevel") or "").strip().lower()
        etype = (item.findtext(GDACS_NS + "eventtype") or "").strip().upper()
        if level in GDACS_LEVEL:
            sev = GDACS_LEVEL[level]
        elif level == "green":
            sev = GDACS_GREEN_BY_TYPE.get(etype, 0.5)
        else:
            continue
        title = tidy_gdacs_title(strip_html(item.findtext("title")).split(". ")[0])
        date = (parse_date(item.findtext(GDACS_NS + "datemodified"))
                or parse_date(item.findtext("pubDate")) or now)
        out.append(story(sev, date, title, "GDACS"))
    return out


def usgs_stories(now):
    url = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/4.5_week.geojson"
    r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    out = []
    for q in r.json().get("features", []):
        p = q.get("properties") or {}
        mag = p.get("mag")                       # can be null in the feed
        sev = USGS_PAGER.get((p.get("alert") or "").lower(), 0.0)
        if not sev and mag is not None and mag >= 6.5:
            sev = 1.0
        if p.get("tsunami") == 1:
            sev += 2.0
        if sev:
            ts = datetime.fromtimestamp((p.get("time") or 0) / 1000, tz=timezone.utc)
            out.append(story(sev, ts, p.get("title") or "Earthquake", "USGS"))
    return out


def score_disasters(now, fetched):
    status, stories = fetched[("DIS", "GDACS")]
    if status != "ok":
        log("WARN", f"GDACS failed, using USGS instead: {stories}")
        status, stories = fetched[("DIS", "USGS")]
        if status != "ok":
            raise RuntimeError(f"GDACS and USGS both unavailable ({stories})")
    routine = sum(s["sev"] for s in stories if s["sev"] <= DIS_ROUTINE_MAX)
    major = sum(s["sev"] for s in stories if s["sev"] > DIS_ROUTINE_MAX)
    return saturate(major + min(DIS_ROUTINE_CAP, routine), DIS_SCALE), stories


# =============================================================================
# HEADLINE CONDENSING (used when a headline would need more than 3 lines)
# =============================================================================
_LABEL_RE = re.compile(r"^(live|breaking( news)?|watch|video|photos?|exclusive|updated?|analysis|"
                       r"opinion|explainer|in pictures|listen|just in)\s*[:|–—-]\s*", re.I)
_BRACKET_RE = re.compile(r"\s*[(\[][^)\]]{0,80}[)\]]")
_TAIL_RES = [
    re.compile(r"\s*[|–—-]\s*(live( updates| blog)?|as it happened|latest( updates)?|report|video|"
               r"photos|opinion|analysis|explainer)\s*$", re.I),
    re.compile(r",?\s+according to [^,;]+$", re.I),
    re.compile(r",\s+(\S+\s+){0,3}(says?|said|reports?|reported|claims?|claimed|warns?|warned|"
               r"confirms?|confirmed|announces?|announced)\s*$", re.I),
]
_LEAD_ATTR_RE = re.compile(r"^(officials?|police|authorities|reports?|sources|witnesses|experts?|analysts?|"
                           r"scientists|researchers|state media|residents)\s+(say|said|warn|warned|fear|"
                           r"believe|confirm|confirmed)\s+(that\s+)?", re.I)
_ABBREVIATIONS = [
    (r"\bDemocratic Republic of (the )?Congo\b", "DR Congo"),
    (r"\bUnited States( of America)?\b", "US"),
    (r"\bUnited Kingdom\b", "UK"),
    (r"\bUnited Nations\b", "UN"),
    (r"\bEuropean Union\b", "EU"),
    (r"\bWorld Health Organi[sz]ation\b", "WHO"),
    (r"\bUnited Arab Emirates\b", "UAE"),
    (r"\b(\d+(?:\.\d+)?) thousand\b", r"\1k"),
    (r"\b(\d+(?:\.\d+)?) million\b", r"\1m"),
    (r"\b(\d+(?:\.\d+)?) billion\b", r"\1bn"),
    (r"(\d) ?(per ?cent|percent)\b", r"\1%"),
    (r"(?i)\bapproximately\b", "about"),
    (r"(?i)\bmore than\b", "over"),
    (r"(?i)\bin order to\b", "to"),
    (r"(?i)\bfollowing\b", "after"),
    (r"(?i)\btelecommunications\b", "telecoms"),
    (r"(?i)\bgovernment\b", "govt"),
    (r"\bVulnerability\b", "flaw"),
]
_ABBREVIATIONS = [(re.compile(p), r) for p, r in _ABBREVIATIONS]
_FILLER_RE = re.compile(r"\b(a|an|the|reportedly|currently)\s+", re.I)
_CLAUSE_RE = re.compile(          # where a trailing clause can be dropped
    r"(;\s"
    r"|,\s(?=(?:as|after|while|amid|with|despite|which|who|but|before|including|where|when|"
    r"days|weeks|hours|months)\b)"
    r"|,\s(?=[a-z][a-z-]*ing\b)"              # ", killing ...", ", forcing ...", ", leaving ..."
    r"|\s(?=(?:as|after|amid|while|despite|ahead of|that|which|days after|weeks after|hours after)\s))",
    re.I)
_DASH_RE = re.compile(r"\s[–—-]\s")       # " - DR Congo": often a place, so cut last
CLAUSE_MIN_WORDS = 6           # never cut a headline down to fewer words than this
_DANGLING = {"a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "for", "with", "by", "from",
             "as", "after", "amid", "while", "but", "that", "its", "their", "his", "her", "is", "are", "was",
             "were", "be", "been", "has", "have", "had", "will", "would", "could", "can", "may", "between",
             "into", "over", "under", "about", "against", "across", "near", "than", "more", "most", "less",
             "very", "this", "these", "those", "who", "which", "not", "no"}


def _tidy(t):
    t = " ".join(t.split()).strip(" ,;:-–—|")
    return t[:1].upper() + t[1:] if t else t


def condense_steps(text):
    """Progressively shorter versions of a headline, gentlest first. The
    caller shows the first one that fits; the original is always first."""
    seen = []

    def emit(t):
        t = _tidy(t)
        if t and t not in seen:
            seen.append(t)
            return True
        return False

    t = text
    emit(t)
    # 1. drop "LIVE:"-style labels, (brackets), and "..., officials say" attributions
    t = _BRACKET_RE.sub("", _LABEL_RE.sub("", t))
    for rx in _TAIL_RES:
        t = rx.sub("", t)
    t = _LEAD_ATTR_RE.sub("", t)
    emit(t)
    # 2. shorter names and numbers
    for rx, repl in _ABBREVIATIONS:
        t = rx.sub(repl, t)
    emit(t)
    # 3. headline style: no articles or filler words
    t = _FILLER_RE.sub("", t)
    emit(t)
    # 4. drop trailing clauses, last one first, keeping the main statement
    def clause_cuts(text, rx):
        for pos in reversed([m.start() for m in rx.finditer(text)]):
            if len(text[:pos].split()) >= CLAUSE_MIN_WORDS:
                emit(text[:pos])
    clause_cuts(t, _CLAUSE_RE)
    # 5. drop a short "Topic:" prefix (the source is shown under the headline),
    #    then try the clause cuts again, this time also at " - "
    head, sep, rest = t.partition(": ")
    if sep and len(head.split()) <= 4 and len(rest.split()) >= 4:
        t = rest
        emit(t)
        clause_cuts(t, _CLAUSE_RE)
    clause_cuts(t, _DASH_RE)
    return seen, _tidy(t)   # last value: fully condensed text without cuts (for "…" fallback)


def truncate_words(words_fit, text):
    """Longest word-boundary prefix of text + '…' for which words_fit() is True,
    not ending on a dangling word like 'and' or 'of'."""
    words = text.split()
    lo, hi = 0, len(words)
    while lo < hi:                                  # binary search on word count
        mid = (lo + hi + 1) // 2
        if words_fit(" ".join(words[:mid]).rstrip(" ,;:-–—") + "…"):
            lo = mid
        else:
            hi = mid - 1
    keep = words[:lo]
    while len(keep) > 1 and keep[-1].lower().strip(",;:") in _DANGLING:
        keep.pop()
    return " ".join(keep).rstrip(" ,;:-–—") + "…"


# =============================================================================
# CALIBRATION (learned "normal" per news category)
# =============================================================================
def load_calibration():
    try:
        with open(CALIB_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"version": CALIB_VERSION, "samples": {}}
    clean = {}
    if isinstance(data, dict) and data.get("version") == CALIB_VERSION:
        for name, rows in (data.get("samples") or {}).items():
            if name in COMPONENT_KEYS and isinstance(rows, list):
                good = [[float(t), float(r)] for row in rows
                        if isinstance(row, list) and len(row) == 2
                        for t, r in [row] if isinstance(t, (int, float)) and isinstance(r, (int, float))]
                clean[name] = sorted(good)
    return {"version": CALIB_VERSION, "samples": clean}


def write_json_atomic(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except OSError as e:
        log("WARN", f"could not save {os.path.basename(path)}: {e}")


def save_calibration(cal):
    write_json_atomic(CALIB_FILE, cal)


def calibrated_median(cal, key):
    """Median raw level of one source over the last 30 days, or None while it
    has fewer than CALIB_MIN_SAMPLES hours of history."""
    samples = sorted(r for _, r in cal["samples"].get(key, []))
    if len(samples) < CALIB_MIN_SAMPLES:
        return None
    return samples[len(samples) // 2]


def baseline_hours():
    """Hours of history behind the learned normals (slowest category)."""
    per_cat = []
    for name in CATEGORIES:
        keys = [k for k in COMPONENT_KEYS if k.startswith(name + ":")]
        per_cat.append(max(len(calibration["samples"].get(k, [])) for k in keys))
    return min(per_cat)


def record_sample(cal, name, raw, now_ts):
    hist = [x for x in cal["samples"].get(name, []) if now_ts - x[0] < CALIB_DAYS * 86400]
    if not hist or now_ts - hist[-1][0] >= CALIB_SAMPLE_GAP:
        hist.append([now_ts, raw])
    cal["samples"][name] = hist


COMPONENT_KEYS = ({f"{name}:{f['key']}" for name, cfg in CATEGORIES.items() for f in cfg["feeds"] if f["scored"]}
                  | {f"{name}:{cfg['extra']}" for name, cfg in CATEGORIES.items() if cfg.get("extra")})
calibration = load_calibration()

# =============================================================================
# SHARED STATE + BACKGROUND FETCHER
# =============================================================================
CATS = ["WAR", "DIS", "CYB", "BIO"]
CAT_NAMES = {c: f"{c} NEWS ALERT" for c in ["WAR", "DIS", "CYB", "BIO"]}
EMPTY_MSG = {"WAR": "No recent war alerts", "DIS": "No current disaster alerts",
             "CYB": "No recent cyber alerts", "BIO": "No recent bio alerts"}

state_lock = threading.Lock()
state = {
    "cats": {c: {"score": None, "prev": None, "headlines": [], "stale": False} for c in CATS},
    "gti": None, "gti_prev": None,
    "next_due": 0.0,           # time.monotonic() of the next sync (immune to clock changes)
    "last_sync": None,         # wall time of the last sync that produced any data
    "syncing": True, "fail_streak": 0, "baseline": 0,
    "attempts": 0, "last_error": None,
}
stop_event = threading.Event()
wake_event = threading.Event()


def compute_gti(scores):
    """Weighted root-mean-square of the categories shown (needs at least 3)."""
    avail = {c: s for c, s in scores.items() if s is not None}
    if len(avail) < 3:
        return None
    wsum = sum(GTI_WEIGHTS[c] for c in avail)
    return int(round(math.sqrt(sum(GTI_WEIGHTS[c] * s * s for c, s in avail.items()) / wsum)))


def sync_once():
    now = datetime.now(timezone.utc)
    now_ts = time.time()
    fetched = fetch_sources(now)
    results, errors = {}, []
    for c in CATS:
        try:
            if c == "DIS":
                value, stories = score_disasters(now, fetched)
            else:
                comps, stories = fetch_category(c, now, fetched)
                value = score_from_ratio(combine(c, comps, calibration))
                for comp in comps:
                    if comp["ok"] and comp["kind"] != "headlines":
                        record_sample(calibration, f"{c}:{comp['key']}", comp["raw"], now_ts)
                log("INFO", f"{c} -> {value}  (" + ", ".join(
                    f"{x['label']} {x['ratio']:.2f}x" for x in comps if "ratio" in x) + ")")
            results[c] = (value, stories)
        except Exception as e:
            log("ERROR", f"{c} failed: {e}")
            errors.append(f"{c}: {e}")
    save_calibration(calibration)
    finish_sync(results, "; ".join(errors) or None)


def finish_sync(results, error=None):
    """Record the outcome of a sync attempt - including a crashed one - so the
    display always moves on from the loading screen."""
    with state_lock:
        for c in CATS:
            slot = state["cats"][c]
            if c in results:
                value, stories = results[c]
                slot["prev"] = slot["score"]
                slot["score"] = value
                slot["headlines"] = pick_headlines(stories)
                slot["stale"] = False
            else:
                slot["stale"] = slot["score"] is not None        # keep last good value
        state["gti_prev"] = state["gti"]
        state["gti"] = compute_gti({c: state["cats"][c]["score"] for c in CATS})
        state["baseline"] = baseline_hours()
        state["attempts"] += 1
        state["last_error"] = error
        if results:
            state["last_sync"] = time.time()
        if len(results) == len(CATS):
            state["fail_streak"] = 0
            delay = REFRESH_OK
        else:
            state["fail_streak"] += 1
            delay = min(REFRESH_OK, REFRESH_RETRY_MIN * 2 ** (state["fail_streak"] - 1))
        state["next_due"] = time.monotonic() + delay
        state["syncing"] = False
    if results:
        save_state_cache()


def save_state_cache():
    with state_lock:
        data = {
            "version": CALIB_VERSION,
            "gti": state["gti"], "gti_prev": state["gti_prev"], "last_sync": state["last_sync"],
            "cats": {c: {"score": state["cats"][c]["score"], "prev": state["cats"][c]["prev"],
                         "headlines": [dict(h, date=h["date"].timestamp() if h["date"] else None)
                                       for h in state["cats"][c]["headlines"]]}
                     for c in CATS},
        }
    write_json_atomic(STATE_FILE, data)


def load_state_cache():
    """Show the last saved values straight away (e.g. each time the screensaver
    starts). Values younger than one sync interval are used as-is and the next
    sync waits its turn; older ones are shown while a fresh sync runs."""
    try:
        with open(STATE_FILE) as f:
            data = json.load(f)
        if data.get("version") != CALIB_VERSION:
            return False
        last = float(data["last_sync"])
        age = time.time() - last
        if not 0 <= age <= STATE_MAX_AGE:
            return False
        cats = {}
        for c in CATS:
            d = data["cats"][c]
            score, prev = d.get("score"), d.get("prev")
            if not all(v is None or isinstance(v, int) for v in (score, prev)):
                return False
            hls = [story(h["sev"], datetime.fromtimestamp(h["date"], timezone.utc) if h.get("date") else None,
                         str(h["title"]), str(h.get("source", ""))) for h in d.get("headlines", [])]
            cats[c] = (score, prev, hls)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return False
    fresh = age < REFRESH_OK
    with state_lock:
        state["attempts"] += 1
        for c, (score, prev, hls) in cats.items():
            state["cats"][c].update(score=score, prev=prev, headlines=hls, stale=False)
        state["gti"] = compute_gti({c: v[0] for c, v in cats.items()})
        state["gti_prev"] = data.get("gti_prev") if isinstance(data.get("gti_prev"), int) else None
        state["last_sync"] = last
        state["next_due"] = time.monotonic() + (REFRESH_OK - age if fresh else 0)
        state["syncing"] = not fresh
        state["baseline"] = baseline_hours()
    log("INFO", f"loaded values from {int(age // 60)} min ago ({'current' if fresh else 'refreshing now'})")
    return True


def fetch_worker():
    """Background loop: sync on schedule, on request (R key) and right after
    the system clock is corrected (a Raspberry Pi sets it from the network
    after boot). Nothing in here is allowed to end the loop."""
    clock_offset = time.time() - time.monotonic()
    while not stop_event.is_set():
        try:
            with state_lock:
                wait = state["next_due"] - time.monotonic()
            if wait > 0:
                requested = wake_event.wait(min(wait, CLOCK_CHECK_SECS))
                wake_event.clear()
                if stop_event.is_set():
                    break
                offset = time.time() - time.monotonic()
                if abs(offset - clock_offset) > 300:
                    log("INFO", "system clock changed (e.g. set from the network after boot); syncing now")
                    clock_offset = offset
                elif not requested:
                    continue                        # keep waiting
            with state_lock:
                state["syncing"] = True
            try:
                sync_once()
            except Exception as e:
                log("ERROR", f"sync crashed: {e!r}\n{traceback.format_exc()}")
                finish_sync({}, f"crashed: {e}")
        except Exception as e:                      # last line of defence
            log("ERROR", f"fetcher error: {e!r}")
            stop_event.wait(5)


_worker = None


def ensure_worker():
    """Start the background fetcher, or restart it if it has stopped."""
    global _worker
    if stop_event.is_set():
        return
    if _worker is None or not _worker.is_alive():
        if _worker is not None:
            log("ERROR", "background fetcher had stopped; restarting it")
            with state_lock:
                state["syncing"] = False
                state["next_due"] = 0.0
        _worker = threading.Thread(target=fetch_worker, daemon=True, name="fetch_worker")
        _worker.start()


def snapshot():
    with state_lock:
        return {
            "cats": {c: dict(state["cats"][c]) for c in CATS},
            **{k: state[k] for k in ("gti", "gti_prev", "last_sync", "syncing",
                                     "fail_streak", "baseline", "attempts", "last_error")},
            "next_sync": time.time() + max(0.0, state["next_due"] - time.monotonic()),
        }


def load_demo_state():
    """Sample data for --demo: tests the display without any network."""
    now = datetime.now(timezone.utc)
    h = lambda hrs: now - timedelta(hours=hrs)
    demo = {
        "WAR": (41, 37, [story(4, h(2), "Missile strikes hit eastern city overnight as air defences intercept drones", "BBC")]),
        "DIS": (22, 22, [story(1, h(5), "Green notification for tropical cyclone KOGUMA-26", "GDACS")]),
        "CYB": (37, 45, [story(5, h(3), "Hospital network hit by ransomware attack, appointments cancelled", "Reuters")]),
        "BIO": (52, 48, [story(5, h(290), "WHO outbreak notice: Ebola disease caused by Bundibugyo virus - Democratic Republic of the Congo", "WHO")]),
    }
    with state_lock:
        for c, (score, prev, hls) in demo.items():
            state["cats"][c].update(score=score, prev=prev, headlines=hls, stale=(c == "CYB"))
        state["gti"] = compute_gti({c: v[0] for c, v in demo.items()})
        state["gti_prev"] = compute_gti({c: v[1] for c, v in demo.items()})
        state.update(last_sync=time.time() - 120, next_due=time.monotonic() + 780,
                     syncing=False, fail_streak=0, baseline=9, attempts=1, last_error=None)


# =============================================================================
# DISPLAY
# =============================================================================
BG = (7, 11, 19)
PANEL = (17, 25, 40)
TRACK = (31, 42, 61)
TEXT = (226, 234, 244)
MUTED = (126, 144, 168)
DIM = (66, 81, 103)
ACCENT = (0, 200, 255)
WARN = (255, 150, 40)
ERR = (240, 60, 80)
UP = (255, 120, 80)
DOWN = (60, 210, 140)

LEVELS = [   # (upper bound, name, color)
    (30, "LOW", (46, 204, 113)),
    (45, "GUARDED", (66, 153, 255)),
    (60, "ELEVATED", (241, 196, 15)),
    (75, "HIGH", (255, 128, 32)),
    (101, "SEVERE", (235, 59, 80)),
]
MONO_FONTS = "dejavusansmono,liberationmono,consolas,menlo,ubuntumono,couriernew,freemono"
SANS_FONTS = "dejavusans,liberationsans,arial,helvetica,ubuntu,freesans"

HEADLINE_MAX_LINES = 3
HEADLINE_SIZES = (21, 16)      # largest / smallest headline font, in 320x240 units

MAIN_SECS, CAT_SECS = 12, 8
FPS = 15
FADE_SECS = 0.25


def level_for(v):
    if v is None:
        return "NO DATA", MUTED
    for limit, name, color in LEVELS:
        if v < limit:
            return name, color
    return LEVELS[-1][1], LEVELS[-1][2]


def mix(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def ago(dt):
    if dt is None:
        return ""
    secs = (datetime.now(timezone.utc) - dt).total_seconds()
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 172800:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def mmss(secs):
    m, s = divmod(max(0, int(secs)), 60)
    return f"{m:02}:{s:02}"


class Display:
    """Layout is designed on a 320x240 grid and scaled to the real screen.
    Widths stretch to the screen; heights are scaled and centred."""

    def __init__(self, pygame, size=None, surface=None):
        """surface: draw into an existing pygame Surface (the caller flips the
        display). Otherwise open a window of `size`, or go fullscreen."""
        self.pg = pg = pygame
        pg.font.init()
        self.present = surface is None
        if surface is not None:
            self.screen = surface
        else:
            pg.display.init()
            if size:
                self.screen = pg.display.set_mode(size)
            else:
                info = pg.display.Info()
                self.screen = pg.display.set_mode((info.current_w, info.current_h),
                                                  pg.FULLSCREEN | pg.NOFRAME)
                pg.mouse.set_visible(False)
            pg.display.set_caption("Threat Monitor")
        self.W, self.H = self.screen.get_size()
        self.u = min(self.W / 320.0, self.H / 240.0)
        self.oy = int((self.H - 240 * self.u) / 2)
        self.m = self.s(10)
        self._paths = {"mono": pg.font.match_font(MONO_FONTS, bold=True),
                       "sans": pg.font.match_font(SANS_FONTS, bold=True)}
        self._fonts, self._texts, self._layouts = {}, {}, {}
        self.anim = {}
        self.gti_anim = None
        self.switch_t = 0.0
        self.fade = pg.Surface((self.W, self.H))
        self.fade.fill(BG)

    # ---- primitives ------------------------------------------------------
    def s(self, v):
        return int(round(v * self.u))

    def y(self, v):
        return self.oy + self.s(v)

    def font(self, kind, size):
        px = max(8, self.s(size))
        key = (kind, px)
        if key not in self._fonts:
            self._fonts[key] = self.pg.font.Font(self._paths.get(kind), px)
        return self._fonts[key]

    def text(self, s, kind, size, color):
        key = (s, kind, size, color)
        surf = self._texts.get(key)
        if surf is None:
            if len(self._texts) > 500:
                self._texts.clear()
            surf = self._texts[key] = self.font(kind, size).render(s, True, color)
        return surf

    def blit(self, surf, pos, anchor="topleft"):
        rect = surf.get_rect(**{anchor: pos})
        self.screen.blit(surf, rect)
        return rect

    def rect(self, color, r, radius=0):
        try:
            self.pg.draw.rect(self.screen, color, r, border_radius=radius)
        except TypeError:                           # pygame 1.9: no rounded corners
            self.pg.draw.rect(self.screen, color, r)

    def triangle(self, cx, cy, size, up, color):
        h = size // 2
        pts = ([(cx - h, cy + h // 2 + 1), (cx + h, cy + h // 2 + 1), (cx, cy - h // 2 - 1)] if up else
               [(cx - h, cy - h // 2 - 1), (cx + h, cy - h // 2 - 1), (cx, cy + h // 2 + 1)])
        self.pg.draw.polygon(self.screen, color, pts)

    def trend(self, cx, cy, now, prev, size):
        if now is None or prev is None:
            return
        d = now - prev
        if d >= 3:
            self.triangle(cx, cy, size, True, UP)
        elif d <= -3:
            self.triangle(cx, cy, size, False, DOWN)
        else:
            self.pg.draw.line(self.screen, DIM, (cx - size // 2 + 1, cy), (cx + size // 2 - 1, cy), max(1, self.s(2)))

    def progress(self, frac):
        h = max(2, self.s(2))
        self.rect(PANEL, (0, self.H - h, self.W, h))
        self.rect(ACCENT, (0, self.H - h, int(self.W * max(0.0, min(1.0, frac))), h))

    def finish(self, now):
        a = 1.0 - (now - self.switch_t) / FADE_SECS
        if a > 0:
            self.fade.set_alpha(int(255 * a))
            self.screen.blit(self.fade, (0, 0))
        if self.present:
            self.pg.display.flip()

    def wrap_lines(self, text, kind, size, max_w):
        f = self.font(kind, size)
        lines, cur = [], ""
        for word in text.split():
            trial = f"{cur} {word}".strip()
            if cur and f.size(trial)[0] > max_w:
                lines.append(cur)
                cur = word
            else:
                cur = trial
        if cur:
            lines.append(cur)
        return lines

    def headline_layout(self, text, max_w):
        """(lines, size, condensed?) for a headline in at most HEADLINE_MAX_LINES
        lines: the original at the largest font that fits, else the gentlest
        condensed version that fits, else a '…' cut. Cached per headline."""
        key = (text, max_w)
        hit = self._layouts.get(key)
        if hit:
            return hit
        big, small = HEADLINE_SIZES
        result = None
        steps, condensed = condense_steps(text)
        for i, cand in enumerate(steps):
            for size in range(big, small - 1, -1):
                lines = self.wrap_lines(cand, "sans", size, max_w)
                if len(lines) <= HEADLINE_MAX_LINES:
                    result = (lines, size, i > 0)
                    break
            if result:
                break
        if result is None:
            fits = lambda t: len(self.wrap_lines(t, "sans", small, max_w)) <= HEADLINE_MAX_LINES
            result = (self.wrap_lines(truncate_words(fits, condensed), "sans", small, max_w), small, True)
        if len(self._layouts) > 200:
            self._layouts.clear()
        self._layouts[key] = result
        return result

    # ---- animation of bar lengths only (numbers are always exact) ---------
    def step(self, snap, dt):
        k = min(1.0, dt * 5)
        for c in CATS:
            tgt = snap["cats"][c]["score"]
            cur = self.anim.get(c)
            self.anim[c] = None if tgt is None else (tgt if cur is None else cur + (tgt - cur) * k)
        tgt = snap["gti"]
        self.gti_anim = None if tgt is None else (tgt if self.gti_anim is None else self.gti_anim + (tgt - self.gti_anim) * k)

    # ---- screens ------------------------------------------------------------
    def draw_loading(self, now):
        self.screen.fill(BG)
        cy = self.H // 2
        self.blit(self.text("THREAT MONITOR", "mono", 17, ACCENT), (self.W // 2, cy - self.s(18)), "center")
        dots = "." * (int(now * 2) % 4)
        self.blit(self.text(f"Contacting sources{dots:<3}", "mono", 11, MUTED), (self.W // 2, cy + self.s(8)), "center")
        self.blit(self.text("BBC · AL JAZEERA · NPR · GDACS · CISA · WHO", "mono", 9, DIM), (self.W // 2, cy + self.s(26)), "center")
        if self.present:
            self.pg.display.flip()

    def draw_mini(self, snap):
        """Tiny view for the Windows screensaver preview box: index + level."""
        W, H = self.W, self.H
        self.screen.fill(BG)
        gti = snap["gti"] if snap["last_sync"] is not None else None
        name, col = level_for(gti)
        px = lambda frac: max(8, int(H * frac))
        f_title = self.pg.font.Font(self._paths.get("mono"), px(0.10))
        f_num = self.pg.font.Font(self._paths.get("mono"), px(0.42))
        f_lvl = self.pg.font.Font(self._paths.get("mono"), px(0.12))
        self.blit(f_title.render("THREAT MONITOR", True, ACCENT), (W // 2, int(H * 0.16)), "center")
        self.blit(f_num.render(str(gti) if gti is not None else "--", True, col), (W // 2, int(H * 0.50)), "center")
        self.blit(f_lvl.render(name, True, col), (W // 2, int(H * 0.82)), "center")
        if self.present:
            self.pg.display.flip()

    def draw_main(self, snap, now, frac):
        W, m, s = self.W, self.m, self.s
        self.screen.fill(BG)

        # header
        self.blit(self.text("THREAT MONITOR", "mono", 11, ACCENT), (m, self.y(6)))
        self.blit(self.text(time.strftime("%H:%M"), "mono", 11, MUTED), (W - m, self.y(6)), "topright")

        # category rows
        lab_w = self.text("WAR", "mono", 15, TEXT).get_width()
        val_w = self.text("100", "mono", 15, TEXT).get_width()
        arrow = s(9)
        x0 = m + lab_w + s(8)
        x1 = W - m - arrow - s(7) - val_w - s(8)
        bw, bh = x1 - x0, max(4, s(10))
        nx = x0 + int(bw * NORMAL_LEVEL / 100)
        for i, c in enumerate(CATS):
            cy = self.y(37 + i * 24)
            slot = snap["cats"][c]
            val, stale = slot["score"], slot["stale"]
            _, col = level_for(val)
            if stale:
                col = mix(col, TRACK, 0.55)
            self.blit(self.text(c, "mono", 15, TEXT), (m, cy), "midleft")
            self.rect(TRACK, (x0, cy - bh // 2, bw, bh), bh // 2)
            shown = self.anim.get(c)
            if shown:
                fw = int(bw * shown / 100)
                if fw > 0:
                    self.rect(col, (x0, cy - bh // 2, fw, bh), min(bh // 2, fw // 2))
            self.pg.draw.line(self.screen, MUTED, (nx, cy - bh // 2 - s(3)), (nx, cy + bh // 2 + s(2)), max(1, s(1)))
            vx = x1 + s(8) + val_w
            if val is None:
                self.blit(self.text("--", "mono", 15, ERR), (vx, cy), "midright")
            else:
                self.blit(self.text(str(val), "mono", 15, MUTED if stale else TEXT), (vx, cy), "midright")
                self.trend(W - m - arrow // 2, cy, val, slot["prev"], arrow)

        self.pg.draw.line(self.screen, PANEL, (m, self.y(128)), (W - m, self.y(128)), max(1, s(1)))

        # global index
        gti = snap["gti"]
        name, col = level_for(gti)
        self.blit(self.text("GLOBAL THREAT INDEX", "mono", 10, MUTED), (m, self.y(134)))
        if gti is not None and snap["gti_prev"] is not None:
            d = gti - snap["gti_prev"]
            t = self.text(f"{d:+d} since last sync" if d else "no change", "mono", 9, MUTED)
            r = self.blit(t, (W - m, self.y(135)), "topright")
            if abs(d) >= 3:
                self.triangle(r.left - s(7), r.centery, s(8), d > 0, UP if d > 0 else DOWN)

        num = self.text(str(gti) if gti is not None else "--", "mono", 38, col if gti is not None else ERR)
        nr = self.blit(num, (m - s(2), self.y(146)))
        if gti is not None:
            self.blit(self.text("%", "mono", 16, col), (nr.right + s(2), nr.bottom - s(9)), "bottomleft")

        badge = self.text(name, "mono", 14, BG)
        bw2, bh2 = badge.get_width() + s(14), badge.get_height() + s(6)
        br = self.pg.Rect(0, 0, bw2, bh2)
        br.midright = (W - m, nr.centery - s(4))
        self.rect(col, br, s(4))
        self.blit(badge, br.center, "center")
        self.blit(self.text(f"NORMAL DAY ~{NORMAL_LEVEL}", "mono", 9, DIM), (W - m, br.bottom + s(4)), "topright")

        # gauge with level bands and a pointer
        gy, gh = self.y(193), max(3, s(4))
        gx0, gx1 = m, W - m
        lo = 0
        for limit, _, lc in LEVELS:
            hi = min(limit, 100)
            a = gx0 + int((gx1 - gx0) * lo / 100)
            b = gx0 + int((gx1 - gx0) * hi / 100)
            self.rect(lc if gti is not None and lo <= gti < limit else mix(lc, BG, 0.6), (a + 1, gy, b - a - 2, gh), gh // 2)
            lo = limit
        if self.gti_anim is not None:
            px = gx0 + int((gx1 - gx0) * min(self.gti_anim, 100) / 100)
            self.triangle(px, gy + gh + s(5), s(9), True, TEXT)      # pointer under the gauge

        # footer
        fy = self.y(219)
        upd = time.strftime("%H:%M", time.localtime(snap["last_sync"])) if snap["last_sync"] else "--:--"
        self.blit(self.text(f"UPDATED {upd}", "mono", 10, MUTED), (m, fy), "midleft")
        if snap["syncing"]:
            right, rc = "SYNCING...", ACCENT
        elif snap["fail_streak"]:
            right, rc = f"RETRY IN {mmss(snap['next_sync'] - now)}", WARN
        else:
            right, rc = f"NEXT IN {mmss(snap['next_sync'] - now)}", MUTED
        self.blit(self.text(right, "mono", 10, rc), (W - m, fy), "midright")
        if all(snap["cats"][c]["score"] is None for c in CATS):
            self.blit(self.text("NO DATA YET", "mono", 10, WARN), (W // 2, fy), "center")
        elif any(snap["cats"][c]["stale"] or snap["cats"][c]["score"] is None for c in CATS):
            self.blit(self.text("SOURCE OFFLINE", "mono", 10, WARN), (W // 2, fy), "center")
        elif snap["baseline"] < CALIB_SETTLED:
            self.blit(self.text(f"LEARNING {snap['baseline']}/{CALIB_SETTLED}h", "mono", 10, DIM), (W // 2, fy), "center")

        self.progress(frac)
        self.finish(now)

    def draw_headline(self, snap, cat, idx, now, frac):
        W, m, s = self.W, self.m, self.s
        self.screen.fill(BG)
        slot = snap["cats"][cat]
        val = slot["score"]
        lvl, col = level_for(val)

        # header band
        bh = s(30)
        self.rect(PANEL, (0, self.y(0), W, bh))
        self.rect(col, (0, self.y(0), s(4), bh))
        cy = self.y(15)
        self.blit(self.text(CAT_NAMES[cat], "mono", 15, TEXT), (m + s(2), cy), "midleft")
        r = self.blit(self.text(f"{val}" if val is not None else "--", "mono", 15, col), (W - m, cy), "midright")
        self.blit(self.text(lvl, "mono", 9, col), (r.left - s(6), cy), "midright")

        hls = slot["headlines"]
        if hls:
            h = hls[idx % len(hls)]
            title, meta, page = h["title"], f"{h['source']} · {ago(h['date'])}", f"{idx % len(hls) + 1}/{len(hls)}"
            colour = TEXT
        else:
            title, meta, page, colour = EMPTY_MSG[cat], "", "", MUTED

        top, bottom = self.y(40), self.y(196)
        lines, size, _ = self.headline_layout(title, W - 2 * m)
        lh = int(self.font("sans", size).get_linesize() * 1.02)
        ty = top + max(0, (bottom - top - len(lines) * lh) // 2)
        for i, line in enumerate(lines):
            self.blit(self.text(line, "sans", size, colour), (m, ty + i * lh))

        my = self.y(210)
        if meta:
            self.blit(self.text(meta, "mono", 10, MUTED), (m, my), "midleft")
        right = "CACHED" if slot["stale"] else page
        if right:
            self.blit(self.text(right, "mono", 10, WARN if slot["stale"] else DIM), (W - m, my), "midright")

        # which screen of the rotation this is
        n = len(CATS) + 1
        cur = CATS.index(cat) + 1
        dot, gap = s(4), s(9)
        x = W // 2 - (n - 1) * gap // 2
        for i in range(n):
            self.pg.draw.circle(self.screen, ACCENT if i == cur else DIM, (x + i * gap, self.y(227)), max(2, dot // 2))

        self.progress(frac)
        self.finish(now)


# =============================================================================
# MAIN LOOP
# =============================================================================
class Rotator:
    """Which screen is showing: MAIN, then each category, on a timer."""

    def __init__(self):
        self.screens = ["MAIN"] + CATS
        self.idx, self.t_switch = 0, time.time()
        self.rot = {c: -1 for c in CATS}           # which headline each category shows next
        self.loaded = False
        self.switched = False

    def go(self, step, now):
        if not self.loaded:                        # ignore taps/keys until data arrives
            return
        self.idx = (self.idx + step) % len(self.screens)
        name = self.screens[self.idx]
        if name in self.rot:
            self.rot[name] += 1
        self.t_switch, self.switched = now, True

    def tick(self, now, snap):
        """Returns None while the very first sync is running, else (screen,
        headline index, progress 0-1). After any attempt - even a failed one -
        the dashboard is shown, with "--" where there is no data."""
        if snap["last_sync"] is None and not snap["attempts"]:
            return None
        if not self.loaded:                        # first data: open on the main screen
            self.loaded, self.idx = True, 0
            self.t_switch, self.switched = now, True
        dur = MAIN_SECS if self.screens[self.idx] == "MAIN" else CAT_SECS
        if now - self.t_switch >= dur:
            self.go(1, now)
            dur = MAIN_SECS if self.screens[self.idx] == "MAIN" else CAT_SECS
        name = self.screens[self.idx]
        return name, max(0, self.rot.get(name, 0)), (now - self.t_switch) / dur

    def take_switched(self):
        s, self.switched = self.switched, False
        return s


def draw_view(disp, snap, view, now):
    if view is None:
        disp.draw_loading(now)
    elif view[0] == "MAIN":
        disp.draw_main(snap, now, view[2])
    else:
        disp.draw_headline(snap, view[0], view[1], now, view[2])


def run(disp, snapshot_dir=None, live=False):
    pg = disp.pg
    clock = pg.time.Clock()
    last = time.time()
    last_watch = 0.0

    if snapshot_dir:                  # render each screen once to PNG and exit
        os.makedirs(snapshot_dir, exist_ok=True)
        snap = snapshot()
        disp.step(snap, 10)
        now = time.time()
        disp.switch_t = now - 10
        disp.draw_main(snap, now, 0.4)
        pg.image.save(disp.screen, os.path.join(snapshot_dir, "0_main.png"))
        for i, c in enumerate(CATS, 1):
            disp.draw_headline(snap, c, 0, now, 0.6)
            pg.image.save(disp.screen, os.path.join(snapshot_dir, f"{i}_{c.lower()}.png"))
        return

    rot = Rotator()
    running = True
    while running:
        now = time.time()
        for ev in pg.event.get():
            if ev.type == pg.QUIT:
                running = False
            elif ev.type == pg.KEYDOWN:
                if ev.key in (pg.K_ESCAPE, pg.K_q):
                    running = False
                elif ev.key in (pg.K_RIGHT, pg.K_SPACE, pg.K_RETURN):
                    rot.go(1, now)
                elif ev.key == pg.K_LEFT:
                    rot.go(-1, now)
                elif ev.key == pg.K_r:
                    wake_event.set()
            elif ev.type == pg.MOUSEBUTTONDOWN:     # touchscreens report taps as clicks
                rot.go(1, now)

        if live and now - last_watch > 5:          # restart the fetcher if it ever stopped
            ensure_worker()
            last_watch = now
        snap = snapshot()
        disp.step(snap, now - last)
        last = now
        view = rot.tick(now, snap)
        if rot.take_switched():
            disp.switch_t = now
        draw_view(disp, snap, view, now)
        clock.tick(FPS)


def run_check():
    """python3 threat_monitor.py --check : fetch every source once and explain
    each score. Changes nothing (no calibration samples are recorded)."""
    global LOG_STDOUT
    LOG_STDOUT = False
    now = datetime.now(timezone.utc)
    print(f"Threat Monitor v3.3 source check - clock {now:%Y-%m-%d %H:%M} UTC, "
          f"local {time.strftime('%Y-%m-%d %H:%M %Z')}")
    print(f"Data folder: {DATA_DIR}   learned history: {baseline_hours()} h")
    print(f"Fetching all sources (up to {SYNC_DEADLINE} s)...\n", flush=True)
    t0 = time.monotonic()
    fetched = fetch_sources(now)
    for name in ("WAR", "CYB", "BIO"):
        comps, stories = fetch_category(name, now, fetched)
        try:
            result = str(score_from_ratio(combine(name, comps, calibration)))
        except RuntimeError as e:
            result = f"--  ({e})"
        print(f"{name}  ->  {result}")
        for c in comps:
            if c["kind"] == "headlines":
                info = c["note"] or f"{c['hits']} matching headlines (shown on screen, not scored)"
                print(f"   {c['label']:<12} {info}")
            elif not c["ok"]:
                print(f"   {c['label']:<12} NOT USED: {c['note']}  ({c['items']} stories in feed)")
            else:
                line = f"   {c['label']:<12} {c['recent']:>3} recent, {c['hits']:>2} threat-related, level {c['raw']:.2f}"
                if "ratio" in c:
                    line += (f"  vs normal {c['normal']:.2f} "
                             f"({'learned' if c['learned'] else 'starting guess'}) = {c['ratio']:.2f}x")
                print(line)
        for h in pick_headlines(stories):
            print(f"      - {h['title'][:100]}  [{h['source']}]")
        print()
    for key in (("DIS", "GDACS"), ("DIS", "USGS")):
        status, value = fetched[key]
        print(f"   {key[1]:<12} " + (f"{len(value)} current events" if status == "ok" else f"failed: {value}"))
    try:
        score, st = score_disasters(now, fetched)
        print(f"DIS  ->  {score}")
        for h in pick_headlines(st):
            print(f"      - {h['title'][:100]}  [{h['source']}]")
    except Exception as e:
        print(f"DIS  ->  --  ({e})")
    print(f"\nDone in {time.monotonic() - t0:.1f} s. Log file: {os.path.join(DATA_DIR, 'threat_monitor.log')}")


def main():
    ap = argparse.ArgumentParser(description="Threat Monitor by Oliver Kuy - global threat news dashboard")
    ap.add_argument("--windowed", metavar="WxH", help="run in a window, e.g. 320x240")
    ap.add_argument("--demo", action="store_true", help="sample data, no network")
    ap.add_argument("--snapshot", metavar="DIR", help="save a PNG of each screen and exit")
    ap.add_argument("--check", action="store_true", help="test every news source and explain the scores")
    args = ap.parse_args()
    if args.check:
        run_check()
        return

    size = None
    if args.windowed:
        try:
            size = tuple(int(v) for v in args.windowed.lower().split("x"))
            assert len(size) == 2
        except (ValueError, AssertionError):
            ap.error("--windowed expects WIDTHxHEIGHT, e.g. 320x240")

    global LOG_FILE
    live = not (args.demo or args.snapshot)
    if live:
        LOG_FILE = os.path.join(DATA_DIR, "threat_monitor.log")
        log("INFO", f"Threat Monitor v3.3 starting (data folder {DATA_DIR})")
    import pygame
    disp = Display(pygame, size)
    if live:
        load_state_cache()
        ensure_worker()
    else:
        load_demo_state()
    try:
        run(disp, args.snapshot, live=live)
    finally:
        stop_event.set()
        wake_event.set()
        pygame.quit()


if __name__ == "__main__":
    main()


# =============================================================================
# NOTES
# =============================================================================
# WAR / CYB / BIO
#   Sources: general news feeds (BBC + Al Jazeera + NPR for WAR, BBC + NPR for
#   CYB and BIO) plus official lists (CISA exploited vulnerabilities for CYB,
#   WHO outbreak notices for BIO). In each feed every recent story gets ONE
#   severity weight (its most serious keyword match); the feed's level is the
#   average per story. Each source is divided by its own 30-day median, the
#   ratios are averaged, and score = 100 * (1 - e^(-0.431 * ratio)):
#   usual level ~35, twice usual ~58, three times ~73. A feed that returns
#   too few recent stories is left out rather than counted as zero; if no
#   feed works the category shows "--". Google News results are shown as
#   headlines but never scored. Run with --check to see every source.
# DIS
#   GDACS alert levels: routine Green events count up to a cap, each Orange
#   or Red alert in full. Falls back to USGS PAGER earthquake alerts.
# GTI
#   Weighted root-mean-square of the four scores, so one severe category
#   lifts it more than a plain average would.
#
# Limits: news coverage measures how much is REPORTED, not real-world danger.
# Because the news categories are relative to the last 30 days, a long crisis
# slowly becomes the new "normal". Delete threat_calibration.json to restart
# calibration (it also resets itself automatically when CALIB_VERSION changes).
# threat_state.json holds the last values so the display starts instantly.
