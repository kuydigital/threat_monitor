# Threat Monitor

Created and maintained by **Oliver Kuy** ([@kuydigital](https://github.com/kuydigital)).

A small dashboard that turns public news and alert feeds into a **Global Threat
Index** plus four scores: **WAR**, **DIS** (natural disasters), **CYB** (cyber)
and **BIO** (outbreaks), with the latest headline for each. It runs on a
Raspberry Pi with a tiny 320×240 screen, in a window on any desktop, or as a
Windows 10/11 screensaver.

![Threat Monitor screens (sample data)](docs/screens.png)

## Windows screensaver (no Python needed)

1. Download `ThreatMonitor-Windows-<version>.zip` from the
   [Releases](https://github.com/kuydigital/threat_monitor/releases) page and unzip it.
2. Double-click **install.bat**. If Windows shows *"Windows protected your PC"*,
   click *More info → Run anyway* (shown for downloaded programs that aren't
   signed by a company).
3. Screen Saver Settings opens with **ThreatMonitor** selected. Pick a wait
   time and click **OK**.

To remove it, run `uninstall_screensaver.bat`.

### Building the screensaver yourself

Double-click `build_screensaver.bat` in a copy of this repository. It builds
the screensaver and installs it. If Python isn't installed, it offers to
install Python 3.13 for your user account first (no admin rights needed). The
finished screensaver carries its own copy of Python, so Python is only needed
for building.

## Raspberry Pi / Linux / macOS

```bash
sudo apt install python3-pygame python3-requests   # Raspberry Pi OS / Debian
# or: pip install -r requirements.txt

python3 threat_monitor.py                     # full screen
python3 threat_monitor.py --windowed 320x240  # in a window
python3 threat_monitor.py --demo              # sample data, no network
python3 threat_monitor.py --check             # test every source, explain the scores
```

Keys: **Esc/Q** quit · **→ / Space / tap** next screen · **←** previous · **R** update now.

## How the scores work

- **WAR, CYB, BIO** measure how much of the general news is about each
  threat, compared with that source's own usual level over the last 30 days.
  An ordinary day reads about **35 (GUARDED)**, twice the usual amount about
  58, three times about 73. The first day uses starting estimates while the
  monitor learns what "usual" looks like (shown as *LEARNING n/24h*).
- **DIS** uses official GDACS alert levels (USGS earthquake alerts as a backup):
  routine green alerts count a little, orange and red alerts count fully.
- **Global Threat Index** combines the four, giving more weight to whichever
  is highest.
- Levels: LOW < 30 · GUARDED 30–44 · ELEVATED 45–59 · HIGH 60–74 · SEVERE 75+.

It measures how much is being *reported*, not real-world danger, so treat it
as a news-intensity indicator rather than a forecast.

## Data sources

[BBC News](https://www.bbc.co.uk/news), [Al Jazeera](https://www.aljazeera.com),
[NPR](https://www.npr.org) and [Google News](https://news.google.com) RSS feeds;
[GDACS](https://www.gdacs.org) disaster alerts (© European Union, CC BY 4.0);
[USGS](https://earthquake.usgs.gov) earthquake feed;
[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog);
[WHO Disease Outbreak News](https://www.who.int/emergencies/disease-outbreak-news).
Headlines belong to their publishers and are shown with their source.

## Troubleshooting

- **Pi / Linux:** `threat_monitor.log` next to the script records every update
  and any source that failed. `python3 threat_monitor.py --check` shows what
  each source returned.
- **Windows:** the log is `%APPDATA%\ThreatMonitor\screensaver.log`. If
  ThreatMonitor is missing from the Screen Saver list, run
  `register_screensaver.bat`.

## Publishing a new release (maintainers)

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds the screensaver on Windows, tests it, and publishes
`ThreatMonitor-Windows-v1.0.0.zip` on the Releases page
(see `.github/workflows/release.yml`).

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Oliver Kuy.
