# THREAT MONITOR - Windows 10/11 screensaver
# Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
# Revised: Friday, October 9, 2026
#
# Wraps threat_monitor.py (same data, scoring and screens) as a .scr file.
# Build it on Windows with build_screensaver.bat; see README.txt. Uses
# pygame-ce (prebuilt for every current Python, including 3.14).
#
# Windows starts a screensaver with one of these arguments:
#   /s          show it full screen (all monitors)
#   /p <hwnd>   draw the small preview inside Screen Saver Settings
#   /c[:hwnd]   the "Settings" button          (no argument = same as /c)
# For testing outside Windows:  python threat_screensaver.py /s --size 1280x720
# -----------------------------------------------------------------------------

import math
import os
import sys
import time

import threat_monitor as tm

IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes

SS_FPS = 10              # a screensaver doesn't need more; keeps CPU use low
PANEL_ASPECT = 1.5       # dashboard width at most 1.5 x its height, centred
PANEL_HEIGHT = 0.94      # leaves a little room so the panel can drift
MOVE_TOLERANCE = 12      # pixels of mouse movement that wake the PC
GRACE_SECS = 1.0         # ignore input right after start (Windows jiggles the mouse)
LOG_MAX_BYTES = 512 * 1024


# =============================================================================
# Windows helpers (all no-ops elsewhere so the logic can be tested anywhere)
# =============================================================================
def set_dpi_aware():
    """Use real pixels on high-DPI screens instead of a blurry scaled window."""
    os.environ.setdefault("SDL_WINDOWS_DPI_AWARENESS", "permonitorv2")
    if not IS_WINDOWS:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def virtual_screen():
    """Bounding box of all monitors: (x, y, width, height)."""
    if not IS_WINDOWS:
        return None
    gsm = ctypes.windll.user32.GetSystemMetrics
    return gsm(76), gsm(77), gsm(78), gsm(79)   # SM_X/Y/CX/CYVIRTUALSCREEN


def monitor_rects():
    """Each monitor as (x, y, width, height) in virtual-screen coordinates."""
    if not IS_WINDOWS:
        return []
    rects = []
    proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.HDC,
                                   ctypes.POINTER(wintypes.RECT), wintypes.LPARAM)

    def callback(hmon, hdc, lprect, lparam):
        r = lprect.contents
        rects.append((r.left, r.top, r.right - r.left, r.bottom - r.top))
        return True

    proc = proc_type(callback)                     # keep a reference during the call
    ctypes.windll.user32.EnumDisplayMonitors(None, None, proc, 0)
    return rects


def cursor_pos():
    if not IS_WINDOWS:
        return None
    pt = wintypes.POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def make_topmost(pg, x, y, w, h):
    if not IS_WINDOWS:
        return
    try:
        hwnd = pg.display.get_wm_info()["window"]
        user32 = ctypes.windll.user32
        user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                        ctypes.c_int, ctypes.c_int, ctypes.c_uint]
        HWND_TOPMOST, SWP_SHOWWINDOW = wintypes.HWND(-1), 0x0040
        user32.SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_SHOWWINDOW)
        user32.SetForegroundWindow(wintypes.HWND(hwnd))
    except Exception as e:
        tm.log("WARN", f"could not bring window to front: {e}")


def window_alive(hwnd):
    if not IS_WINDOWS:
        return True
    return bool(ctypes.windll.user32.IsWindow(wintypes.HWND(hwnd)))


def client_size(hwnd):
    rect = wintypes.RECT()
    ctypes.windll.user32.GetClientRect(wintypes.HWND(hwnd), ctypes.byref(rect))
    return rect.right - rect.left, rect.bottom - rect.top


def message_box(text, title, owner=None):
    if IS_WINDOWS:
        ctypes.windll.user32.MessageBoxW(wintypes.HWND(owner or 0), text, title, 0x40)  # MB_ICONINFORMATION
    else:
        print(f"{title}\n\n{text}")


# =============================================================================
# Logging: a .scr has no console, so log to a small file in the data folder
# =============================================================================
def setup_log():
    """Log to screensaver.log only (a .scr has no console). threat_monitor's
    log() never raises, so a log problem can't stop the screensaver."""
    try:
        os.makedirs(tm.DATA_DIR, exist_ok=True)
    except OSError:
        pass
    tm.LOG_FILE = os.path.join(tm.DATA_DIR, "screensaver.log")
    tm.LOG_MAX_BYTES = LOG_MAX_BYTES
    tm.LOG_STDOUT = False


# =============================================================================
# Command line
# =============================================================================
def parse_args(argv):
    """Returns (mode, hwnd, test_size). Accepts /s /S -s, /p 123, /p:123, /c:123."""
    args = list(argv[1:])
    test_size = None
    if "--size" in args:                          # testing only
        i = args.index("--size")
        w, h = args[i + 1].lower().split("x")
        test_size = (int(w), int(h))
        del args[i:i + 2]
    if not args:
        return "config", None, test_size
    first = args[0].strip().lower()
    flag, _, value = first.partition(":")
    if not value and len(args) > 1:
        value = args[1]
    try:
        hwnd = int(value) if value else None
    except ValueError:
        hwnd = None
    mode = {"/s": "show", "-s": "show", "/p": "preview", "-p": "preview",
            "/c": "config", "-c": "config"}.get(flag[:2], "config")
    return mode, hwnd, test_size


# =============================================================================
# /s  full-screen screensaver
# =============================================================================
class Panel:
    """One monitor: a dashboard surface that drifts slowly inside the monitor
    area (prevents burn-in on OLED screens)."""

    def __init__(self, pg, screen, rect, phase):
        self.area = screen.subsurface(rect)
        w, h = rect.size
        ph = int(h * PANEL_HEIGHT)
        pw = min(w, int(ph * PANEL_ASPECT))
        self.surf = pg.Surface((pw, ph)).convert()
        self.disp = tm.Display(pg, surface=self.surf)
        self.spare = (w - pw, h - ph)
        self.phase = phase

    def offset(self, now):
        sx, sy = self.spare
        fx = 0.5 + 0.5 * math.sin(now / 173.0 + self.phase)     # ~18 min per sweep
        fy = 0.5 + 0.5 * math.sin(now / 241.0 + self.phase * 2)
        return int(sx * fx), int(sy * fy)


def run_show(test_size=None, max_seconds=None, frame_hook=None):
    set_dpi_aware()
    import pygame as pg

    vs = virtual_screen()
    if vs is None:                                 # not Windows: one test window
        size = test_size or (1280, 720)
        vs = (0, 0) + tuple(size)
        monitors = [vs]
    else:
        monitors = monitor_rects() or [vs]
    vx, vy, vw, vh = vs
    os.environ["SDL_VIDEO_WINDOW_POS"] = f"{vx},{vy}"

    pg.display.init()
    screen = pg.display.set_mode((vw, vh), pg.NOFRAME)
    pg.display.set_caption("Threat Monitor")
    pg.mouse.set_visible(False)
    make_topmost(pg, vx, vy, vw, vh)
    screen.fill(tm.BG)
    pg.display.flip()

    panels = [Panel(pg, screen, pg.Rect(x - vx, y - vy, w, h), i * 1.7)
              for i, (x, y, w, h) in enumerate(monitors)]

    tm.load_state_cache()                          # show the last values immediately
    tm.ensure_worker()

    rot = tm.Rotator()
    clock = pg.time.Clock()
    start = last = last_watch = time.time()
    origin = cursor_pos()
    focus_lost = getattr(pg, "WINDOWFOCUSLOST", None)
    running = True
    while running:
        now = time.time()
        armed = now - start > GRACE_SECS
        for ev in pg.event.get():
            if ev.type == pg.QUIT:
                running = False
            elif not armed:
                continue
            elif ev.type in (pg.KEYDOWN, pg.MOUSEBUTTONDOWN, getattr(pg, "MOUSEWHEEL", -1)):
                running = False
            elif ev.type == pg.MOUSEMOTION and origin is None:   # non-Windows fallback
                if abs(ev.rel[0]) + abs(ev.rel[1]) > MOVE_TOLERANCE:
                    running = False
            elif focus_lost is not None and ev.type == focus_lost:
                running = False
        pos = cursor_pos()
        if armed and origin is not None and pos is not None:
            if abs(pos[0] - origin[0]) + abs(pos[1] - origin[1]) > MOVE_TOLERANCE:
                running = False
        if not running:
            break

        if now - last_watch > 5:                   # restart the fetcher if it ever stopped
            tm.ensure_worker()
            last_watch = now
        snap = tm.snapshot()
        view = rot.tick(now, snap)
        switched = rot.take_switched()
        for p in panels:
            if switched:
                p.disp.switch_t = now
            p.disp.step(snap, now - last)
            tm.draw_view(p.disp, snap, view, now)
            p.area.fill(tm.BG)
            p.area.blit(p.surf, p.offset(now))
        pg.display.flip()
        last = now
        if frame_hook:
            frame_hook(screen, now)
        if max_seconds and now - start > max_seconds:
            break
        clock.tick(SS_FPS)

    tm.stop_event.set()
    tm.wake_event.set()
    pg.quit()


# =============================================================================
# /p  preview inside Screen Saver Settings (no network: shows last values)
# =============================================================================
def run_preview(hwnd):
    if not IS_WINDOWS or not hwnd:
        return
    w, h = client_size(hwnd)
    if w <= 0 or h <= 0:
        return
    os.environ["SDL_WINDOWID"] = str(hwnd)        # draw into the dialog's little screen
    import pygame as pg
    pg.display.init()
    screen = pg.display.set_mode((w, h))
    disp = tm.Display(pg, surface=screen)
    tm.load_state_cache()
    started = time.time()
    while window_alive(hwnd) and time.time() - started < 3600:
        pg.event.pump()
        disp.draw_mini(tm.snapshot())
        pg.display.flip()
        time.sleep(0.5)
    pg.quit()


# =============================================================================
# /c  settings button
# =============================================================================
def run_config(owner):
    message_box(
        "Threat Monitor screensaver\n"
        "Created and maintained by Oliver Kuy\n"
        "github.com/kuydigital/threat_monitor\n\n"
        "Shows the Global Threat Index and the latest war, disaster, cyber "
        "and bio alerts while your PC is idle. News categories are measured "
        "against their own recent normal, so an ordinary day reads about 35 (GUARDED).\n\n"
        "Sources: BBC, Al Jazeera, NPR, Google News, GDACS, USGS, CISA, WHO.\n\n"
        "There are no settings to change. Saved data and the log are in:\n"
        f"{tm.DATA_DIR}",
        "Threat Monitor", owner)


def run_selftest():
    """--selftest: draw every screen off-screen with sample data and exit 0.
    The GitHub build runs this to check the packaged .scr really works.
    A windowed build has no console, so problems go to selftest.log."""
    try:
        os.environ["SDL_VIDEODRIVER"] = "dummy"
        import pygame as pg
        pg.display.init()
        surf = pg.Surface((640, 480))
        disp = tm.Display(pg, surface=surf)
        tm.load_demo_state()
        snap = tm.snapshot()
        now = time.time()
        disp.step(snap, 10)
        disp.draw_main(snap, now, 0.5)
        for c in tm.CATS:
            disp.draw_headline(snap, c, 0, now, 0.5)
        disp.draw_mini(snap)
        pg.quit()
        return 0
    except Exception:
        import traceback
        try:
            with open("selftest.log", "w", encoding="utf-8") as f:
                traceback.print_exc(file=f)
        except OSError:
            pass
        return 1


def main():
    if "--selftest" in sys.argv[1:]:
        sys.exit(run_selftest())
    mode, hwnd, test_size = parse_args(sys.argv)
    if getattr(sys, "frozen", False) or IS_WINDOWS:
        setup_log()
    tm.log("INFO", f"screensaver start: mode={mode} hwnd={hwnd}")
    try:
        if mode == "show":
            run_show(test_size)
        elif mode == "preview":
            run_preview(hwnd)
        else:
            run_config(hwnd)
    except Exception as e:                         # never leave a stuck full-screen window
        tm.log("ERROR", f"{mode} failed: {e!r}")
    finally:
        tm.stop_event.set()
        tm.wake_event.set()


if __name__ == "__main__":
    main()
