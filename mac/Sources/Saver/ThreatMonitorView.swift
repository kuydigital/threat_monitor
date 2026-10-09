// THREAT MONITOR - macOS screensaver
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// macOS creates one of these views per screen. All views share one Engine
// (data) and one Rotator (which screen is showing). The dashboard panel
// drifts slowly inside the screen so nothing stays in one place for long.
// Build with mac/build.sh.

import AppKit
import ScreenSaver

@objc(ThreatMonitorView)
final class ThreatMonitorView: ScreenSaverView {
    private let renderer = Renderer()
    private let phase = Double.random(in: 0..<(2 * Double.pi))
    private var lastDraw: Double = 0

    // Test hooks for mac/Tests/saver_check.m (set through key-value coding).
    /// "", or a screen to draw without the rotation: MAIN, WAR, DIS, CYB, BIO, LOADING, MINI.
    @objc var tmForcedScreen: String = ""
    /// true: show sample data instead of fetching.
    @objc var tmDemo: Bool = false {
        didSet { if tmDemo { Engine.shared.loadDemo() } }
    }
    /// The current data as JSON.
    @objc var tmStatus: String { Engine.shared.statusJSON() }

    override init?(frame: NSRect, isPreview: Bool) {
        super.init(frame: frame, isPreview: isPreview)
        setUp()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setUp()
    }

    private func setUp() {
        animationTimeInterval = 1.0 / 10.0          // a screensaver doesn't need more
        DistributedNotificationCenter.default().addObserver(
            self, selector: #selector(screensaverWillStop(_:)),
            name: Notification.Name("com.apple.screensaver.willstop"), object: nil)
    }

    deinit {
        DistributedNotificationCenter.default().removeObserver(self)
    }

    override var isFlipped: Bool { true }
    override var isOpaque: Bool { true }
    override var hasConfigureSheet: Bool { false }
    override var configureSheet: NSWindow? { nil }

    override func startAnimation() {
        super.startAnimation()
        Engine.shared.viewStarted()
    }

    override func stopAnimation() {
        super.stopAnimation()
        Engine.shared.viewStopped()
    }

    override func animateOneFrame() {
        setNeedsDisplay(bounds)
    }

    /// Since macOS 14 the screensaver process keeps running after the
    /// screensaver ends and never stops its views, so they would pile up and
    /// keep downloading. Ending the process is the usual fix; macOS starts a
    /// fresh one next time.
    @objc private func screensaverWillStop(_ note: Notification) {
        if isPreview { return }
        if #available(macOS 14.0, *) {
            exit(0)
        }
    }

    override func draw(_ rect: NSRect) {
        let now = wallNow()
        let b = bounds
        Palette.bg.ns.setFill()
        NSBezierPath(rect: b).fill()

        let snap = Engine.shared.snapshot()
        let forced = tmForcedScreen.uppercased()
        let dt = lastDraw == 0 ? 10 : now - lastDraw
        lastDraw = now

        if forced == "MINI" || b.width < 320 || b.height < 200 {
            renderer.setSize(b.width, b.height)
            renderer.drawMini(snap)
            return
        }

        // Panel: 94% of the height, at most 1.5 x as wide as tall.
        let ph = (b.height * 0.94).rounded(.down)
        let pw = min(b.width, (ph * 1.5).rounded(.down))
        var fx = 0.5, fy = 0.5
        if !isPreview && forced.isEmpty {
            fx = 0.5 + 0.5 * sin(now / 173.0 + phase)          // ~18 minutes per sweep
            fy = 0.5 + 0.5 * sin(now / 241.0 + phase * 2)
        }
        let ox = ((b.width - pw) * CGFloat(fx)).rounded(.down)
        let oy = ((b.height - ph) * CGFloat(fy)).rounded(.down)

        NSGraphicsContext.saveGraphicsState()
        let shift = NSAffineTransform()
        shift.translateX(by: ox, yBy: oy)
        shift.concat()
        NSBezierPath(rect: NSRect(x: 0, y: 0, width: pw, height: ph)).addClip()
        renderer.setSize(pw, ph)
        renderer.step(snap, dt: dt)
        switch forced {
        case "":
            let view = Rotator.shared.tick(now, snap)
            renderer.draw(snap, view: view, now: now, fadeFrom: Rotator.shared.tSwitch)
        case "LOADING":
            renderer.drawLoading(now)
        case "MAIN":
            renderer.drawMain(snap, now: now, frac: 0.4)
        default:
            renderer.drawHeadline(snap, cat: TM.cats.contains(forced) ? forced : "WAR", index: 0, now: now, frac: 0.6)
        }
        NSGraphicsContext.restoreGraphicsState()
    }
}
