// THREAT MONITOR for macOS - drawing
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// Same screens as the Python version (Display class): the layout is designed
// on a 320x240 grid and scaled to the real panel. Widths stretch to the
// panel; heights are scaled and centred. Drawn in a flipped view (y down).

import AppKit

struct RGB {
    let r: Int, g: Int, b: Int
    let ns: NSColor

    init(_ r: Int, _ g: Int, _ b: Int) {
        self.r = r
        self.g = g
        self.b = b
        ns = NSColor(srgbRed: CGFloat(r) / 255, green: CGFloat(g) / 255, blue: CGFloat(b) / 255, alpha: 1)
    }

    /// Python: mix(a, b, t)
    func mix(_ o: RGB, _ t: Double) -> RGB {
        RGB(Int(Double(r) + Double(o.r - r) * t), Int(Double(g) + Double(o.g - g) * t),
            Int(Double(b) + Double(o.b - b) * t))
    }
}

enum Palette {
    static let bg = RGB(7, 11, 19)
    static let panel = RGB(17, 25, 40)
    static let track = RGB(31, 42, 61)
    static let text = RGB(226, 234, 244)
    static let muted = RGB(126, 144, 168)
    static let dim = RGB(66, 81, 103)
    static let accent = RGB(0, 200, 255)
    static let warn = RGB(255, 150, 40)
    static let err = RGB(240, 60, 80)
    static let up = RGB(255, 120, 80)
    static let down = RGB(60, 210, 140)
    static let levels: [(limit: Int, name: String, color: RGB)] = [
        (30, "LOW", RGB(46, 204, 113)),
        (45, "GUARDED", RGB(66, 153, 255)),
        (60, "ELEVATED", RGB(241, 196, 15)),
        (75, "HIGH", RGB(255, 128, 32)),
        (101, "SEVERE", RGB(235, 59, 80)),
    ]

    static func level(_ v: Int?) -> (name: String, color: RGB) {
        guard let v = v else { return ("NO DATA", muted) }
        for l in levels where v < l.limit { return (l.name, l.color) }
        let last = levels[levels.count - 1]
        return (last.name, last.color)
    }
}

final class Renderer {
    enum Kind { case mono, sans }
    enum Anchor { case topLeft, topRight, midLeft, midRight, center, bottomLeft }

    private(set) var W: CGFloat = 0
    private(set) var H: CGFloat = 0
    private var u: CGFloat = 1
    private var oy: CGFloat = 0
    private var m: CGFloat = 10
    private var fonts: [String: NSFont] = [:]
    private var layouts: [String: (lines: [String], size: Int)] = [:]
    private var anim: [String: Double] = [:]
    private var gtiAnim: Double?
    private let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f
    }()

    func setSize(_ w: CGFloat, _ h: CGFloat) {
        if w == W && h == H { return }
        W = w
        H = h
        u = min(W / 320, H / 240)
        oy = ((H - 240 * u) / 2).rounded(.down)
        m = s(10)
        fonts.removeAll()
        layouts.removeAll()
    }

    // ---- primitives --------------------------------------------------------
    func s(_ v: CGFloat) -> CGFloat { (v * u).rounded() }
    func y(_ v: CGFloat) -> CGFloat { oy + s(v) }

    func font(_ kind: Kind, _ size: CGFloat) -> NSFont {
        let px = max(8, s(size))
        let key = "\(kind == .mono ? "m" : "s")\(px)"
        if let f = fonts[key] { return f }
        let f = kind == .mono ? NSFont.monospacedSystemFont(ofSize: px, weight: .bold)
                              : NSFont.systemFont(ofSize: px, weight: .bold)
        fonts[key] = f
        return f
    }

    func measure(_ str: String, _ f: NSFont) -> CGSize {
        (str as NSString).size(withAttributes: [.font: f])
    }

    @discardableResult
    func text(_ str: String, _ f: NSFont, _ color: RGB, _ p: CGPoint, _ a: Anchor = .topLeft) -> CGRect {
        let attrs: [NSAttributedString.Key: Any] = [.font: f, .foregroundColor: color.ns]
        let size = (str as NSString).size(withAttributes: attrs)
        var o = p
        switch a {
        case .topLeft: break
        case .topRight: o.x -= size.width
        case .midLeft: o.y -= size.height / 2
        case .midRight: o.x -= size.width; o.y -= size.height / 2
        case .center: o.x -= size.width / 2; o.y -= size.height / 2
        case .bottomLeft: o.y -= size.height
        }
        o.x = o.x.rounded()
        o.y = o.y.rounded()
        (str as NSString).draw(at: o, withAttributes: attrs)
        return CGRect(origin: o, size: size)
    }

    @discardableResult
    func text(_ str: String, _ kind: Kind, _ size: CGFloat, _ color: RGB, _ p: CGPoint, _ a: Anchor = .topLeft) -> CGRect {
        text(str, font(kind, size), color, p, a)
    }

    func fill(_ c: RGB, _ r: CGRect, _ radius: CGFloat = 0, alpha: CGFloat = 1) {
        guard r.width > 0, r.height > 0 else { return }
        (alpha < 1 ? c.ns.withAlphaComponent(alpha) : c.ns).setFill()
        let rr = min(radius, r.width / 2, r.height / 2)
        (rr > 0 ? NSBezierPath(roundedRect: r, xRadius: rr, yRadius: rr) : NSBezierPath(rect: r)).fill()
    }

    func line(_ c: RGB, _ a: CGPoint, _ b: CGPoint, _ width: CGFloat) {
        let p = NSBezierPath()
        p.move(to: a)
        p.line(to: b)
        p.lineWidth = width
        c.ns.setStroke()
        p.stroke()
    }

    func triangle(_ cx: CGFloat, _ cy: CGFloat, _ size: CGFloat, up: Bool, _ c: RGB) {
        let h = (size / 2).rounded(.down)
        let q = (h / 2).rounded(.down)
        let pts: [CGPoint] = up
            ? [CGPoint(x: cx - h, y: cy + q + 1), CGPoint(x: cx + h, y: cy + q + 1), CGPoint(x: cx, y: cy - q - 1)]
            : [CGPoint(x: cx - h, y: cy - q - 1), CGPoint(x: cx + h, y: cy - q - 1), CGPoint(x: cx, y: cy + q + 1)]
        let p = NSBezierPath()
        p.move(to: pts[0])
        p.line(to: pts[1])
        p.line(to: pts[2])
        p.close()
        c.ns.setFill()
        p.fill()
    }

    func circle(_ c: RGB, _ center: CGPoint, _ radius: CGFloat) {
        c.ns.setFill()
        NSBezierPath(ovalIn: CGRect(x: center.x - radius, y: center.y - radius, width: 2 * radius, height: 2 * radius)).fill()
    }

    func trend(_ cx: CGFloat, _ cy: CGFloat, _ now: Int?, _ prev: Int?, _ size: CGFloat) {
        guard let now = now, let prev = prev else { return }
        let d = now - prev
        if d >= 3 {
            triangle(cx, cy, size, up: true, Palette.up)
        } else if d <= -3 {
            triangle(cx, cy, size, up: false, Palette.down)
        } else {
            let half = (size / 2).rounded(.down)
            line(Palette.dim, CGPoint(x: cx - half + 1, y: cy), CGPoint(x: cx + half - 1, y: cy), max(1, s(2)))
        }
    }

    func progress(_ frac: Double) {
        let h = max(2, s(2))
        fill(Palette.panel, CGRect(x: 0, y: H - h, width: W, height: h))
        fill(Palette.accent, CGRect(x: 0, y: H - h, width: (W * CGFloat(max(0, min(1, frac)))).rounded(.down), height: h))
    }

    /// Fade in from the background colour after a screen change.
    func fade(_ now: Double, from start: Double) {
        let a = 1.0 - (now - start) / TM.fadeSecs
        if a > 0 { fill(Palette.bg, CGRect(x: 0, y: 0, width: W, height: H), alpha: CGFloat(min(1, a))) }
    }

    func lineHeight(_ f: NSFont) -> CGFloat {
        (f.ascender - f.descender + f.leading).rounded(.up)
    }

    func wrapLines(_ str: String, _ f: NSFont, _ maxW: CGFloat) -> [String] {
        var lines: [String] = []
        var cur = ""
        for word in Py.split(str) {
            let trial = cur.isEmpty ? word : cur + " " + word
            if !cur.isEmpty && measure(trial, f).width > maxW {
                lines.append(cur)
                cur = word
            } else {
                cur = trial
            }
        }
        if !cur.isEmpty { lines.append(cur) }
        return lines
    }

    /// A headline in at most 3 lines: the original at the largest size that
    /// fits, else the gentlest condensed version that fits, else a "…" cut.
    func headlineLayout(_ str: String, _ maxW: CGFloat) -> (lines: [String], size: Int) {
        let key = "\(maxW)|\(str)"
        if let hit = layouts[key] { return hit }
        let big = TM.headlineSizes.big, small = TM.headlineSizes.small
        var result: (lines: [String], size: Int)?
        let steps = Text.condenseSteps(str)
        search: for cand in steps.steps {
            for size in stride(from: big, through: small, by: -1) {
                let lines = wrapLines(cand, font(.sans, CGFloat(size)), maxW)
                if lines.count <= TM.headlineMaxLines {
                    result = (lines, size)
                    break search
                }
            }
        }
        if result == nil {
            let f = font(.sans, CGFloat(small))
            let cut = Text.truncateWords({ self.wrapLines($0, f, maxW).count <= TM.headlineMaxLines }, steps.condensed)
            result = (wrapLines(cut, f, maxW), small)
        }
        if layouts.count > 200 { layouts.removeAll() }
        let r: (lines: [String], size: Int) = result ?? (lines: [str], size: small)
        layouts[key] = r
        return r
    }

    // ---- animation of bar lengths only (numbers are always exact) ----------
    func step(_ snap: Snapshot, dt: Double) {
        let k = min(1.0, max(0, dt) * 5)
        for c in TM.cats {
            if let target = snap.slot(c).score.map { Double($0) } {
                let cur = anim[c] ?? target
                anim[c] = cur + (target - cur) * k
            } else {
                anim[c] = nil
            }
        }
        if let target = snap.gti.map { Double($0) } {
            let cur = gtiAnim ?? target
            gtiAnim = cur + (target - cur) * k
        } else {
            gtiAnim = nil
        }
    }

    // ---- screens -------------------------------------------------------------
    func draw(_ snap: Snapshot, view: RotView?, now: Double, fadeFrom: Double) {
        guard let v = view else {
            drawLoading(now)
            return
        }
        if v.screen == "MAIN" {
            drawMain(snap, now: now, frac: v.frac)
        } else {
            drawHeadline(snap, cat: v.screen, index: v.index, now: now, frac: v.frac)
        }
        fade(now, from: fadeFrom)
    }

    func drawLoading(_ now: Double) {
        fill(Palette.bg, CGRect(x: 0, y: 0, width: W, height: H))
        let cy = (H / 2).rounded(.down)
        let cx = (W / 2).rounded(.down)
        text("THREAT MONITOR", .mono, 17, Palette.accent, CGPoint(x: cx, y: cy - s(18)), .center)
        let dots = String(repeating: ".", count: Int(now * 2) % 4)
        let padded = dots + String(repeating: " ", count: 3 - dots.count)
        text("Contacting sources\(padded)", .mono, 11, Palette.muted, CGPoint(x: cx, y: cy + s(8)), .center)
        text("BBC · AL JAZEERA · NPR · GDACS · CISA · WHO", .mono, 9, Palette.dim, CGPoint(x: cx, y: cy + s(26)), .center)
    }

    /// Small preview (System Settings thumbnail): index and level only.
    func drawMini(_ snap: Snapshot) {
        fill(Palette.bg, CGRect(x: 0, y: 0, width: W, height: H))
        let gti = snap.lastSync != nil ? snap.gti : nil
        let lv = Palette.level(gti)
        func f(_ frac: CGFloat) -> NSFont { NSFont.monospacedSystemFont(ofSize: max(8, (H * frac).rounded(.down)), weight: .bold) }
        let cx = (W / 2).rounded(.down)
        text("THREAT MONITOR", f(0.10), Palette.accent, CGPoint(x: cx, y: (H * 0.16).rounded(.down)), .center)
        text(gti.map { String($0) } ?? "--", f(0.42), lv.color, CGPoint(x: cx, y: (H * 0.50).rounded(.down)), .center)
        text(lv.name, f(0.12), lv.color, CGPoint(x: cx, y: (H * 0.82).rounded(.down)), .center)
    }

    func drawMain(_ snap: Snapshot, now: Double, frac: Double) {
        fill(Palette.bg, CGRect(x: 0, y: 0, width: W, height: H))

        // header
        text("THREAT MONITOR", .mono, 11, Palette.accent, CGPoint(x: m, y: y(6)))
        text(clock.string(from: Date(timeIntervalSince1970: now)), .mono, 11, Palette.muted, CGPoint(x: W - m, y: y(6)), .topRight)

        // category rows
        let labW = measure("WAR", font(.mono, 15)).width.rounded()
        let valW = measure("100", font(.mono, 15)).width.rounded()
        let arrow = s(9)
        let x0 = m + labW + s(8)
        let x1 = W - m - arrow - s(7) - valW - s(8)
        let bw = x1 - x0
        let bh = max(4, s(10))
        let half = (bh / 2).rounded(.down)
        let nx = x0 + (bw * CGFloat(TM.normalLevel) / 100).rounded(.down)
        for (i, c) in TM.cats.enumerated() {
            let cy = y(37 + CGFloat(i) * 24)
            let slot = snap.slot(c)
            let val = slot.score
            var col = Palette.level(val).color
            if slot.stale { col = col.mix(Palette.track, 0.55) }
            text(c, .mono, 15, Palette.text, CGPoint(x: m, y: cy), .midLeft)
            fill(Palette.track, CGRect(x: x0, y: cy - half, width: bw, height: bh), half)
            if let shown = anim[c], shown > 0 {
                let fw = (bw * CGFloat(shown) / 100).rounded(.down)
                if fw > 0 { fill(col, CGRect(x: x0, y: cy - half, width: fw, height: bh), min(half, (fw / 2).rounded(.down))) }
            }
            line(Palette.muted, CGPoint(x: nx, y: cy - half - s(3)), CGPoint(x: nx, y: cy + half + s(2)), max(1, s(1)))
            let vx = x1 + s(8) + valW
            if let v = val {
                text(String(v), .mono, 15, slot.stale ? Palette.muted : Palette.text, CGPoint(x: vx, y: cy), .midRight)
                trend(W - m - (arrow / 2).rounded(.down), cy, v, slot.prev, arrow)
            } else {
                text("--", .mono, 15, Palette.err, CGPoint(x: vx, y: cy), .midRight)
            }
        }

        line(Palette.panel, CGPoint(x: m, y: y(128)), CGPoint(x: W - m, y: y(128)), max(1, s(1)))

        // global index
        let gti = snap.gti
        let lv = Palette.level(gti)
        text("GLOBAL THREAT INDEX", .mono, 10, Palette.muted, CGPoint(x: m, y: y(134)))
        if let g = gti, let p = snap.gtiPrev {
            let d = g - p
            let r = text(d != 0 ? String(format: "%+ld since last sync", d) : "no change", .mono, 9, Palette.muted,
                         CGPoint(x: W - m, y: y(135)), .topRight)
            if abs(d) >= 3 { triangle(r.minX - s(7), r.midY.rounded(), s(8), up: d > 0, d > 0 ? Palette.up : Palette.down) }
        }

        let numFont = font(.mono, 38)
        let nr = text(gti.map { String($0) } ?? "--", numFont, gti != nil ? lv.color : Palette.err, CGPoint(x: m - s(2), y: y(146)))
        if gti != nil {
            let pf = font(.mono, 16)
            let baseline = nr.minY + numFont.ascender
            text("%", pf, lv.color, CGPoint(x: nr.maxX + s(1), y: baseline - pf.ascender))
        }

        let badgeFont = font(.mono, 14)
        let bsize = measure(lv.name, badgeFont)
        let bw2 = bsize.width.rounded() + s(14), bh2 = bsize.height.rounded() + s(6)
        let br = CGRect(x: W - m - bw2, y: (nr.midY - s(4) - bh2 / 2).rounded(), width: bw2, height: bh2)
        fill(lv.color, br, s(4))
        text(lv.name, badgeFont, Palette.bg, CGPoint(x: br.midX, y: br.midY), .center)
        text("NORMAL DAY ~\(Int(TM.normalLevel))", .mono, 9, Palette.dim, CGPoint(x: W - m, y: br.maxY + s(4)), .topRight)

        // gauge with level bands and a pointer
        let gy = y(193), gh = max(3, s(4))
        let gx0 = m, gx1 = W - m
        var lo = 0
        for l in Palette.levels {
            let hi = min(l.limit, 100)
            let a = gx0 + ((gx1 - gx0) * CGFloat(lo) / 100).rounded(.down)
            let b = gx0 + ((gx1 - gx0) * CGFloat(hi) / 100).rounded(.down)
            let active = gti.map { lo <= $0 && $0 < l.limit } ?? false
            fill(active ? l.color : l.color.mix(Palette.bg, 0.6), CGRect(x: a + 1, y: gy, width: b - a - 2, height: gh), (gh / 2).rounded(.down))
            lo = l.limit
        }
        if let ga = gtiAnim {
            let px = gx0 + ((gx1 - gx0) * CGFloat(min(ga, 100)) / 100).rounded(.down)
            triangle(px, gy + gh + s(5), s(9), up: true, Palette.text)
        }

        // footer
        let fy = y(219)
        let upd = snap.lastSync.map { clock.string(from: Date(timeIntervalSince1970: $0)) } ?? "--:--"
        text("UPDATED \(upd)", .mono, 10, Palette.muted, CGPoint(x: m, y: fy), .midLeft)
        let right: String
        let rc: RGB
        if snap.syncing {
            right = "SYNCING..."
            rc = Palette.accent
        } else if snap.failStreak > 0 {
            right = "RETRY IN \(mmss(snap.nextSync - now))"
            rc = Palette.warn
        } else {
            right = "NEXT IN \(mmss(snap.nextSync - now))"
            rc = Palette.muted
        }
        text(right, .mono, 10, rc, CGPoint(x: W - m, y: fy), .midRight)
        let cx = (W / 2).rounded(.down)
        if TM.cats.allSatisfy({ snap.slot($0).score == nil }) {
            text("NO DATA YET", .mono, 10, Palette.warn, CGPoint(x: cx, y: fy), .center)
        } else if TM.cats.contains(where: { snap.slot($0).stale || snap.slot($0).score == nil }) {
            text("SOURCE OFFLINE", .mono, 10, Palette.warn, CGPoint(x: cx, y: fy), .center)
        } else if snap.baseline < TM.calibSettled {
            text("LEARNING \(snap.baseline)/\(TM.calibSettled)h", .mono, 10, Palette.dim, CGPoint(x: cx, y: fy), .center)
        }

        progress(frac)
    }

    func drawHeadline(_ snap: Snapshot, cat: String, index: Int, now: Double, frac: Double) {
        fill(Palette.bg, CGRect(x: 0, y: 0, width: W, height: H))
        let slot = snap.slot(cat)
        let val = slot.score
        let lv = Palette.level(val)

        // header band
        let bh = s(30)
        fill(Palette.panel, CGRect(x: 0, y: y(0), width: W, height: bh))
        fill(lv.color, CGRect(x: 0, y: y(0), width: s(4), height: bh))
        let cy = y(15)
        text(TM.catNames[cat] ?? cat, .mono, 15, Palette.text, CGPoint(x: m + s(2), y: cy), .midLeft)
        let r = text(val.map { String($0) } ?? "--", .mono, 15, lv.color, CGPoint(x: W - m, y: cy), .midRight)
        text(lv.name, .mono, 9, lv.color, CGPoint(x: r.minX - s(6), y: cy), .midRight)

        let title: String, meta: String, page: String, colour: RGB
        let hls = slot.headlines
        if hls.isEmpty {
            title = TM.emptyMsg[cat] ?? ""
            meta = ""
            page = ""
            colour = Palette.muted
        } else {
            let i = index % hls.count
            let h = hls[i]
            title = h.title
            meta = "\(h.source) · \(agoText(h.date, now: Date(timeIntervalSince1970: now)))"
            page = "\(i + 1)/\(hls.count)"
            colour = Palette.text
        }

        let top = y(40), bottom = y(196)
        let lay = headlineLayout(title, W - 2 * m)
        let f = font(.sans, CGFloat(lay.size))
        let lh = (lineHeight(f) * 1.02).rounded(.down)
        let ty = top + max(0, ((bottom - top - CGFloat(lay.lines.count) * lh) / 2).rounded(.down))
        for (i, l) in lay.lines.enumerated() {
            text(l, f, colour, CGPoint(x: m, y: ty + CGFloat(i) * lh))
        }

        let my = y(210)
        if !meta.isEmpty { text(meta, .mono, 10, Palette.muted, CGPoint(x: m, y: my), .midLeft) }
        let right = slot.stale ? "CACHED" : page
        if !right.isEmpty {
            text(right, .mono, 10, slot.stale ? Palette.warn : Palette.dim, CGPoint(x: W - m, y: my), .midRight)
        }

        // which screen of the rotation this is
        let n = TM.cats.count + 1
        let cur = (TM.cats.firstIndex(of: cat) ?? 0) + 1
        let dot = s(4), gap = s(9)
        let x = (W / 2).rounded(.down) - (CGFloat(n - 1) * gap / 2).rounded(.down)
        for i in 0..<n {
            circle(i == cur ? Palette.accent : Palette.dim, CGPoint(x: x + CGFloat(i) * gap, y: y(227)), max(2, (dot / 2).rounded(.down)))
        }

        progress(frac)
    }
}
