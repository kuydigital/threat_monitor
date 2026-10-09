// THREAT MONITOR for macOS - checks the finished screensaver
// Created and maintained by Oliver Kuy - https://github.com/kuydigital/threat_monitor
//
// Loads "Threat Monitor.saver" the way macOS does (bundle -> principal class
// -> initWithFrame:isPreview:), lets it download live data, and saves a
// picture of every screen, at several screen sizes, in OUTPUT_FOLDER.
//
//   saver-check "Threat Monitor.saver" OUTPUT_FOLDER [--no-live]

#import <AppKit/AppKit.h>
#import <ScreenSaver/ScreenSaver.h>

static int failures = 0;

static void check(BOOL ok, NSString *what) {
    printf("%s %s\n", ok ? "PASS" : "FAIL", what.UTF8String);
    if (!ok) failures++;
}

static BOOL savePNG(NSView *view, NSString *path) {
    NSBitmapImageRep *rep = [view bitmapImageRepForCachingDisplayInRect:view.bounds];
    if (rep == nil) return NO;
    [view cacheDisplayInRect:view.bounds toBitmapImageRep:rep];
    NSData *png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    return [png writeToFile:path atomically:YES];
}

static NSDictionary *status(ScreenSaverView *view) {
    NSString *json = [view valueForKey:@"tmStatus"];
    NSData *data = [json dataUsingEncoding:NSUTF8StringEncoding];
    id obj = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
    return [obj isKindOfClass:[NSDictionary class]] ? obj : @{};
}

static NSArray<NSString *> *screens(void) {
    return @[@"MAIN", @"WAR", @"DIS", @"CYB", @"BIO", @"LOADING", @"MINI"];
}

static void renderAll(ScreenSaverView *view, NSString *dir, NSString *prefix) {
    for (NSString *s in screens()) {
        [view setValue:s forKey:@"tmForcedScreen"];
        NSString *path = [dir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@_%@.png", prefix, s.lowercaseString]];
        check(savePNG(view, path), [NSString stringWithFormat:@"draws %@ %@ (%.0fx%.0f)", prefix, s,
                                    view.bounds.size.width, view.bounds.size.height]);
    }
    [view setValue:@"" forKey:@"tmForcedScreen"];
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        setvbuf(stdout, NULL, _IOLBF, 0);
        if (argc < 3) {
            printf("usage: saver-check \"Threat Monitor.saver\" OUTPUT_FOLDER [--no-live]\n");
            return 2;
        }
        BOOL live = !(argc > 3 && strcmp(argv[3], "--no-live") == 0);
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
        NSString *saverPath = @(argv[1]);
        NSString *out = @(argv[2]);
        [[NSFileManager defaultManager] createDirectoryAtPath:out withIntermediateDirectories:YES attributes:nil error:nil];

        // 1. the bundle loads like macOS loads it
        NSBundle *bundle = [NSBundle bundleWithPath:saverPath];
        NSError *error = nil;
        BOOL loaded = bundle != nil && [bundle loadAndReturnError:&error];
        check(loaded, [NSString stringWithFormat:@"bundle loads %@", error ? error.localizedDescription : @""]);
        if (!loaded) return 1;
        printf("     %s version %s, minimum macOS %s\n",
               [bundle.bundleIdentifier UTF8String],
               [[bundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"] UTF8String],
               [[bundle objectForInfoDictionaryKey:@"LSMinimumSystemVersion"] UTF8String]);
        Class cls = bundle.principalClass;
        check(cls != Nil && [cls isSubclassOfClass:[ScreenSaverView class]],
              [NSString stringWithFormat:@"principal class %@ is a ScreenSaverView", cls ? NSStringFromClass(cls) : @"(none)"]);
        if (cls == Nil || ![cls isSubclassOfClass:[ScreenSaverView class]]) return 1;
        check([bundle pathForResource:@"thumbnail" ofType:@"png"] != nil &&
              [bundle pathForResource:@"thumbnail@2x" ofType:@"png"] != nil, @"thumbnails present");

        ScreenSaverView *view = [[cls alloc] initWithFrame:NSMakeRect(0, 0, 1440, 900) isPreview:NO];
        check(view != nil, @"creates a full-screen view");
        if (view == nil) return 1;
        check(!view.hasConfigureSheet, @"no options sheet");
        printf("     animation interval %.3f s\n", view.animationTimeInterval);

        // 2. live data, fetched by the screensaver itself
        if (live) {
            [view startAnimation];
            NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:120];
            NSDictionary *st = nil;
            NSString *first = [out stringByAppendingPathComponent:@"live_first_frame.png"];
            [view animateOneFrame];
            check(savePNG(view, first), @"first frame (before any data)");
            while ([deadline timeIntervalSinceNow] > 0) {
                [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:1.0]];
                [view animateOneFrame];
                st = status(view);
                if ([st[@"attempts"] intValue] > 0 && ![st[@"syncing"] boolValue]) break;
            }
            NSData *pretty = [NSJSONSerialization dataWithJSONObject:st ?: @{} options:NSJSONWritingPrettyPrinted error:nil];
            printf("live status:\n%s\n", [[NSString alloc] initWithData:pretty encoding:NSUTF8StringEncoding].UTF8String);
            check([st[@"attempts"] intValue] > 0, @"a live update finished within 2 minutes");
            int scored = 0;
            NSDictionary *cats = st[@"cats"];
            for (NSString *c in @[@"WAR", @"DIS", @"CYB", @"BIO"]) {
                if ([cats[c][@"score"] isKindOfClass:[NSNumber class]]) scored++;
            }
            check(scored >= 3, [NSString stringWithFormat:@"live scores for %d of 4 categories", scored]);
            check([st[@"gti"] isKindOfClass:[NSNumber class]], @"live Global Threat Index");
            NSString *dataDir = st[@"dataDir"];
            NSString *stateFile = [dataDir stringByAppendingPathComponent:@"threat_state.json"];
            NSString *calFile = [dataDir stringByAppendingPathComponent:@"threat_calibration.json"];
            check([[NSFileManager defaultManager] fileExistsAtPath:stateFile], @"saved the values for an instant start");
            check([[NSFileManager defaultManager] fileExistsAtPath:calFile], @"saved the calibration");
            // the normal rotation, as it would appear on screen
            for (int i = 0; i < 3; i++) {
                [view animateOneFrame];
                [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];
            }
            check(savePNG(view, [out stringByAppendingPathComponent:@"live_rotation.png"]), @"draws the rotation");
            renderAll(view, out, @"live");
            [view stopAnimation];
            NSString *log = [NSString stringWithContentsOfFile:[dataDir stringByAppendingPathComponent:@"screensaver.log"]
                                                      encoding:NSUTF8StringEncoding error:nil];
            printf("screensaver.log:\n%s\n", (log ?: @"(none)").UTF8String);
        }

        // 3. sample data at different screen sizes
        [view setValue:@YES forKey:@"tmDemo"];
        renderAll(view, out, @"demo");
        NSArray *sizes = @[@[@1920, @1080], @[@1024, @768], @[@3440, @1440], @[@2560, @1664], @[@800, @1280]];
        for (NSArray *wh in sizes) {
            CGFloat w = [wh[0] doubleValue], h = [wh[1] doubleValue];
            ScreenSaverView *v = [[cls alloc] initWithFrame:NSMakeRect(0, 0, w, h) isPreview:NO];
            [v setValue:@"MAIN" forKey:@"tmForcedScreen"];
            NSString *name = [NSString stringWithFormat:@"size_%.0fx%.0f_main.png", w, h];
            check(savePNG(v, [out stringByAppendingPathComponent:name]), [NSString stringWithFormat:@"draws %@", name]);
            [v setValue:@"" forKey:@"tmForcedScreen"];
            name = [NSString stringWithFormat:@"size_%.0fx%.0f_drifting.png", w, h];
            check(savePNG(v, [out stringByAppendingPathComponent:name]), [NSString stringWithFormat:@"draws %@", name]);
        }

        // 4. the small preview in System Settings
        for (NSArray *wh in @[@[@296, @184], @[@480, @300]]) {
            CGFloat w = [wh[0] doubleValue], h = [wh[1] doubleValue];
            ScreenSaverView *p = [[cls alloc] initWithFrame:NSMakeRect(0, 0, w, h) isPreview:YES];
            check(p != nil && p.isPreview, @"creates a preview view");
            NSString *name = [NSString stringWithFormat:@"preview_%.0fx%.0f.png", w, h];
            check(savePNG(p, [out stringByAppendingPathComponent:name]), [NSString stringWithFormat:@"draws %@", name]);
        }

        // 5. speed: a frame should take a few milliseconds at most
        ScreenSaverView *big = [[cls alloc] initWithFrame:NSMakeRect(0, 0, 2560, 1440) isPreview:NO];
        for (NSString *s in @[@"MAIN", @"BIO"]) {
            [big setValue:s forKey:@"tmForcedScreen"];
            NSBitmapImageRep *rep = [big bitmapImageRepForCachingDisplayInRect:big.bounds];
            [big cacheDisplayInRect:big.bounds toBitmapImageRep:rep];      // warm up (fonts, layout)
            NSDate *t0 = [NSDate date];
            for (int i = 0; i < 30; i++) [big cacheDisplayInRect:big.bounds toBitmapImageRep:rep];
            double ms = -[t0 timeIntervalSinceNow] * 1000 / 30;
            check(ms < 100, [NSString stringWithFormat:@"%@ frame at 2560x1440 takes %.1f ms", s, ms]);
        }

        printf("\n%s\n", failures == 0 ? "All screensaver checks passed." : [NSString stringWithFormat:@"%d check(s) failed.", failures].UTF8String);
        return failures == 0 ? 0 : 1;
    }
}
