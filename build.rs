fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(target_os = "macos")]
    {
        use std::path::PathBuf;
        use std::process::Command;

        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
        let src_path = out_dir.join("bon_winbounds.m");
        let dylib_path = out_dir.join("libbon_winbounds.dylib");

        let objc_src = r#"#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#include <stdlib.h>
#include <stdio.h>

static BOOL g_bon_setting_frame = NO;
static int g_bon_cdp_port = 0;
static NSString *g_bon_active_port_path = nil;

static void bon_noop_setMinSize(id self, SEL _cmd, NSSize s) {
    (void)self; (void)_cmd; (void)s;
}

static NSSize bon_small_minSize(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return NSMakeSize(200.0, 180.0);
}

static IMP g_orig_constrain = NULL;
static NSRect bon_constrainFrame(id self, SEL _cmd, NSRect frameRect, NSScreen *screen) {
    if (g_bon_setting_frame) {
        return frameRect;
    }
    if (g_orig_constrain) {
        return ((NSRect (*)(id, SEL, NSRect, NSScreen *))g_orig_constrain)(self, _cmd, frameRect, screen);
    }
    return frameRect;
}

static void bon_swizzle_window_class(Class cls) {
    if (!cls) return;
    class_replaceMethod(cls, @selector(setMinSize:), (IMP)bon_noop_setMinSize, "v@:{CGSize=dd}");
    class_replaceMethod(cls, @selector(setContentMinSize:), (IMP)bon_noop_setMinSize, "v@:{CGSize=dd}");
    class_replaceMethod(cls, @selector(minSize), (IMP)bon_small_minSize, "{CGSize=dd}@:");
    class_replaceMethod(cls, @selector(contentMinSize), (IMP)bon_small_minSize, "{CGSize=dd}@:");
}

static int bon_resolve_cdp_port(void) {
    if (g_bon_cdp_port > 0) return g_bon_cdp_port;
    if (!g_bon_active_port_path) return 0;
    NSString *contents = [NSString stringWithContentsOfFile:g_bon_active_port_path
                                                   encoding:NSUTF8StringEncoding
                                                      error:nil];
    if (!contents) return 0;
    int port = atoi([contents UTF8String]);
    if (port > 0) g_bon_cdp_port = port;
    return g_bon_cdp_port;
}

__attribute__((constructor))
static void bon_winbounds_init(void) {
    @autoreleasepool {
        NSArray<NSString *> *args = [[NSProcessInfo processInfo] arguments];
        for (NSString *arg in args) {
            if ([arg hasPrefix:@"--type="]) {
                return;
            }
        }
        // Strip DYLD_INSERT_LIBRARIES immediately so Renderer/GPU/Utility helpers never load this shim.
        unsetenv("DYLD_INSERT_LIBRARIES");

        for (NSString *arg in args) {
            if ([arg hasPrefix:@"--user-data-dir="]) {
                NSString *dir = [arg substringFromIndex:16];
                g_bon_active_port_path = [[dir stringByAppendingPathComponent:@"DevToolsActivePort"] copy];
                break;
            }
        }

        Method m = class_getInstanceMethod([NSWindow class], @selector(constrainFrameRect:toScreen:));
        if (m && !g_orig_constrain) {
            g_orig_constrain = method_setImplementation(m, (IMP)bon_constrainFrame);
        }
        bon_swizzle_window_class([NSWindow class]);

        [[NSDistributedNotificationCenter defaultCenter]
            addObserverForName:@"com.bonlogin.winbounds"
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            NSString *spec = [note object];
            if (![spec isKindOfClass:[NSString class]]) return;
            int targetPort = 0, raise = 0;
            double x = 0, y = 0, w = 0, h = 0;
            if (sscanf([spec UTF8String], "%d,%lf,%lf,%lf,%lf,%d", &targetPort, &x, &y, &w, &h, &raise) != 6) {
                return;
            }
            int myPort = bon_resolve_cdp_port();
            if (myPort <= 0 || myPort != targetPort) return;

            Class nw = NSClassFromString(@"NativeWidgetMacNSWindow");
            if (nw) bon_swizzle_window_class(nw);

            NSUInteger reqMask = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable;
            NSMutableArray<NSWindow *> *browserWins = [NSMutableArray array];
            for (NSWindow *win in [NSApp orderedWindows]) {
                if ([win parentWindow] != nil) continue;
                if (([win styleMask] & reqMask) != reqMask) continue;
                if ([win isVisible] || [win isMiniaturized]) {
                    [browserWins addObject:win];
                }
            }
            if ([browserWins count] == 0) {
                for (NSWindow *win in [NSApp windows]) {
                    if ([win parentWindow] == nil && (([win styleMask] & reqMask) == reqMask)) {
                        [browserWins addObject:win];
                        break;
                    }
                }
            }
            if ([browserWins count] == 0) return;

            NSScreen *primary = [[NSScreen screens] firstObject];
            double primaryH = primary ? primary.frame.size.height : 982.0;
            BOOL hasRect = (w >= 200.0 && h >= 180.0);
            NSRect targetRect = NSMakeRect(x, primaryH - (y + h), w, h);

            for (NSWindow *targetWin in browserWins) {
                if ([targetWin isMiniaturized]) {
                    [targetWin deminiaturize:nil];
                }
                [targetWin setMinSize:NSMakeSize(200.0, 180.0)];
                [targetWin setContentMinSize:NSMakeSize(200.0, 180.0)];
                if (hasRect && ([targetWin styleMask] & NSWindowStyleMaskFullScreen) == 0) {
                    g_bon_setting_frame = YES;
                    [targetWin setFrame:targetRect display:YES animate:NO];
                    g_bon_setting_frame = NO;
                }
            }
            if (raise) {
                NSWindow *frontWin = [browserWins firstObject];
                [NSApp activateIgnoringOtherApps:YES];
                [frontWin orderFrontRegardless];
            }
        }];
    }
}
"#;

        std::fs::write(&src_path, objc_src).expect("write bon_winbounds.m");
        let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
            Ok("x86_64") => "x86_64",
            _ => "arm64",
        };
        let status = Command::new("/usr/bin/clang")
            .args([
                "-dynamiclib",
                "-O2",
                "-arch",
                arch,
                "-mmacosx-version-min=13.0",
                "-framework",
                "Cocoa",
                src_path.to_str().unwrap(),
                "-o",
                dylib_path.to_str().unwrap(),
            ])
            .status()
            .expect("invoke clang for libbon_winbounds.dylib");
        assert!(status.success(), "clang failed building libbon_winbounds.dylib");
    }
}
