# 004 — Preserve hover styles inside `with_spring` and add spring pills to Profile Editor tabs

- **Status**: DONE
- **Commit**: 386e879
- **Severity**: MEDIUM
- **Category**: 4. Interruptibility & 7. Cohesion & tokens
- **Estimated scope**: 3 files (`src/ui/render_layout.rs`, `src/ui/workspace_views.rs`, `src/ui/profile_modal.rs`)

## Problem

1. **`with_spring` clobbers `.hover()` background on inactive navigation and subtab pills (`src/ui/render_layout.rs:163-201, 1138-1191, 1206-1242`, `src/ui/workspace_views.rs:1194-1248`)**:
   In `sidebar_nav_item`, `genlogin_subtab_item`, `proxy_subtab_item`, and `sidebar-create-prof-spring`, `.hover(|s| ...)` is declared on the `Div` before `.with_spring(..., |this, phase| this.bg(phase.interpolate_clamped(rgba(0x00000000).into(), BonTheme::accent())))`. Because `SpringAnimationElement` runs its animator closure on every frame, unconditionally calling `this.bg(...)` when `phase == 0.0` sets an explicit transparent background after `.hover()` was configured, and re-attaching `.hover(...)` inside the `with_spring` closure ensures hover feedback is always preserved at rest (`phase <= 0.001` or `phase >= 0.999`).

```rust
// src/ui/render_layout.rs:1206-1212, 1233-1242 — current
        .hover(|s| {
            if active {
                s.bg(rgb(0x2997ff))
            } else {
                s.bg(BonTheme::bg_hover())
            }
        })
        // ...
        .with_spring(
            SharedString::from(format!("nav-spring-{label}")),
            SpringAnimation::new(BonTheme::snappy_spring()).to(active),
            |this, phase| {
                this.bg(phase.interpolate_clamped(
                    Hsla::from(rgba(0x00000000)),
                    BonTheme::accent(),
                ))
            },
        )
```

2. **Profile Editor's 6-tab bar (`src/ui/profile_modal.rs:544-570`) lacks spring pill transitions**:
   While `Local | Groups | Trash` and `My Proxies | Free Proxies` use `BonTheme::snappy_spring()` on their segmented pills, the Profile Editor's 6-tab bar (`Overview | Network | Location | Hardware | Bookmarks | Cookies`) snaps colors abruptly via `Button::with_variant(BonTheme::toggle_pill(...))`.

## Target

1. Move `.hover(...)` inside the `with_spring` animator closure (after `.bg(...)`) on `sidebar_nav_item`, `genlogin_subtab_item`, `proxy_subtab_item`, and `sidebar-create-prof-spring` so hover states layer cleanly over the spring-interpolated resting background.
2. Render the 6 Profile Editor tabs (`src/ui/profile_modal.rs:537-571`) inside a recessed segmented track (`BonTheme::bg_well()`, matching `render_layout.rs:430-457`) with `SpringAnimation::new(BonTheme::snappy_spring()).to(is_active)` on each tab pill.

## Repo conventions to follow

- Follow `genlogin_subtab_item` (`src/ui/render_layout.rs:1124-1192`) and `proxy_subtab_item` (`src/ui/workspace_views.rs:1182-1249`), which use `BonTheme::snappy_spring()` inside a `BonTheme::bg_well()` track.

## Steps

1. In `src/ui/render_layout.rs:163-201`, `1138-1191`, and `1206-1242`, move `.hover(...)` inside the `with_spring` closure after `.bg(...)`.
2. In `src/ui/workspace_views.rs:1194-1248`, move `.hover(...)` inside the `with_spring` closure after `.bg(...)`.
3. In `src/ui/profile_modal.rs:537-571`, replace the `Button::new(format!("prof-tab-{lbl}"))` loop with a spring-animated pill item `editor_tab_item(tab, lbl, active_tab == tab, cx)` using `SpringAnimation::new(BonTheme::snappy_spring()).to(is_active)`.

## Boundaries

- Do NOT change the 6 `ProfileEditorTab` variants or their click handlers.

## Verification

- **Mechanical**: `cargo test --quiet` passes.
- **Feel check**:
  - Hover over inactive sidebar items, subtabs, and Profile Editor tabs: subtle hover highlight (`BonTheme::bg_hover()`) appears reliably; clicking any tab springs the active blue pill smoothly with `BonTheme::snappy_spring()`.
- **Done when**: All segmented/tab bars across Profiles, Proxies, and Profile Editor share the same `BonTheme::snappy_spring()` pill behavior and preserve hover states.
