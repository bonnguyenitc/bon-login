# 001 — Remove high-frequency navigation & row-selection opacity blanking

- **Status**: DONE
- **Commit**: 386e879
- **Severity**: HIGH
- **Category**: 1. Purpose & frequency
- **Estimated scope**: 4 files (`src/ui/render_layout.rs`, `src/ui/workspace_views.rs`, `src/ui/profile_modal.rs`, `src/ui/profile_list.rs`)

## Problem

In an Operate-mode macOS workbench (`DESIGN.md` cites Zed, Linear, and Raycast), top-level workspace switches (`⌘1`/`⌘2`/`⌘3`), subtab switches (`Local` / `Groups` / `Trash`, `My Proxies` / `Free Proxies`), profile editor tab switches (`Overview` / `Network` / `Location` / `Hardware` / `Bookmarks` / `Cookies`), and row selections in the profile roster occur 100+ times per day. Currently, every conditional view branch wraps its root container in `.with_animation(..., BonTheme::ui_enter_anim(), |this, delta| this.opacity(delta))`, which starts at `delta = 0.0` (`opacity: 0.0`) on mount and flashes the entire pane over 140ms.

Worse, `src/ui/profile_list.rs:315, 663-667` keys `detail-drawer-body`'s entrance animation to `format!("detail-seed-{}", prof.seed)`, so clicking from Profile A to Profile B blanks out the entire right-hand Detail Drawer (`Profile name`, `Tags`, `Bookmarks`, `Proxy`, action buttons) to `opacity: 0.0` on every row click:

```rust
// src/ui/profile_list.rs:315, 663-667 — current
let content_anim_id = SharedString::from(format!("detail-seed-{}", prof.seed));
// ...
    .with_animation(
        content_anim_id,
        BonTheme::ui_enter_anim(),
        |this, delta| this.opacity(delta),
    )
```

```rust
// src/ui/render_layout.rs:475-489, 995-1035 — current
render_groups_subtab_view(self, cx)
    .with_animation(
        "subtab-groups-enter",
        BonTheme::ui_enter_anim(),
        |this, delta| this.opacity(delta),
    )
    .into_any_element()
```

```rust
// src/ui/workspace_views.rs:384-388 — current
render_free_proxies_subtab_view(app, cx).with_animation(
    "subtab-free-proxies-enter",
    BonTheme::ui_enter_anim(),
    |this, delta| this.opacity(delta),
)
```

```rust
// src/ui/profile_modal.rs:945-949, 1310-1314, 1439-1443, 1593-1597, 1778-1782, 1793-1797 — current
.with_animation(
    "prof-tab-overview-enter",
    BonTheme::ui_enter_anim(),
    |this, delta| this.opacity(delta),
)
```

## Target

Delete `.with_animation(..., BonTheme::ui_enter_anim(), |this, delta| this.opacity(delta))` from all high-frequency workspace views, subtabs, editor tab panels, and `detail-drawer-body` row selections so switching views/tabs/rows is instant (0ms blanking), while keeping spring pill feedback on the tab controls themselves and targeted highlight feedback when clicking `↻ Refresh` (`randomize_profile_seed`).

```rust
// src/ui/render_layout.rs — target
if sub_tab == ProfileSubTab::Group {
    render_groups_subtab_view(self, cx).into_any_element()
} else if sub_tab == ProfileSubTab::Trash {
    render_trash_table(self, cx).into_any_element()
}
// and for WorkspaceView::Proxies / EditProfile / Extensions:
WorkspaceView::Proxies => render_proxies_view(self, cx).into_any_element(),
WorkspaceView::Extensions => render_extensions_view(self, cx).into_any_element(),
```

## Repo conventions to follow

- High-frequency navigation pill indicators use `SpringAnimation::new(BonTheme::snappy_spring()).to(active)` (`src/ui/render_layout.rs:1182-1191`), while content panes render immediately without opacity blanking.
- Reserve `BonTheme::ui_enter_anim()` for overlays (`popup_modals.rs`) and conditional contextual toolbars (`batch-action-bar-enter`, `pmgr-batch-bar-enter`, `fp-batch-bar-enter`).

## Steps

1. In `src/ui/render_layout.rs:475-489` and `src/ui/render_layout.rs:995-1035`, remove `.with_animation("subtab-groups-enter", ...)`, `.with_animation("subtab-trash-enter", ...)`, `.with_animation("subtab-local-enter", ...)`, `.with_animation("view-proxies-enter", ...)`, `.with_animation("view-edit-profile-enter", ...)`, and `.with_animation("view-extensions-enter", ...)`. Keep `batch-action-bar-enter` (`src/ui/render_layout.rs:984-988`).
2. In `src/ui/workspace_views.rs:384-388`, remove `.with_animation("subtab-free-proxies-enter", BonTheme::ui_enter_anim(), |this, delta| this.opacity(delta))`.
3. In `src/ui/profile_modal.rs:945-949, 1310-1314, 1439-1443, 1593-1597, 1778-1782, 1793-1797`, remove the six `prof-tab-*-enter` `.with_animation` wrappers on the tab content cards.
4. In `src/ui/profile_list.rs:315, 663-667`, remove `content_anim_id` and `.with_animation(content_anim_id, BonTheme::ui_enter_anim(), |this, delta| this.opacity(delta))` from `detail-drawer-body`.

## Boundaries

- Do NOT remove `batch-action-bar-enter`, `pmgr-batch-bar-enter`, or `fp-batch-bar-enter` on the contextual batch action bars.
- Do NOT add new dependencies.

## Verification

- **Mechanical**: `cargo test --quiet` passes with 0 warnings/errors.
- **Feel check**:
  - Press `⌘1`, `⌘2`, `⌘3` rapidly and click across `Local`, `Groups`, `Trash` subtabs: content switches instantaneously with zero opacity flash, while the active pill background springs smoothly.
  - Click across 5 different rows in the Profiles table: the right-hand Detail Drawer updates values immediately without blinking out.
- **Done when**: Switching views, subtabs, editor tabs, or selected profile rows never animates container opacity from `0.0`.
