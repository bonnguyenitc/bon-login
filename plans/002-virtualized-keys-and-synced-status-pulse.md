# 002 — Key virtualized Free Proxies animations by stable identity and sync status pulses

- **Status**: DONE
- **Commit**: 386e879
- **Severity**: HIGH
- **Category**: 4. Interruptibility & 5. Performance & 7. Cohesion
- **Estimated scope**: 3 files (`src/ui/theme.rs`, `src/ui/profile_list.rs`, `src/ui/workspace_views.rs`)

## Problem

1. **Virtualized slot state collision (`HIGH`)**: In `src/ui/workspace_views.rs:1784-1792` and `1911-1914`, inside `uniform_list("free-proxies-table-rows", ...)`, the row checkbox spring ID is `format!("fp-row-chk-{row_num}")` and the status pulse ID is `format!("fp-chk-pulse-{row_num}")`, where `row_num = row_ix + 1` is the viewport/page index rather than the proxy's identity `key_chk`. When scrolling, filtering, or paginating while any proxy is checked or verifying, recycled row slots inherit the previous item's `SpringElementState` and misfire checkbox/pulse animations:

```rust
// src/ui/workspace_views.rs:1784-1792 — current
.child(BonTheme::checkbox(
    format!("fp-row-chk-{row_num}"),
    is_checked,
    if is_checked { SfSymbol::CHECKMARK } else { "" },
    BonTheme::bg_elevated(),
    cx.listener(move |app, _, _, cx| {
        app.toggle_free_proxy_checked(&key_chk, cx);
    }),
))
```

2. **Unsynchronized 120fps status pulses (`MEDIUM`)**: Status pulses across `src/ui/profile_list.rs:1333-1339` (`1400ms`, `0.48..1.0`), `src/ui/workspace_views.rs:967-979` (`1100ms`, `0.4..1.0`), and `src/ui/workspace_views.rs:1911-1923` (`1100ms`, `0.4..1.0`) use hand-typed inline `Animation::new(...).repeat()` instead of a shared token with GPUI's `Animation::repeat_synced()` and `Animation::with_max_fps(30.0)`. When batch-checking 24 proxies or launching multiple profiles, rows pulse out of phase and trigger 120fps full-window layout/paint passes.

## Target

1. Add `BonTheme::status_pulse_anim()` in `src/ui/theme.rs` using `.repeat_synced()`, `pulsating_between(0.45, 1.0)`, `Duration::from_millis(1200)`, and `.with_max_fps(30.0)`.
2. Key Free Proxy row checkboxes (`format!("fp-row-chk-spring-{key_chk_id}")`) and status pulses (`format!("fp-chk-pulse-{key_pulse_id}")`) by the proxy's stable endpoint key, and replace all three inline pulse animations with `BonTheme::status_pulse_anim()`.

```rust
// src/ui/theme.rs — target
/// Phase-locked 30fps breathing pulse (`1200ms`, alpha `0.45..1.0`) for Starting/Checking badges
pub fn status_pulse_anim() -> Animation {
    Animation::new(Duration::from_millis(1200))
        .repeat_synced()
        .with_max_fps(30.0)
        .with_easing(pulsating_between(0.45, 1.0))
}
```

## Repo conventions to follow

- Animation tokens live in `BonTheme` (`src/ui/theme.rs:40-47`).
- Virtualized table row animations must be keyed by stable entity ID, matching `src/ui/profile_list.rs:1061` (`format!("prof-chk-spring-{profile_id}")`) and `src/ui/workspace_views.rs:835` (`format!("pmgr-row-chk-spring-{pid}")`).

## Steps

1. In `src/ui/theme.rs`, add `BonTheme::status_pulse_anim()` right below `BonTheme::ui_enter_anim()`.
2. In `src/ui/profile_list.rs:1333-1339`, replace the inline `Animation::new(Duration::from_millis(1400)).repeat().with_easing(pulsating_between(0.48, 1.0))` with `BonTheme::status_pulse_anim()`.
3. In `src/ui/workspace_views.rs:967-979`, replace the inline `Animation::new(Duration::from_millis(1100)).repeat().with_easing(pulsating_between(0.4, 1.0))` with `BonTheme::status_pulse_anim()`.
4. In `src/ui/workspace_views.rs:1784-1792` and `1911-1923`, key the Free Proxy row checkbox by `format!("fp-row-chk-spring-{key_chk_id}")` and the pulse by `format!("fp-chk-pulse-{key_pulse_id}")` with `BonTheme::status_pulse_anim()`.

## Boundaries

- Do NOT alter proxy verification or profile launching business logic.

## Verification

- **Mechanical**: `cargo test --quiet` passes.
- **Feel check**:
  - In `Proxies -> Free Proxies`, check row 1, then scroll or filter the table: unchecked rows entering slot 1 never flash or spring from blue to gray.
  - Click `Scan Live (24)` in Free Proxies or batch-check multiple proxies: all `Checking...` badges breathe in unison (`repeat_synced`) at 30fps.
- **Done when**: All virtualized row animations use stable entity keys and all status pulses share `BonTheme::status_pulse_anim()`.
