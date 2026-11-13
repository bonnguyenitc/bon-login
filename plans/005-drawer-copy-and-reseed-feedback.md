# 005 — Add spatial Detail Drawer entrance, 1-click Copy micro-feedback, and targeted seed-refresh highlight

- **Status**: DONE
- **Commit**: 386e879
- **Severity**: LOW
- **Category**: 8. Missed opportunities
- **Estimated scope**: 4 files (`src/ui/mod.rs`, `src/ui/actions.rs`, `src/ui/profile_list.rs`, `src/ui/profile_modal.rs`)

## Problem

1. **Detail Drawer (`src/ui/profile_list.rs:303-326, 669-673`) lacks spatial entrance**:
   Toggling `show_detail_drawer` (`⌘B` or clicking `✕` / `Show Detail Panel`) fades `detail-drawer-panel` opacity in place without any horizontal slide, so the right-hand panel doesn't communicate that it enters from the right edge of the workspace.
2. **1-Click Copy badges (`src/ui/profile_list.rs:472-483, 1084-1102, 1207-1231`) lack local confirmation at the cursor**:
   Clicking a profile row's `ID`, `2FA` badge, or `drawer-copy-totp` fires a bottom-right toast far from the cursor, but the clicked element itself never changes icon or color to confirm the copy at the point of interaction.
3. **`↻ Refresh` Fingerprint (`src/ui/profile_list.rs:369-376`, `src/ui/profile_modal.rs:716-738`) lacks targeted row highlight**:
   After removing the full-drawer opacity blanking in Plan `001`, clicking `↻ Refresh` (`randomize_profile_seed`) needs a targeted highlight pulse on the seed-derived rows (`Browser version`, `OS`, `CPU / RAM`, `WebGL`) so the operator sees which fingerprint parameters were regenerated while identity rows (`Profile name`, `Tags`, `Bookmarks`) stay completely still.

## Target

1. **Bidirectional Spatial Detail Drawer Spring (`src/ui/profile_list.rs:331-342, 698-706`)**:
   Keep the Detail Drawer's outer clip wrapper mounted when `selected_profile.is_some()` and drive its width (`px(0.) <-> px(285.)`), left margin (`px(0.) <-> px(16.)`), and opacity (`0.0 <-> 1.0`) with `SpringAnimation::new(BonTheme::snappy_spring()).to(show_detail_drawer)` so both opening and closing (`⌘B` / `✕`) animate smoothly and can be interrupted mid-flight.
2. **Local Copy Micro-Feedback (`src/ui/mod.rs`, `src/ui/actions.rs`, `src/ui/profile_list.rs`)**:
   Track `recently_copied_key: Option<String>` on `BonLoginApp` (cleared automatically after `750ms`). When the user clicks a row's `ID` (`id:{profile_id}`) or `2FA` (`totp:{profile_id}`), render a crisp `SfSymbol::CHECKMARK` in `BonTheme::success()` directly on the clicked badge/cell for `750ms`.
3. **Targeted Seed-Refresh Highlight (`src/ui/mod.rs`, `src/ui/actions.rs`, `src/ui/profile_list.rs`)**:
   Track `reseed_flash_seed: Option<u32>` on `BonLoginApp` when `randomize_profile_seed` is triggered. In the Detail Drawer, wrap only the seed-derived fingerprint rows (`Browser version`, `OS`, `CPU / RAM`, `WebGL`) in a `with_animation(format!("reseed-row-{label}-{seed}"), BonTheme::ui_enter_anim(), ...)` that interpolates row background from `BonTheme::accent_subtle()` back to transparent when `reseed_flash_seed == Some(prof.seed)`.

## Repo conventions to follow

- Use `BonTheme::ui_enter_anim()` (`140ms`, `ease_out_quint()`) and `SpringTarget::interpolate_clamped`.
- Auto-clearing UI feedback timers use `cx.spawn(async move |this, cx| { cx.background_executor().timer(...).await; ... }).detach()` (`src/ui/render_layout.rs:10-22`).

## Steps

1. In `src/ui/mod.rs`, add `pub recently_copied_key: Option<String>` and `pub reseed_flash_seed: Option<u32>` to `BonLoginApp` (initialized to `None`).
2. In `src/ui/actions.rs`, add helper `flash_copied_key(&mut self, key: String, cx: &mut Context<Self>)` (750ms timer) and call it in `copy_profile_id` (`format!("id:{profile_id}")`) and `copy_profile_totp` (`format!("totp:{profile_id}")`); in `randomize_profile_seed`, set `self.reseed_flash_seed = Some(p.seed)`.
3. In `src/ui/profile_list.rs`, update `detail-drawer-panel` to `.with_animation("detail-drawer-panel", BonTheme::ui_enter_anim(), |this, delta| this.opacity(delta).ml(px((1.0 - delta) * 10.0)))`, render `SfSymbol::CHECKMARK` + `BonTheme::success()` when `recently_copied_key` matches `id:{profile_id}` or `totp:{profile_id}`, and highlight seed-derived rows when `reseed_flash_seed == Some(prof.seed)`.

## Boundaries

- Do NOT animate `Profile name`, `Tags`, `Bookmarks`, or `Proxy` rows when `randomize_profile_seed` is clicked.

## Verification

- **Mechanical**: `cargo test --quiet` passes.
- **Feel check**:
  - Press `⌘B` twice to close and reopen the Detail Drawer: it slides in subtly over `10px` from the right with `ease_out_quint`.
  - Click a profile's `ID` or `2FA` badge in the table or Detail Drawer: the badge turns emerald with a checkmark (`✓`) for `750ms` right under the cursor.
  - Click `↻ Refresh` in the Detail Drawer: only the fingerprint rows (`Browser version`, `OS`, `CPU / RAM`, `WebGL`) flash a subtle accent highlight while identity rows remain steady.
- **Done when**: All three additive micro-interactions work cleanly and pass `cargo test`.
