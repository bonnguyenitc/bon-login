# Animation Improvement Plans (`plans/`)

Plans 001-005 were generated from the Emil Kowalski animation audit at commit `386e879`.
Plan 006 comes from the anti-detection audit at commit `be48bcd` (separate axis: network reputation & behavior, no animation work).

## Summary & Status

| Plan | Title | Severity | Category | Status |
| :---: | :--- | :---: | :--- | :---: |
| [001](001-remove-high-frequency-opacity-fades.md) | Remove high-frequency navigation & row-selection opacity blanking | **HIGH** | 1. Purpose & frequency | `DONE` |
| [002](002-virtualized-keys-and-synced-status-pulse.md) | Key virtualized Free Proxies animations by stable identity and sync status pulses | **HIGH** | 4. Interruptibility & 5. Performance | `DONE` |
| [003](003-interruptible-toast-and-modal-physicality.md) | Make toast banner interruptible and add physical entrance to popup modals | **MEDIUM** | 3. Physicality & 4. Interruptibility | `DONE` |
| [004](004-spring-hover-and-editor-tabs.md) | Preserve hover styles inside `with_spring` and add spring pills to Profile Editor tabs | **MEDIUM** | 4. Interruptibility & 7. Cohesion | `DONE` |
| [005](005-drawer-copy-and-reseed-feedback.md) | Add spatial Detail Drawer entrance, 1-click Copy micro-feedback, and targeted seed-refresh highlight | **LOW** | 8. Missed opportunities | `DONE` |
| [006](006-ip-quality-gate-and-human-behavior.md) | IP quality gate, human behavior engine, and profile trust ramp | **HIGH** | Anti-detection — network & behavior | `DONE` |

## Recommended Execution Order & Dependencies

1. **Plan 001** (`001-remove-high-frequency-opacity-fades.md`) — Independent; removes the full-pane opacity flashes across `render_layout.rs`, `workspace_views.rs`, `profile_modal.rs`, and `profile_list.rs`.
2. **Plan 002** (`002-virtualized-keys-and-synced-status-pulse.md`) — Independent; introduces `BonTheme::status_pulse_anim()` in `theme.rs` and fixes virtualized `uniform_list` animation keys in `workspace_views.rs` and `profile_list.rs`.
3. **Plan 003** (`003-interruptible-toast-and-modal-physicality.md`) — Independent; upgrades toast interruptibility in `render_layout.rs` and popup modal physicality in `popup_modals.rs`.
4. **Plan 004** (`004-spring-hover-and-editor-tabs.md`) — Runs after Plan 001 (touches `render_layout.rs`, `workspace_views.rs`, and `profile_modal.rs`).
5. **Plan 005** (`005-drawer-copy-and-reseed-feedback.md`) — Runs after Plan 001 (replaces the removed full-drawer seed fade in `profile_list.rs` with targeted fingerprint-row highlight and copy micro-feedback).
6. **Plan 006** (`006-ip-quality-gate-and-human-behavior.md`) — Independent of 001-005. Phase 0 touches `launcher.rs`/`models.rs` flags; Phase 1 adds `GeoInfo` fields + `ip_reputation` migration; Phase 2 adds `src/human.rs` and rewires `run_cookie_robot_warmup_in`. Phase 3 (`profile seed`, `audit`) should land before Plan 007 (social matrix job engine), which depends on `Profile::can_publish()` and `human.rs`.
