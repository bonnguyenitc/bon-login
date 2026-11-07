---
version: 1
slug: "src-ui-mod-rs"
primary_target: "src/ui/mod.rs"
related_targets: ["src/ui/profile_list.rs","src/ui/profile_modal.rs","src/ui/theme.rs"]
---

# Surface Brief — BonLogin Main Workspace (`src/ui/mod.rs`)

- **Mode:** Operate
- **Scope:** Primary macOS desktop workspace (`src/ui/mod.rs`, `src/ui/profile_list.rs`, `src/ui/profile_modal.rs`, `src/ui/theme.rs`)
- **Seed:** `seed: none (unavailable)` — user explicitly pinned **Dark Precision (Zed / Linear / Raycast)** + **Split Master–Inspector** with 1-button compact rows.

## Direction contract

- **THESIS:** An operator's identity fleet should behave like a high-frequency instrument panel (Zed / Linear), never a vertically stacked form page that jumps when a drawer opens or buries rows under eight competing buttons.
- **OWN-WORLD:** Deep obsidian-zinc canvas (`#090A0F`), recessed graphite panels (`#0F1117`), elevated inspector cards (`#161922`), crisp `1px` hairline dividers (`#212634`), cool-tinted slate secondary text (`#8E96AA`), and strict semantic status tokens (`#10B981` Running Emerald, `#F59E0B` Starting Amber, `#EF4444` Fail-Closed Crimson, `#6366F1` Inspector Selection Indigo).
- **STORY:** The operator scans all profiles on the left, filters by group or keyword, launches/stops any profile with a single primary button on the row, and clicks any row to inspect, edit fingerprint parameters, run `agent-browser` commands, or transfer Cookies/State in the fixed right-hand Inspector.
- **FIRST VIEWPORT:** A single unified 1360x840 macOS window split into: (1) a compact 44px Top Command Bar (App identity, Kernel status pill, Fleet telemetry, Bulk actions, `+ New Profile`), (2) a flexible Left Master Pane containing the Search + Group Filter bar and the 4-column Profile Roster (`Identity`, `Fingerprint Spec`, `Proxy & GeoIP`, `Status + Launch/Stop`), and (3) a fixed 460px Right Inspector Pane with 3 segmented tabs (`Overview & Agent`, `Fingerprint & Proxy`, `Cookies & State`).
- **FORM:** Split Master–Detail Desktop Workbench (Zed/Linear/Raycast paradigm) replacing the stacked modal/drawer layout.
- **SIGNATURE:** Selecting any row in the Master Roster immediately binds the 3-tab Right Inspector to that profile—allowing live 1-click switching between `agent-browser` DOM snapshots/fingerprint audits, C++ spoofing toggles (`Canvas`, `Audio`, `Font`, `Rects`, `GPU`), and Cookie JSON import/export with zero vertical layout shift.
