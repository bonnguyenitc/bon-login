# BonLogin Design System (`DESIGN.md`)

## 1. Visual World & Philosophy — Dark Precision

BonLogin is an **Operate-mode** macOS desktop workbench built in 100% Pure Rust (`gpui-kit = "0.9.0"`). Its design language draws from high-frequency developer and operator instruments (**Zed**, **Linear**, **Raycast**):

- **Zero Layout Shift:** Editing a profile, inspecting live telemetry, or running `agent-browser` automation never pushes, squashes, or overlays the main profile roster.
- **One Row, One Primary Action:** Each roster row displays identity metadata, fingerprint spec, network/GeoIP state, and a single primary button (`Launch` or `Stop`). All secondary operations (`Check Proxy`, `Clone`, `Wipe Cache`, `Delete`, `Snapshot`, `Audit Live Fingerprint`, `Export/Import Cookies`) live inside the persistent Right Inspector.
- **Restrained Semantic Color:** Surfaces stay strictly in deep obsidian-graphite neutrals with cool-tinted slate typography; saturated color is reserved exclusively for live operational state (`Running Emerald`, `Starting Amber`, `Fail-Closed Crimson`, `Active Selection Indigo`).

---

## 2. Color Tokens (`src/ui/theme.rs` — `BonTheme`)

| Token | Hex / Value | Role |
|---|---|---|
| `BonTheme::bg_canvas()` | `#1C1C1E` | macOS `systemBackground` Dark Mode window canvas |
| `BonTheme::bg_sidebar()` | `rgba(22, 22, 25, 0.84)` | Translucent vibrancy left navigation sidebar |
| `BonTheme::bg_panel()` | `#242427` | `secondarySystemGroupedBackground` for tables & Detail Drawer |
| `BonTheme::bg_elevated()` | `#2C2C30` | `tertiarySystemBackground` for table headers, cards & controls |
| `BonTheme::bg_selected()` | `rgba(10, 132, 255, 0.28)` | Active selected / checked row surface |
| `BonTheme::bg_hover()` | `rgba(255, 255, 255, 0.05)` | Subtle row & control hover highlight |
| `BonTheme::bg_well()` | `#151517` | Recessed segmented control track & monospace code well |
| `BonTheme::border()` | `rgba(255, 255, 255, 0.09)` | `1px` specular hairline divider |
| `BonTheme::border_control()` | `rgba(255, 255, 255, 0.22)` | Checkbox and control bezel border |
| `BonTheme::border_active()` | `rgba(10, 132, 255, 0.65)` | Active focus & modal card highlight border |
| `BonTheme::text_primary()` | `#F5F5F7` | Primary high-contrast body and heading ink |
| `BonTheme::text_secondary()` | `#AEAEB2` | `systemGray2` secondary copy and form labels |
| `BonTheme::text_muted()` | `#8E8E93` | `systemGray` WCAG AA caption, IDs (`bon_<id8>`), and column headers |
| `BonTheme::accent()` | `#0A84FF` | Apple System Blue for active tabs, checkboxes, and primary CTAs |
| `BonTheme::success()` | `#30D158` | Apple System Green for Ready/Live proxy status & copy confirmation |
| `BonTheme::info()` | `#64D2FF` | Apple System Cyan for Running browser sessions & active checks |
| `BonTheme::warning()` | `#FF9F0A` | Apple System Orange for Starting tunnel / Engine missing |
| `BonTheme::danger()` | `#FF453A` | Apple System Red for Fail-Closed proxy block & Stop session trigger |
---

## 3. Spatial Architecture & Topology (`src/ui/mod.rs`)

```text
+--------------------------------------------------------------------------------------------------+
| Top Command Bar: BonLogin | [● Kernel 148] | [2/2 Profiles • 0 Running]   [Check] [Launch] [+New]|
+------------------------------------------------------------+-------------------------------------+
| Left Master Pane (Flex 1)                                  | Right Inspector Pane (Fixed 470px)  |
| +--------------------------------------------------------+ | +---------------------------------+ |
| | [Search Input (300px)]  [All] [Personal] [Marketing]   | | | ● Profile Name [Group]   Idle   | |
| +--------------------------------------------------------+ | | [Launch] [Check Proxy] [Clone]  | |
| | Profile       | Fingerprint Spec | Proxy/Geo | State | | | | [Overview & Agent][FP][Cookies] | |
| |---------------+------------------+-----------+-------+ | | +---------------------------------+ |
| | ● macOS Direct| macOS•Chrome•8C  | Direct    | Idle  | | | | Tab 1: Overview & Agent Runner  | |
| |   bon_f26c33a7| Canvas•Audio•GPU | System    | [Lnch]| | | | - Identity & Spoof Spec Sheet   | |
| |---------------+------------------+-----------+-------+ | | | - Live CDP / WS Endpoint Card   | |
| |   Win11 Demo  | Win•Chrome•8C    | Direct    | Idle  | | | | - Built-in agent-browser Runner | |
| |   bon_ff4544d3| Canvas•Audio•Seed| Unchecked | [Lnch]| | | |   [Snapshot] [Audit FP] [Shot]  | |
| +--------------------------------------------------------+ | +---------------------------------+ |
+------------------------------------------------------------+-------------------------------------+
```

### Inspector Tabs (`src/ui/profile_modal.rs`)
1. **`Overview & Agent` (`InspectorTab::OverviewAgent`):**
   - **Spec Sheet:** Displays `bon_<id8>`, `--fingerprint=<seed>`, OS/Brand version, CPU cores, Window size, `--disable-spoofing` CSV, Upstream Proxy, and Exit GeoIP.
   - **CDP Endpoint Card (when Running):** Shows active PID & port with 1-click `Copy Agent CLI` and `Copy WS URL`.
   - **Built-in `agent-browser` Runner:** Command input + `Run`, `Snapshot (-i)`, `Audit Live Fingerprint`, `Screenshot`, and recessed output well.
2. **`Fingerprint & Proxy` (`InspectorTab::FingerprintProxy`):**
   - Inline editor for Profile Name, Group Tag, Seed (`Randomize Seed`), Target OS (`macOS`, `Windows`, `Linux`), Browser Brand (`Chrome`, `Edge`, `Opera`, `Vivaldi`), CPU Cores (`4C`–`16C`), Window Size (`1280x800`, `1440x900`, `1920x1080`), 5 independent C++ spoofing layer toggles (`Canvas`, `Audio`, `Font`, `Rects`, `GPU Mode`), Proxy string, Custom Timezone/Locale, Startup URL, and Notes.
3. **`Cookies & State` (`InspectorTab::CookiesState`):**
   - Live session transfer powered by `agent-browser state save/load` and `cookies set --curl`: `Export State (JSON)`, `Import Payload / Saved State`, `Get Cookies JSON`, and `Clear Cookies`.

---

## 4. Craft Floor Guardrails

- **Elevation:** Declared once via `1px` hairline borders (`BonTheme::border()`) and surface luminance steps (`bg_canvas` $\rightarrow$ `bg_panel` $\rightarrow$ `bg_elevated`), never fuzzy drop shadows or thick side borders.
- **Status Indicators:** Drawn with crisp `6px` geometric status dots (`rounded_full()`) paired with semantic pill badges—never emoji or inconsistent Unicode glyphs.
- **Heading Discipline:** No uppercase kickers or eyebrows above headings; section titles and table headers speak directly in `text_xs font_semibold`.

---

## 5. Motion & Animation System (`src/ui/theme.rs` — Emil Kowalski Philosophy)

| Token | Specification | Usage |
|---|---|---|
| `BonTheme::snappy_spring()` | `SpringConfig::new(420.0, 38.0, 1.0)` ($\omega_0 \approx 20.5$, $\zeta \approx 0.93$) | Interruptible velocity-preserving spring for sidebar nav pills, segmented subtabs (`Local \| Groups \| Trash`, `My Proxies \| Free Proxies`), 6-tab Profile Editor pills, checkboxes, extension switches, and bidirectional `Detail` Drawer (`0px <-> 285px`) reveal |
| `BonTheme::ui_enter_anim()` | `140ms` `ease_out_quint()` | Crisp entrance for centered popup modals (`+10px` vertical lift + separate backdrop alpha interpolation), contextual batch action bars (`-4px -> 0px` slide), and stable-ID floating toast notifications |
| `BonTheme::status_pulse_anim()` | `1200ms` `pulsating_between(0.45, 1.0)` + `.repeat_synced()` + `.with_max_fps(30.0)` | Phase-locked 30fps breathing pulse shared across all `Starting` and `Checking...` status badges |

- **100+/day Navigation Rule:** Switching top-level views (`⌘1`–`⌘3`), subtabs, editor tabs, or selecting profile rows in the table is **instant** (`0ms` container opacity blanking); only the active pill indicator springs smoothly.
- **Virtualized Identity Rule:** Every spring or animation inside `uniform_list` (`Profiles`, `My Proxies`, `Free Proxies`) is keyed by the item's stable identity (`profile_id`, `pid`, `endpoint_key()`), never by viewport slot index.
- **Accessibility (`cx.reduce_motion()`):** Respected automatically by GPUI's `AnimationElement` and `SpringAnimationElement`, snapping oneshot animations and springs to their target state without scheduling redundant frames.
