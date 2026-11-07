# BonLogin Design System (`DESIGN.md`)

## 1. Visual World & Philosophy — Dark Precision

BonLogin is an **Operate-mode** macOS desktop workbench built in 100% Pure Rust (`gpui-kit = "0.9.0"`). Its design language draws from high-frequency developer and operator instruments (**Zed**, **Linear**, **Raycast**):

- **Zero Layout Shift:** Editing a profile, inspecting live telemetry, or running `agent-browser` automation never pushes, squashes, or overlays the main profile roster.
- **One Row, One Primary Action:** Each roster row displays identity metadata, fingerprint spec, network/GeoIP state, and a single primary button (`Launch` or `Stop`). All secondary operations (`Check Proxy`, `Clone`, `Wipe Cache`, `Delete`, `Snapshot`, `Audit Live Fingerprint`, `Export/Import Cookies`) live inside the persistent Right Inspector.
- **Restrained Semantic Color:** Surfaces stay strictly in deep obsidian-graphite neutrals with cool-tinted slate typography; saturated color is reserved exclusively for live operational state (`Running Emerald`, `Starting Amber`, `Fail-Closed Crimson`, `Active Selection Indigo`).

---

## 2. Color Tokens (`src/ui/theme.rs` — `BonTheme`)

| Token | Hex | Role |
|---|---|---|
| `BonTheme::bg_canvas()` | `#090A0F` | Deepest application window canvas |
| `BonTheme::bg_panel()` | `#0F1117` | Primary surface for Master Roster & Right Inspector panes |
| `BonTheme::bg_elevated()` | `#161922` | Table headers, inspector headers, and spec cards |
| `BonTheme::bg_selected()` | `#1A1F2E` | Active selected row background in Master Roster |
| `BonTheme::bg_well()` | `#07080C` | Recessed monospace output well for `agent-browser` & Cookie JSON |
| `BonTheme::border()` | `#212634` | `1px` structural hairline divider |
| `BonTheme::border_active()` | `#3B4668` | Highlighted `1px` border on selected row and active CDP card |
| `BonTheme::text_primary()` | `#F3F5F8` | Primary high-contrast body and heading ink |
| `BonTheme::text_secondary()` | `#949DB2` | Cool-tinted slate secondary copy and form labels |
| `BonTheme::text_muted()` | `#636C82` | Technical metadata, IDs (`bon_<id8>`), and column headers |
| `BonTheme::accent()` | `#6366F1` | Precision Indigo for group badges and active controls |
| `BonTheme::success()` | `#10B981` | Running session indicator, verified GeoIP exit node, Kernel ready |
| `BonTheme::warning()` | `#F59E0B` | Starting tunnel / GeoIP resolution in progress / Kernel missing |
| `BonTheme::danger()` | `#EF4444` | Fail-Closed proxy block & Stop session trigger |

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
