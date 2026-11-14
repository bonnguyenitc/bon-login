<div align="center">
  <img src="assets/bonlogin-logo.svg" width="96" height="96" alt="BonLogin Logo" />
  <h1>BonLogin</h1>
  <p><strong>Pure-Rust Antidetect Browser, Proxy Tunnel & AI Agent Command Center for macOS</strong></p>
  <p>
    <a href="#why-bonlogin">Why BonLogin</a> •
    <a href="#feature-overview">Features</a> •
    <a href="#system-architecture">Architecture</a> •
    <a href="#getting-started">Getting Started</a> •
    <a href="#desktop-ui-guide">Desktop UI Guide</a> •
    <a href="#cli-reference">CLI Reference</a> •
    <a href="#local-http-control-api">HTTP API</a> •
    <a href="#agent-flow-playbooks">Agent Flows</a> •
    <a href="#roadmap">Roadmap</a> •
    <a href="LICENSE">License</a>
  </p>
</div>

---

**BonLogin** is a 100% pure-Rust, GPU-accelerated (`GPUI` / Metal 120fps) antidetect browser manager and headless AI automation control plane for macOS (Apple Silicon & Intel). Built as a local-first, zero-bloat alternative to Electron/Node.js multilogin suites, BonLogin combines:

- **C++ Kernel-Level Fingerprint Isolation** via [`adryfish/fingerprint-chromium`](https://github.com/adryfish/fingerprint-chromium) (Chromium 148).
- **In-Process Async Proxy Tunneling** (`HTTP CONNECT` & `SOCKS5` with remote DNS `ATYP = 0x03`) written in pure Rust (`tokio`).
- **Fail-Closed Pre-Launch GeoIP Synchronization** (automatic IP, Country, IANA Timezone, and ICU Locale alignment before browser spawn).
- **Native Stealth Automation** via [`vercel-labs/agent-browser`](https://github.com/vercel-labs/agent-browser), **Patchright**, a built-in **DOM Playbook Recorder (`AgentFlow`)**, and a **Local HTTP Control API (`127.0.0.1:19820`)**.

---

## Why BonLogin?

| Capability | Electron Antidetect Browsers | Stock Playwright / CDP | **BonLogin (Rust + GPUI)** |
| :--- | :--- | :--- | :--- |
| **UI & Supervisor Memory** | 450–900 MB (Chromium UI + Node.js) | N/A (CLI only) | **~35 MB (Native Rust + Metal GPUI)** |
| **Fingerprint Spoofing** | JS wrapper injection (`Object.defineProperty` leaks) | Unpatched Chromium | **C++ Blink / V8 / Skia (`fingerprint-chromium` 148)** |
| **WebGPU / WebGL on Apple Silicon** | Often software-rendered or mismatched | Default | **Hardware Metal Passthrough (`--disable-spoofing=gpu`) or Seed GPU** |
| **Authenticated Proxies (`user:pass`)** | MV3 extension hacks or external binaries | Context-only limits | **In-process Tokio `LocalProxyTunnel` (HTTP & SOCKS5 `0x03`)** |
| **DNS & WebRTC Leak Protection** | Optional / inconsistent | None | **Fail-Closed GeoIP + `--host-resolver-rules` + UDP lock** |
| **CDP Stealth (`Runtime.enable`)** | Detected when automation attaches | Flagged by Cloudflare / CreepJS | **C++ patched `Runtime.enable` + Stealth Guardrails** |
| **Control Surfaces** | GUI or Paid Cloud API | Code only | **120fps Desktop UI + Full Headless CLI + Local HTTP API** |

---

## Feature Overview

### 1. C++ Fingerprint Engine & Hardware Coherence
- **Deterministic 32-bit Seed (`--fingerprint=<seed>`):** Every profile generates a seed whose WebGL renderer maps to verified hardware configurations (passing CreepJS & BrowserScan without hex-gibberish penalties).
- **Multi-OS & Brand Emulation:** Emulate **macOS**, **Windows 11**, or **Linux** with **Chrome 148** or **Edge 148** Client Hints (`Sec-CH-UA`, `Sec-CH-UA-Platform`, `Sec-CH-UA-Full-Version-List`).
- **Per-Vector Spoofing Toggles:** Independently toggle C++ noise for **Canvas**, **WebGL**, **AudioContext**, **Fonts**, and **ClientRects**, or switch WebGL to **Apple Metal Native Passthrough** (`--disable-spoofing=gpu`).
- **Visual Identity & Multi-Tab Startup:** Automatically colors each Chromium profile's toolbar/avatar to match its row dot in BonLogin (`[#id4] Profile Name`) and supports launching multiple startup URLs per profile.

### 2. Zero-Leak Network, Proxy Manager & Fail-Closed GeoIP
- **In-Process `LocalProxyTunnel` (`src/proxy_tunnel.rs`):**
  - Binds an ephemeral local loopback listener (`127.0.0.1:<port>`) per active profile with a 10-second upstream handshake timeout and automatic `JoinSet` socket cleanup on exit.
  - Supports upstream **HTTP/HTTPS** (`Proxy-Authorization: Basic`) and **SOCKS5** (`RFC 1928/1929` username/password auth).
  - Forces **`ATYP = 0x03` (Domain Name)** on SOCKS5 and passes `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` to Chromium so zero DNS queries ever leak from macOS.
- **Fail-Closed Pre-Launch Check (`src/geoip.rs`):**
  - Before Chromium spawns, BonLogin probes egress IP, Country, and Timezone *through the profile's own tunnel* (`ipwho.is` → `ipinfo.io` → `ip-api.com`, 8s timeout).
  - If the proxy is dead or misconfigured, launch aborts immediately (**Fail-Closed**).
  - When live, BonLogin caches the resolved GeoIP and injects matching `--timezone=<iana_tz>`, `--lang=<icu_locale>`, and `--accept-lang` flags.
- **Proxy Pool Manager & 1-Click IP Rotation:**
  - Bulk import HTTP/SOCKS5 proxies (`type:host:port:user:pass:name|http://rotate_url`), organize by `#tags`, track expiration dates (`DD/MM/YYYY`), extend validity (`+30d`), and round-robin assign proxies to profiles.
  - Trigger single or batch **Proxy IP Rotation** via provider webhook URLs (`change_ip_url`) and automatically re-verify the new exit IP across all linked profiles.

### 3. Operator Productivity & Profile Lifecycle
- **Universal 6-Format Cookie Importer & Live Sync:**
  - Paste or import cookies in **Playwright State JSON**, **Cookie-Editor JSON**, **J2Team JSON**, **Netscape `.txt`**, **cURL commands**, or **raw `key=value` / MMO pipe lines** (`UID|Pass|2FA|c_user=...`).
  - Injects cookies into pre-launch storage or hot-loads them into an already-running browser, and automatically flushes updated cookies back to disk on browser exit.
- **Cookie Robot (Auto Warm-up):** Automatically visits preset or custom URLs (Google, YouTube, Reddit, Amazon, etc.), scrolls naturally with human dwell times, and saves accumulated cookies.
- **Built-in 2FA TOTP Authenticator:** Generates live 6-digit RFC 6238 TOTP codes (`Base32` or `otpauth://`) with countdown timers; 1-click copies and human-types the code (`cdp_type_as_human`) into the focused browser input—or broadcasts 2FA across all running browsers at once.
- **Bookmarks Bar Manager:** Manage per-profile Bookmarks Bar items from the UI (`Overview`, `Bookmarks` tab, `Quick Meta`, or `Detail` drawer). Clicking a bookmark chip on a running profile navigates the active tab immediately.
- **Window Tile & Grid Arranger (`Browser.setWindowBounds`):** Tile all or selected running browsers across any connected macOS display (`Auto Fit`, `2×1`, `2×2`, `3×2`, `4×2`, or custom `W,H`) using pure Browser-domain CDP—zero `Emulation.*` viewport leaks.
- **Clipboard Sync & Human Typing (`Input.dispatchKeyEvent`):** Bypass paste-blocking forms by typing clipboard text character-by-character into one or all running browsers simultaneously.
- **Backups, CSV Bulk I/O, Disk Cache Cleaner & Trash Bin:**
  - **Portable `.zip` Profile Archives:** Export/restore full profile archives (`.zip` containing metadata, pre-launch cookies, and essential `user-data-dir` Cookies/LocalStorage/IndexedDB).
  - **CSV / TSV & JSON Backup:** Bulk import/export profiles via CSV, TSV, or JSON.
  - **Clean Cache vs. Wipe Data:** Strip megabytes of Chromium shader/cache bloat while keeping cookies (`🧹 Clean Cache`), or reset a profile's browser directory cleanly while keeping its fingerprint config (`🧼 Wipe Data`).
  - **Soft-Delete Trash Bin:** Deleted profiles move to the `Trash` tab with full data preserved until restored or permanently wiped.

### 4. Curated Extension Vault & Agent-Ready MV3 Patching
- **14 Built-in & Web Store Extensions:** One-click enable/disable for **uBlock Origin Lite**, **Authenticator (2FA)**, **Cookie-Editor**, **Bitwarden**, **Violentmonkey**, **CapSolver**, **Simple Translate**, **MetaMask**, **Rabby Wallet**, **Phantom**, **OKX Wallet**, plus 3 built-in operator extensions (**Cookie & Token Grabber**, **Proxy / IP Status Badge**, **Coordinates Helper**).
- **Custom CRX / ZIP / Chrome Web Store Installer:** Upload `.crx`/`.zip` files or paste any Chrome Web Store URL/32-char ID.
- **Deterministic Extension Identity & Agent Shim:** Extracts RSA public keys from CRX headers so unpacked extensions keep their exact `chrome-extension://<32-char-id>` origin, and injects a lightweight tab/popup bridge so AI agents can inspect extension popups as standard tabs.

---

## System Architecture

```
+-----------------------------------------------------------------------------------+
|                        BonLogin Desktop & CLI Control Plane                       |
|  +-------------------------+  +-----------------------+  +---------------------+  |
|  | GPUI Desktop (Metal)    |  | Headless CLI          |  | Local HTTP API      |  |
|  | - Profiles / Groups     |  | - bon-login launch    |  | - 127.0.0.1:19820   |  |
|  | - Proxy Pool Manager    |  | - bon-login agent     |  | - /profiles, /type  |  |
|  | - Extensions & Flows UI |  | - bon-login flow      |  | - /arrange, /totp   |  |
|  +------------+------------+  +-----------+-----------+  +----------+----------+  |
+---------------|---------------------------|-------------------------|-------------+
                +---------------------------+-------------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------+
|                         Core Services Layer (Pure Rust)                           |
|  +-------------------+   +----------------------+   +--------------------------+  |
|  | SQLite (db.rs)    |   | Proxy & GeoIP Engine |   | Process & CDP Supervisor |  |
|  | - WAL mode        |   | - Tokio Local Tunnel |   | - Locate/xattr Kernel    |  |
|  | - Profiles,       |   |   (HTTP & SOCKS5     |   | - --remote-debugging-    |  |
|  |   Proxies, Groups,|   |    ATYP 0x03 domain) |   |   port=0                 |  |
|  |   Tags, Extensions|   | - Fail-Closed GeoIP  |   | - DevToolsActivePort     |  |
|  +-------------------+   +----------------------+   +--------------------------+  |
+-------------------------------------------+---------------------------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------+
|                    adryfish/fingerprint-chromium (macOS 148)                      |
|  --fingerprint=<seed>  --disable-blink-features=AutomationControlled              |
|  --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"                      |
+-------------------------------------------+---------------------------------------+
                                            |
                    DevToolsActivePort (ws://127.0.0.1:<port>/devtools/browser/...)
                                            |
                      +---------------------+---------------------+
                      v                                           v
        +---------------------------+               +---------------------------+
        | vercel-labs/agent-browser |               | Patchright / Custom CDP   |
        | - Stealth Guardrails      |               | - Zero Runtime.enable leak|
        | - Multi-Agent --pin-tab   |               | - Native Browser.* bounds |
        | - Self-Healing AgentFlows |               +---------------------------+
        +---------------------------+
```

---

## Getting Started

### Prerequisites

1. **macOS** (Apple Silicon `arm64` or Intel `x86_64`) with Xcode Command Line Tools:
   ```bash
   xcode-select --install
   ```
2. **Rust Toolchain** (automatically pinned via `rust-toolchain.toml`):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
3. **Optional — `agent-browser` CLI** (for AI agent DOM snapshots, Cookie Robot warm-up, and Flow Playbooks):
   ```bash
   npm install -g agent-browser
   ```

### Build & Run

```bash
# Clone the repository
git clone https://github.com/bonnguyenitc/bon-login.git
cd bon-login

# Launch the GPUI Desktop App
cargo run

# Or build a standalone macOS BonLogin.app release bundle
./scripts/build-release.sh
open target/release/BonLogin.app
```

> **Automatic Kernel Installer:** If `adryfish/fingerprint-chromium` is not installed yet, click **Download Kernel** in the bottom-left sidebar (or run `bon-login kernel install`) to automatically download, mount, extract, and unquarantine (`xattr -cr`) `Chromium.app` (`148.0.7778.215`).

---

## Desktop UI Guide

### 1. Top Header & Global Controls
- **`🔌 Local API` / `🟢 API :19820`:** Starts or stops the embedded Local HTTP JSON Control Server on `127.0.0.1:19820` and copies the endpoint URL to your clipboard.
- **`▶️ Flows (N)`:** Opens the **Agent Flow Playbooks** modal to replay saved DOM automation flows (`flows/*.json`), pass `{{var}}` overrides, or save a profile's recorded steps as a reusable flow.
- **`🖥️ Arrange (N)`:** Opens the **Window Tile & Grid Arranger** modal to tile all (or checked) running browsers across any monitor (`Auto Fit`, `2×1`, `2×2`, `3×2`, `4×2`, or custom `Width,Height`).
- **`⚡ Quick add`:** Batch-create up to 50 profiles at once with custom name prefixes, OS (`Windows 11` / `Mac OS` / `Linux`), browser brand (`Chrome` / `Edge`), group assignment, and round-robin proxy selection.

### 2. Profiles Workspace (`Local` | `Groups` | `Trash`)
- **Toolbar Actions:** Search by name/ID/IP/tag/note/seed, **`🧹 Clean Cache`**, **`📊 Import CSV`**, **`📤 Export CSV`**, **`📥 Import JSON`**, and **`📥 Import .zip`**.
- **Batch Action Bar** (appears when 1+ profiles are checked):
  - **`▶ Start N` / `■ Stop N`** — Launch or gracefully stop selected profiles.
  - **`🖥️ Arrange N`** — Tile selected running browser windows.
  - **`⚡ Sync Clipboard`** — Navigate all selected running browsers to a copied URL, or human-type copied text into their active inputs simultaneously.
  - **`🔐 Broadcast 2FA`** — Generate and human-type each running profile's own 6-digit TOTP code into its active browser window.
  - **`📁 Assign to group`** — Move selected profiles to a folder.
  - **`↻ Reseed`** — Randomize hardware-coherent fingerprint seeds for all selected profiles.
  - **`🛡️ Check proxy` / `🔄 Rotate IP` / `🔁 Update proxy`** — Verify proxies, trigger IP rotation webhooks, or reassign proxies in bulk.
  - **`🎚️ Update profiles` / `🔖 Tags, Bookmarks & Note` / `🤖 Cookie Robot` / `▶️ Run Flow`**.
  - **`⋯` Menu:** Copy IDs, Copy names, Export `.zip` archives, Export JSON backup, or Move to Trash.
- **Row `⋯` Context Menu & Right-Hand `Detail` Drawer:**
  - Inspect live fingerprint parameters, **Disk Usage**, **Bookmarks** (1-click open in active tab), and live **2FA TOTP** countdown badge.
  - Actions: `Edit`, `Bookmarks, Tags & 2FA`, `Copy 2FA Code`, `Focus Browser Window`, `Human-Type Clipboard`, `Capture Screenshot`, `Rotate Proxy IP`, `Cookie Robot (Warm-up)`, `Agent Flows (Playbooks)`, `Copy Agent CLI`, `Copy Pinned-Tab CLI`, `Import/Export Cookies`, `Export Backup (.zip)`, `Clean Disk Cache`, `Wipe Browser Data`, `Clone (1-click)`, `Clone Multiple...`, `Copy ID`, `Copy Proxy`, `Move to Trash`.

### 3. Proxy Management Workspace
- Import HTTP/SOCKS5 proxies (`1 per line`), filter or delete `#tags`, track `Started at` / `Expired at` badges, and view how many profiles use each proxy.
- Single & batch actions: **`Check`**, **`🔄 Rotate IP`**, **`Extend (+30d)`**, **`Copy`**, **`Assign to profiles`**, **`✎ Edit proxy / Rotate URL`**, and **`Delete`**.

---

## CLI Reference

The `bon-login` binary is a dual-mode executable: running `bon-login` with no arguments opens the GPUI Desktop App, while passing any subcommand runs in headless CLI mode (returning structured JSON).

### Browser & Live Session Control
```bash
# List all profiles with live PID, CDP port, and WebSocket status (JSON)
bon-login list [--group <group>] [--search <query>]

# Launch profile(s) with fail-closed GeoIP check & auto-connect agent-browser
bon-login launch <id|name|--group <g>|--all> [--pin-tab <tag>] [--url <url>]

# Gracefully stop running profile(s) and flush SQLite cookies to disk
bon-login stop <id|name|--group <g>|--all>

# Re-scan CDP targets (OAuth popups, Web3 wallet windows, extensions) into tabs
bon-login sync <id|name>

# Tile all running browser windows into a non-overlapping screen grid
bon-login arrange [--size <W,H>]

# Bring a running profile's browser window to the front on macOS
bon-login focus <id|name>

# Human-type text character-by-character via CDP Input.dispatchKeyEvent
bon-login type <id|name> <text...>
# Generate 6-digit 2FA TOTP code (and optionally type it into the running browser)
bon-login totp <id|name> [--type]

# Capture a zero-leak PNG screenshot via CDP Page.captureScreenshot
bon-login screenshot <id|name> [--out <file.png>]

# Generate (and optionally open) a zero-bandwidth local Stealth & Proxy Health Preflight Card
bon-login preflight <id|name|--group <g>|--all> [--open]
# Broadcast URL navigation, human typing, or per-profile 2FA across running browsers
bon-login broadcast <open|type|totp> [value] [--group <group>]

# Live 1-to-N Multi-Profile Synchronizer (mouse, wheel, keyboard, and URL navigation)
bon-login synchronizer <master_id|name> [follower1,follower2...|--group <g>] [--tile] [--duration <secs>]
```

### Profile Lifecycle Management (`bon-login profile ...`)
```bash
bon-login profile list [--group <g>] [--search <q>]
bon-login profile show <id|name>

# Create a profile with full fingerprint, proxy, 2FA, bookmarks, and spoofing flags
bon-login profile create "TikTok US 01" \
  --os windows --brand chrome --group "TikTok" --tags "Live,VIP" \
  --proxy-tag "US-Residential" --totp "JBSWY3DPEHPK3PXP" \
  --gpu seed --canvas on --audio on --font on --rects on \
  --window-size 1920,1080 --startup-url "https://seller-us.tiktok.com" \
  --bookmarks "Seller Center|https://seller-us.tiktok.com,Analytics|https://ads.tiktok.com"

# Update single, group, or all profiles
bon-login profile update <id|name|--group <g>|--all> [same flags as create]

# Manage per-profile Bookmarks Bar (list, add, set, or clear)
bon-login profile bookmarks <id|name> [list | add <Name|URL,...> | set <Name|URL,...> | clear]
bon-login profile reseed <id|name|--group <g>|--all>
bon-login profile clone <id|name> [--count <n>] [--name <prefix>]
bon-login profile batch-create --count 10 --prefix "Shop" --group "TikTok" --os windows --proxy-tag "US"

# Proxy verification, IP rotation, and cookie warm-up (with custom dwell seconds)
bon-login profile check-proxy <id|name|--group <g>|--all>
bon-login profile rotate-proxy <id|name|--group <g>|--all>
bon-login profile warmup <id|name|--group <g>|--all> [url1,url2,...] [--dwell <secs>]

# Cookies, Archives (.zip), CSV, JSON Backup & Disk Maintenance
bon-login profile export-cookies <id|name> [--out <file.json>]
bon-login profile import-cookies <id|name> <file_or_raw_cookie_payload>
bon-login profile export-zip <id|name|--group <g>|--all>
bon-login profile import-zip <archive.zip>
bon-login profile export-csv [--out <file.csv>]
bon-login profile import-csv <file.csv>
bon-login profile backup [--out <backup.json>]
bon-login profile restore <backup.json>
bon-login profile clean-cache <id|name|--group <g>|--all>
bon-login profile wipe <id|name|--group <g>|--all>
bon-login profile trash [list | restore <id|--all> | empty]
bon-login profile delete <id|name|--group <g>|--all> [--permanent]
```

### Proxy, Group, Tag, Extension & Kernel CLI
```bash
# Proxy Pool Manager
bon-login proxy list [--tag <tag>]
bon-login proxy free [--protocol socks5|http] [--country <CC>] [--search <q>] [--limit <n>] [--verify] [--save] [--tag <t>]
bon-login proxy add "socks5://user:pass@1.2.3.4:1080|https://api.rot.local/ip" --tag "US" --expire 30d
bon-login proxy update <id|name|--tag <t>|--all> [--name <n>] [--tag <t>] [--expire <days_or_date|none>] [--rotate-url <url|none>]
bon-login proxy check <id|name|--tag <t>|--all>
bon-login proxy rotate <id|name|--tag <t>|--all>
bon-login proxy extend <id|name|--tag <t>|--all> <days|0|clear>
bon-login proxy assign <proxy_id|--tag <t>|--all|none> --to <profile_id|--group <g>|--all>
bon-login proxy export [--tag <t>] [--out <file.txt>]
bon-login proxy delete <id|name|--tag <t>|--all>

# Groups & Proxy Tags
bon-login group list | add <name> | delete <name> | move <target> <group|none>
bon-login tag list   | add <name> | delete <name>

# Extensions
bon-login ext list
bon-login ext enable <id|name|--all> | disable <id|name|--all>
bon-login ext add <crx_or_zip_or_folder_or_webstore_url_or_id>
bon-login ext remove <id|name>
bon-login ext open <ext_id|name> [--profile <profile_id|name>]

# Fingerprint-Chromium Kernel
bon-login kernel status | check | install [--force]
```

---

## Agent Flow Playbooks (`bon-login flow`)

BonLogin includes a built-in **DOM Playbook Recorder & Self-Healing Runner** on top of `agent-browser`:

1. **Automatic Step Recording (`@eN` → Resilient Multi-Locators):**
   Whenever you run `bon-login agent <profile> snapshot -i -c` followed by `bon-login agent <profile> click @e3` or `fill @e5 "value"`, BonLogin inspects the live DOM attributes (`data-testid`, `id`, `name`, `aria-label`, `placeholder`, `href`, and ARIA `role:name`) and records a ranked fallback locator list into `_history_<id8>.json`.
2. **Parameterize Secrets & Variables (`{{var}}`):**
   Save a profile's recorded steps as a reusable playbook while replacing literal credentials with `{{var}}` placeholders (plus built-in `{{profile.name}}`, `{{profile.short_id}}`, and `{{profile.notes}}`).
3. **Self-Healing Execution:**
   When a selector changes on a target website, `bon-login flow run` automatically tries each fallback locator, promotes the winning locator to index `0`, or outputs a ready-to-run `bon-login flow heal` command with a fresh DOM snapshot.

```bash
# 1. Interact with a profile via stealth-guarded agent-browser
bon-login agent "TikTok US 01" open "https://example.com/login"
bon-login agent "TikTok US 01" snapshot -i -c
bon-login agent "TikTok US 01" fill @e1 "alice@example.com"
bon-login agent "TikTok US 01" fill @e2 "SuperSecret123"
bon-login agent "TikTok US 01" click @e3

# 2. Save the recorded session history as a parameterized flow
bon-login flow save login_playbook "TikTok US 01" \
  --var email="alice@example.com" \
  --var password="SuperSecret123"

# 3. Replay the flow across any profile or group with custom variables, CSV data, & concurrency
bon-login flow run login_playbook --group "TikTok" \
  --csv accounts.csv --concurrency 5 \
  --var email="bob@example.com" \
  --var password="OtherPassword456"
# 4. Self-heal a broken step if the website layout changes
bon-login flow heal login_playbook 2 "TikTok US 01" click @e9

# 5. Mark a dismissible banner/popup step as optional (or delete a step)
bon-login flow step login_playbook 1 optional
```

> **Stealth Guardrails:** `bon-login agent` automatically blocks any `agent-browser` command or flag that invokes CDP `Emulation.*` (`set viewport`, `set device`, `set geo`, `set media`, `set headers`, `--user-agent`, `--proxy`), ensuring your C++ fingerprint remains 100% intact.

---

## Local HTTP Control API

Toggle **`🔌 Local API`** in the top header bar or run `bon-login serve [--port 19820]` to expose a local JSON control plane on `127.0.0.1:19820` (protected against browser cross-origin CSRF / DNS rebinding requests):

| Method & Path | Description |
| :--- | :--- |
| `GET /health` | Health check (`{"ok": true, "service": "bon-login"}`) |
| `GET /profiles` | List all profiles, proxy metadata, tags, and live runtime status |
| `GET /flows` | List all saved Agent Flows, required `{{vars}}`, and DOM steps |
| `POST /profiles/<id\|name>/launch` | Launch profile via supervisor and return `{pid, cdp_port, ws_url}` |
| `POST /profiles/<id\|name>/stop` | Gracefully stop running profile and flush cookies |
| `POST /profiles/<id\|name>/rotate-proxy` | Trigger proxy IP rotation webhook and return new `GeoInfo` |
| `POST /profiles/<id\|name>/clean-cache` | Clean Chromium disk cache for a stopped profile |
| `POST /profiles/<id\|name>/type` | Human-type raw request body into the active browser input |
| `POST /profiles/<id\|name>/totp` | Generate and human-type the profile's 6-digit 2FA TOTP code |
| `POST /profiles/<id\|name>/screenshot` | Capture a PNG screenshot and return its file path |
| `POST /profiles/<id\|name>/preflight` | Generate local Stealth & Proxy Preflight Card HTML and navigate if running |
| `POST /profiles/<id\|name>/flow/<flow_name>` | Launch/attach profile and replay saved Agent Flow (JSON `{"vars":{...}}` or `k=v` body) |
| `POST /arrange` | Tile all running browser windows (optional body `"960,600"`) |
| `GET /synchronizer` | Query active 1-to-N Multi-Profile Synchronizer status & mirrored event count |
| `POST /synchronizer/start` | Start background Synchronizer (`{"master": "<id>", "followers": ["<id2>"]}`) |
| `POST /synchronizer/stop` | Stop active background Synchronizer session |
```bash
# Example: Launch a profile and type its 2FA code via cURL / n8n / Python
curl -X POST http://127.0.0.1:19820/profiles/a1b2c3d4/launch
curl -X POST http://127.0.0.1:19820/profiles/a1b2c3d4/totp
```

---

## Data Storage Layout

All application data is stored locally under `~/Library/Application Support/com.bonlogin.app/`:

| Path | Description |
| :--- | :--- |
| `bonlogin.sqlite3` | Local SQLite database (WAL mode: `profiles`, `proxies`, `profile_groups`, `proxy_tags`, `extensions`) |
| `kernels/chromium-148.0.7778.215/` | Unquarantined `adryfish/fingerprint-chromium` macOS `.app` bundle |
| `profiles/<profile_uuid>/` | Isolated Chromium `--user-data-dir` (plus `bon_runtime.json` & `DevToolsActivePort`) |
| `states/bon_<id8>_prelaunch.json` | Normalized pre-launch & exported cookie/storage bundles |
| `extensions/<ext_id>/` | Unpacked Manifest V3 extensions patched for `agent-browser` |
| `flows/<flow_name>.json` | Saved `AgentFlow` DOM playbooks & per-profile `_history_<id8>.json` |
| `screenshots/` | PNG screenshots captured via CDP `Page.captureScreenshot` |

---

## Testing

```bash
# Run the full unit & integration test suite (36 tests: SOCKS5 ATYP 0x03, Fail-Closed GeoIP,
# SQLite CRUD, Cookie Parser, CRX3 Key Extraction, AgentFlow Locators, HTTP API, E2E Launch)
cargo test --bin bon-login
```

---

## Roadmap

High-leverage operator & stealth automation features planned and delivered under the Ponytail zero-bloat philosophy:

| # | Feature | Status | Description |
| :-: | :--- | :---: | :--- |
| **1** | **Multi-Profile Synchronizer (1-to-N Live Input Mirror)** | ✅ **Done** | Real-time Master → Follower mirroring of mouse clicks (viewport-scaled), wheel scrolling, keyboard typing (`Input.dispatchKeyEvent`), and URL navigation across running profiles (`bon-login synchronizer <master> [followers...]`, `POST /synchronizer/*`, and Desktop UI `🔗 Sync` controls). |
| **2** | **Paste as Human Typing + Auto-2FA Broadcast** | ✅ **Done** | Bypass anti-bot clipboard paste listeners via character-by-character CDP keystroke dispatch and 1-click RFC 6238 TOTP typing (`bon-login type`, `bon-login totp --type`, `bon-login broadcast`). |
| **3** | **Smart Cookie Robot / 1-Click Warm-up** | ✅ **Done** | Automated multi-domain browsing and human scrolling to warm up fresh cookie stores before sensitive logins (`bon-login profile warmup`). |
| **4** | **Profile Storage Cleaner & Disk Quota** | ✅ **Done** | Strip Chromium shader/code/crashpad caches while preserving 100% of Cookies, LocalStorage, and IndexedDB (`bon-login profile clean-cache`). |
| **5** | **Batch AgentFlow Runner + CSV Data Variables (`--csv`, `--concurrency N`)** | ✅ **Done** | Execute parameterized `AgentFlow` playbooks across 50+ profiles with per-row CSV credentials (`{{email}}`, `{{pass}}`, matched by profile or index) and bounded worker concurrency (`bon-login flow run ... --csv <file> --concurrency <n>` & UI). |
| **6** | **Stealth & Proxy Health Preflight Card (Local Start Page)** | ✅ **Done** | Zero-bandwidth local diagnostic start page (`bon://preflight`, `bon-login preflight`, `POST /profiles/:id/preflight`, and UI `🛡️ Preflight`) showing live Exit IP, Timezone/Locale coherence, WebRTC/DNS lock status, Seed/GPU summary, and quick bookmarks. |

---

## License

Released under the [MIT License](LICENSE).
