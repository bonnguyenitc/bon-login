<div align="center">
  <img src="assets/bonlogin-logo.svg" width="96" height="96" alt="BonLogin Logo" />
  <h1>BonLogin</h1>
  <p><strong>Native Rust Antidetect Browser & AI Agent Command Center for macOS</strong></p>
  <p>
    <a href="#features">Features</a> •
    <a href="#architecture">Architecture</a> •
    <a href="#getting-started">Getting Started</a> •
    <a href="#ai-agent-integration">AI Agent Integration</a> •
    <a href="LICENSE">License</a>
  </p>
</div>

---

**BonLogin** is a pure-Rust, GPU-accelerated antidetect browser manager and AI automation command center built for macOS (Apple Silicon & Intel). Designed as a zero-bloat alternative to Electron-based antidetect browsers, BonLogin combines **GPUI** (`gpui-kit`), a per-profile Tokio **LocalProxyTunnel**, and the C++-patched **`fingerprint-chromium`** engine with native **`agent-browser`** & **Patchright** CDP integration.

## Why BonLogin?

| Capability | Electron Antidetect Browsers | Stock Playwright / CDP | **BonLogin** |
| :--- | :--- | :--- | :--- |
| **UI & Daemon Memory** | 400–900 MB (Chromium UI + Node.js) | N/A (CLI only) | **~35 MB (Native Rust + Metal GPUI)** |
| **Fingerprint Spoofing** | JS injection (`Object.defineProperty` leaks) | Unpatched Chromium | **C++ Blink/V8/Skia (`fingerprint-chromium`)** |
| **WebGPU / WebGL on Apple Silicon** | Often software-rendered (`SwiftShader` flag) | Default | **Real Apple M-Series GPU passthrough (`--disable-spoofing=gpu`)** |
| **Authenticated Proxy Support** | Extension-based or heavy local binary | Per-context limitations | **In-process Rust `LocalProxyTunnel` (HTTP & SOCKS5 `0x03`)** |
| **Fail-Closed Leak Protection** | Optional / inconsistent | None | **Pre-launch GeoIP check + remote DNS enforcement** |
| **CDP Stealth (`Runtime.enable`)** | Vulnerable when automation attaches | Detected by Cloudflare/DataDome | **Zero-leak attachment via `agent-browser` & `Patchright`** |

---

## Features

- **C++ Kernel-Level Fingerprint Isolation:** Controls [`adryfish/fingerprint-chromium`](https://github.com/adryfish/fingerprint-chromium) via deterministic `--fingerprint=<uint32_seed>` flags across Canvas, AudioContext, Fonts, ClientRects, Hardware Concurrency, and Device Memory—zero JS prototype tampering.
- **Zero-Leak In-Process Proxy Tunnel (`src/proxy_tunnel.rs`):**
  - Binds an ephemeral local loopback listener (`127.0.0.1:<port>`) per running profile.
  - Translates Chromium traffic into authenticated upstream **HTTP `CONNECT`** or **SOCKS5 (`RFC 1928/1929`)** tunnels.
  - Enforces `ATYP = 0x03` (Domain Name) on SOCKS5 so DNS resolution happens exclusively on the remote proxy server.
- **Fail-Closed Pre-Launch GeoIP Synchronization (`src/geoip.rs`):**
  - Resolves egress IP, Country, and IANA Timezone through the profile's proxy (`ipwho.is` → `ipinfo.io` → `ip-api.com` fallback chain) *before* spawning Chromium.
  - Automatically injects matching `--timezone` and `--lang` flags; aborts launch immediately if the proxy is unreachable or leaks.
- **Centralized Proxy Manager & Bulk Operations:**
  - Manage HTTP/SOCKS5 proxy pools with tags, live latency/egress checks, and tag-based random assignment.
  - Bulk-create profiles, batch-import cookies (JSON / Netscape / Header strings), and organize profiles with color-coded tags and campaign groups.
- **Curated Extension Vault & Auto-Built Utility Extensions:**
  - One-click Manifest V3 extensions per profile (uBlock Origin Lite, Cookie-Editor, Simple Translate, Violentmonkey, Authenticator 2FA, MetaMask, Rabby, Phantom, OKX) plus built-in operator tools (`IP Status Badge`, `Cookie/Token Grabber`, `Coordinates HUD`).
- **AI Agent Command Center (`vercel-labs/agent-browser`):**
  - Attach `agent-browser` directly to any running profile's `DevToolsActivePort` WebSocket URL (`ws://127.0.0.1:<port>/devtools/browser/<uuid>`).
  - Run interactive accessibility snapshots (`snapshot -i`), inspect C++ fingerprint vectors live, capture screenshots, and export/import Playwright Auth State JSON from the right-hand Inspector.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                         BonLogin (Rust + GPUI)                            │
│  ┌──────────────────┐   ┌────────────────────┐   ┌─────────────────────┐  │
│  │   SQLite Store   │   │  GeoIP Verifier    │   │  LocalProxyTunnel   │  │
│  │ (WAL + Profiles, │   │ (Fail-Closed Check │   │ 127.0.0.1:<ephem>   │  │
│  │  Proxies, Tags)  │   │  via Upstream)     │   │  ├─ HTTP CONNECT    │  │
│  └────────┬─────────┘   └─────────┬──────────┘   │  └─ SOCKS5 ATYP=0x03│  │
└───────────┼───────────────────────┼──────────────┴──────────┬──────────┘  │
            │                       ▼                         │             │
            │        ┌──────────────────────────────┐         │             │
            └───────►│ adryfish/fingerprint-chromium│◄────────┘             │
                     │  --fingerprint=<seed>        │                       │
                     │  --disable-spoofing=gpu      │                       │
                     │  --remote-debugging-port=0   │                       │
                     └──────────────┬───────────────┘                       │
                                    │ DevToolsActivePort (ws://127.0.0.1)   │
                     ┌──────────────┴───────────────┐                       │
                     ▼                              ▼                       │
          ┌─────────────────────┐        ┌─────────────────────┐            │
          │   agent-browser     │        │     Patchright      │            │
          │ (AI Agent Snapshot) │        │ (Stealth CDP Auto)  │            │
          └─────────────────────┘        └─────────────────────┘            │
```

### Project Layout

```text
bon-login/
├── src/
│   ├── main.rs            # Application entrypoint & GPUI window initialization
│   ├── models.rs          # Profile, Proxy, FingerprintConfig, Extension & Runtime state models
│   ├── db.rs              # SQLite persistence (rusqlite bundled), migrations, bulk operations
│   ├── proxy_tunnel.rs    # Async Tokio LocalProxyTunnel (HTTP CONNECT & SOCKS5 ATYP=0x03)
│   ├── geoip.rs           # Fail-Closed GeoIP resolver (ipwho.is / ipinfo.io / ip-api.com)
│   ├── launcher.rs        # Chromium process manager, CDP discovery, window monitor & agent-browser CLI
│   └── ui/
│       ├── mod.rs           # Main workspace, sidebar navigation, Proxy Manager & Inspector
│       ├── profile_list.rs  # Master profile table, batch actions & tag/group filtering
│       ├── profile_modal.rs # Create/Edit profile drawer (Overview, Network, Hardware, Extensions, Bookmarks)
│       └── theme.rs         # Dark Precision color tokens & typography scale
├── assets/                # App logo SVG & bundled extension icons
└── Cargo.toml             # Rust 2024 edition manifest
```

---

## Getting Started

### Prerequisites

1. **macOS** (Apple Silicon `arm64` or Intel `x86_64`) with Xcode Command Line Tools:
   ```bash
   xcode-select --install
   ```
2. **Rust Toolchain** (Nightly toolchain is configured automatically via `rust-toolchain.toml`):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
3. **Fingerprint Chromium Kernel (`148.0.7778.215`+):**
   Download the macOS build of [`adryfish/fingerprint-chromium`](https://github.com/adryfish/fingerprint-chromium/releases) and place `Chromium.app` in:
   ```text
   ~/Library/Application Support/com.bonlogin.app/kernels/chromium-148.0.7778.215/Chromium.app
   ```
   Remove the macOS quarantine attribute so the unnotarized open-source binary can launch:
   ```bash
   xattr -cr ~/Library/Application\ Support/com.bonlogin.app/kernels/chromium-148.0.7778.215/Chromium.app
   ```
4. **Optional — `agent-browser` CLI** (for AI agent snapshots, live fingerprint audits, and state export/import):
   ```bash
   npm install -g agent-browser
   ```

### Build & Run

```bash
# Clone the repository
git clone https://github.com/bonnguyenitc/bon-login.git
cd bon-login

# Run in development mode (optimized GPUI dependencies enabled in Cargo.toml)
cargo run

# Or build release binary + signed macOS BonLogin.app bundle
./scripts/build-release.sh
open target/release/BonLogin.app
```

### Run Tests

```bash
cargo test
```

---

## AI Agent Integration

Every running profile writes its dynamic WebSocket endpoint to `<profile_dir>/DevToolsActivePort` and exposes it in the BonLogin Inspector.

### Using `agent-browser`

```bash
# Read the active WebSocket endpoint for a running profile
WS_URL="ws://127.0.0.1:<port>/devtools/browser/<uuid>"

# Capture an AI-friendly interactive accessibility tree (@e1, @e2 refs)
agent-browser --session bon_profile1 connect "$WS_URL"
agent-browser --session bon_profile1 snapshot -i

# Export or restore authenticated session state (cookies + localStorage)
agent-browser --session bon_profile1 state save ./auth-state.json
agent-browser --session bon_profile1 state load ./auth-state.json
```

### Using `Patchright` (Node.js / Python)

```javascript
import { chromium } from 'patchright';

const browser = await chromium.connectOverCDP('ws://127.0.0.1:<port>/devtools/browser/<uuid>');
const context = browser.contexts()[0];
const page = context.pages()[0] || await context.newPage();
await page.goto('https://browserscan.net');
```

---

## Data Storage Paths

All local state is stored inside `~/Library/Application Support/com.bonlogin.app/`:

| Path | Description |
| :--- | :--- |
| `bonlogin.sqlite3` | Local SQLite database (profiles, proxy pool, tags, folders, settings) |
| `kernels/chromium-<ver>/Chromium.app` | Patched `fingerprint-chromium` binary bundle |
| `profiles/<profile_uuid>/` | Isolated Chromium `--user-data-dir` per profile |
| `extensions/` | Auto-built utility extensions and unpacked user extensions |
| `states/<profile_uuid>-state.json` | Exported Auth State snapshots |

---

## License

Released under the [MIT License](LICENSE).
