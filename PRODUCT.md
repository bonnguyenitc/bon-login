# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Pure Rust desktop application on macOS using `gpui-kit = "0.9.0"` (`gpui-pre = "=0.3.11"` + `gpui-component`), `rusqlite` (`bundled`), `tokio`, and `reqwest`, controlling the `adryfish/fingerprint-chromium` (`148.0.7778.215`) browser kernel and integrating natively with `vercel-labs/agent-browser` (`v0.41.2`) and `Patchright`.

## Users

Solo indie hackers, media buyers, multi-account operators, and AI automation engineers working long sessions on macOS (MacBook Pro / Mac Studio displays) who manage dozens of isolated browser identities and drive them both manually and via AI agents.

## Product Purpose

BonLogin provides hardware-speed, zero-leak browser identity isolation and AI-ready automation on macOS without the memory bloat of Electron, Node.js, or Python daemons. Success means launching an isolated profile in under a second with guaranteed Fail-Closed proxy verification and zero-detection CDP attachment.

## Positioning

Unlike Electron-based antidetect browsers or stock Playwright/CDP wrappers that leak `Runtime.enable` or local DNS queries, BonLogin combines a pure-Rust Tokio `LocalProxyTunnel` (enforcing SOCKS5 `ATYP = 0x03` remote DNS resolution and Fail-Closed GeoIP checks) with the C++-patched `adryfish/fingerprint-chromium` engine (`--disable-spoofing=gpu` passthrough on Apple Silicon) so both manual browsing and `agent-browser` / `Patchright` CDP sessions pass BrowserScan, CreepJS, and PixelScan with 0 MB of idle daemon overhead.

## Operating Context

Used daily as an operational command center alongside terminal sessions, code editors (Zed / Cursor), and live Chromium windows. Operators scan profile states at a glance, filter by campaign group, toggle profiles on/off with one click, and inspect or automate individual profiles (DOM snapshots, live fingerprint audits, cookie/state transfers) in a dedicated side inspector without losing sight of their roster.

## Capabilities and Constraints

- Single-table local SQLite storage (`~/Library/Application Support/com.bonlogin.app/bonlogin.sqlite3`) with automatic schema migration.
- Per-profile `LocalProxyTunnel` (`127.0.0.1:<ephemeral_port>`) forwarding to HTTP or SOCKS5 proxies with `user:pass` auth, 10s handshake timeout, and `JoinSet` socket cleanup.
- Fail-Closed GeoIP resolution (`ipwho.is` -> `ipinfo.io` -> `ip-api.com`, 8s timeout) before Chromium is ever spawned.
- Dynamic CDP port allocation (`--remote-debugging-port=0`) read from `<user-data-dir>/DevToolsActivePort` (`ws://127.0.0.1:<port>/devtools/browser/<uuid>`).
- Graceful `SIGTERM` shutdown with a 2-second SQLite cookie flush window.
- Built-in `agent-browser` runner for interactive DOM snapshots (`snapshot -i`), live C++ fingerprint auditing, screenshots, and JSON Auth State / Cookie import-export.

## Brand Commitments

- **Visual World:** Dark Precision (inspired by Zed, Linear, and Raycast) — deep neutral graphite/obsidian surfaces, 1px hairline borders, high-contrast tabular data, and disciplined semantic color reserved strictly for live state (`Running Emerald`, `Fail-Closed Crimson`, `Starting Amber`, `Selection Indigo`).
- **Workspace Topology:** Split Master–Inspector layout — clean, scannable Master Profile Roster on the left (only 1 primary `Launch` / `Stop` button per row) paired with a persistent, zero-layout-shift Inspector on the right housing three focused tabs (`Overview & Agent`, `Fingerprint & Proxy`, `Cookies & State`).

## Evidence on Hand

- Installed and verified `adryfish/fingerprint-chromium` `148.0.7778.215` kernel in `~/Library/Application Support/com.bonlogin.app/kernels/chromium-148.0.7778.215/Chromium.app`.
- Verified `vercel-labs/agent-browser` `v0.41.2` CLI integration (`connect`, `snapshot -i`, `eval`, `state save/load`, `cookies set --curl`).
- Automated unit and E2E test suite in `src/` (`cargo test`).

## Product Principles

1. **Zero Layout Shift:** Inspecting, editing, or automating a profile never pushes, squashes, or obscures the profile roster.
2. **One Row, One Primary Action:** Each roster row exposes its identity, proxy/GeoIP truth, runtime state, and a single `Launch` / `Stop` trigger; secondary operations live in the right-hand Inspector.
3. **Fail-Closed Honesty:** Proxy, GeoIP, and kernel states are surfaced with exact technical truth (IP, Country, Timezone, PID, CDP port) rather than vague status labels.
4. **Native Speed & Restraint:** Every control feels instantaneous and native to macOS; color and motion communicate state transitions only.
