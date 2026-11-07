---
name: bon-login-agent
description: Control BonLogin anti-detect browser profiles via `bon-login` CLI and `agent-browser` without breaking C++ stealth fingerprints or leaking DNS/WebRTC.
---

# BonLogin + `agent-browser` Control Skill

Use this skill whenever automating or inspecting anti-detect browser profiles managed by **BonLogin**.

## 1. Headless CLI Control Plane (`bon-login`)

Never launch `Chromium` or `agent-browser` standalone when working with a BonLogin profile—doing so bypasses `LocalProxyTunnel` (SOCKS5/HTTP auth + ATYP `0x03` remote DNS), Fail-Closed GeoIP verification, and `--fingerprint=<seed>`.

Always use the `bon-login` binary (or `cargo run --release --`):

```bash
# 1. List all profiles and live CDP / agent-browser sessions (JSON)
bon-login list

# 2. Launch a profile by short_id, session name (bon_<id8>), or profile name
#    Automatically starts LocalProxyTunnel, verifies GeoIP (Fail-Closed),
#    spawns adryfish Chromium 148, and connects `agent-browser --session bon_<id8> --input-mode human`
bon-login launch <short_id_or_name> [--url https://example.com]

# 3. Create an isolated pinned-tab session for multi-agent parallel work on the same profile
bon-login launch <short_id_or_name> --pin-tab worker1 --url https://x.com

# 4. Run agent-browser with Stealth Guardrails (auto-launches profile if stopped)
bon-login agent <short_id_or_name> snapshot -i -c

# 5. Re-sync newly opened OAuth popups or Web3 extension windows into agent-browser tabs
bon-login sync <short_id_or_name>

# 6. Gracefully stop a profile (SIGTERM -> flushes SQLite cookies -> closes tunnel & daemon)
bon-login stop <short_id_or_name>
bon-login stop --all
```

## 2. Fast `agent-browser` Patterns (`--session bon_<id8>`)

Once launched, each profile is bound to session `bon_<id8>` with `--input-mode human`, `AGENT_BROWSER_IDLE_TIMEOUT_MS=0`, and isolated downloads in `~/Library/Application Support/com.bonlogin.app/downloads/bon_<id8>/`.

- **Semantic Accessibility Snapshot (80–95% fewer tokens than HTML):**
  ```bash
  agent-browser --session bon_<id8> snapshot -i -c
  ```
- **Batch Form Fill & Click in One Round-Trip:**
  ```bash
  agent-browser --session bon_<id8> batch --bail \
    'fill @e2 "user@example.com"' \
    'fill @e3 "secret"' \
    'click @e4'
  ```
- **Set-of-Mark (SoM) Visual Annotation for Canvas / Captcha / WebGL:**
  ```bash
  agent-browser --session bon_<id8> screenshot --annotate
  ```
- **Interacting with Chrome Extensions & Wallets (MetaMask, Phantom, CapSolver):**
  BonLogin patches unpacked extensions so popup/options pages work as normal tabs while `chrome.tabs.query({active: true})` still resolves the active web tab:
  ```bash
  bon-login sync <id8>
  agent-browser --session bon_<id8> tab
  ```

## 3. Stealth Guardrails (NEVER Run These Commands)

`adryfish/fingerprint-chromium` spoofs hardware, screen, UA, Client Hints, WebGL, Audio, and Timezone at the **C++ Blink/V8 layer**.

**NEVER** invoke the following `agent-browser` commands/flags on a BonLogin session, because they trigger CDP `Emulation.*` or `Network.*` overrides detectable by CreepJS, BrowserScan, Cloudflare Turnstile, and DataDome:

- ❌ `agent-browser set viewport ...`
- ❌ `agent-browser set device ...`
- ❌ `agent-browser set geo ...`
- ❌ `agent-browser set media ...`
- ❌ `agent-browser set headers ...`
- ❌ `agent-browser --user-agent ...` / `--proxy ...` / `--args ...`

(`bon-login agent <id8> ...` automatically blocks these forbidden flags/subcommands.)
