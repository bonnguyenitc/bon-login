---
name: bon-login-agent
description: Full CLI control plane for BonLogin anti-detect browser (profiles, proxies, groups, tags, extensions, kernel, and `agent-browser` automation with Stealth Guardrails).
---

# BonLogin Full CLI & `agent-browser` Control Skill

Every feature in **BonLogin** has a direct CLI subcommand that outputs structured JSON and syncs two-way with the GPUI desktop app.

## 1. Browser & Agent Control (`list`, `launch`, `stop`, `sync`, `agent`)

```bash
# List all profiles with live CDP / agent-browser status (JSON)
bon-login list [--group <g>] [--search <q>]

# Launch a profile (or an entire group) with LocalProxyTunnel + Fail-Closed GeoIP + adryfish Chromium 148
bon-login launch <short_id|name|--group <g>> [--pin-tab <tag>] [--url <url>]

# Run agent-browser with Stealth Guardrails (auto-launches profile if stopped)
bon-login agent <short_id|name> snapshot -i -c
bon-login agent <short_id|name> batch --bail 'fill @e2 "user"' 'click @e3'

# Re-sync newly opened OAuth popups / Web3 extension windows into agent-browser tabs
bon-login sync <short_id|name>

# Stop running profile(s) gracefully (SIGTERM -> flush SQLite cookies -> close tunnel & daemon)
bon-login stop <short_id|name|--group <g>|--all>
```

## 2. Profile Management (`bon-login profile ...`)

```bash
bon-login profile list [--group <g>] [--search <q>]
bon-login profile show <id|name>

# Create profile (proxies are assigned from Proxy Manager via --proxy or --proxy-tag)
bon-login profile create "FB Ads US 01" --os windows --brand chrome --group Facebook --proxy-tag US-Resi

# Update single profile, a whole group, or --all
bon-login profile update <id|name|--group <g>|--all> \
  [--name <n>] [--os macos|windows|linux] [--brand chrome|edge|brave|opera] \
  [--group <g|none>] [--proxy <saved_proxy|none>] [--proxy-tag <tag>] \
  [--seed <u32|random>] [--cores <n>] [--gpu native|seed] \
  [--canvas on|off] [--audio on|off] [--font on|off] [--rects on|off] \
  [--window-size <W,H>] [--timezone <tz|auto>] [--locale <loc|auto>] \
  [--startup-url <url>] [--notes <txt>]

# Clone & Batch Create
bon-login profile clone <id|name> [--count 5] [--name "ClonePrefix"]
bon-login profile batch-create --count 10 --prefix "TikTok" --group TikTok --os windows --proxy-tag VN-ISP

# Check Proxy, Cookies/State Import & Export, Wipe, Delete, Backup & Restore
bon-login profile check-proxy <id|name|--all>
bon-login profile export-cookies <id|name> [--out ./state.json]
bon-login profile import-cookies <id|name> <./cookies.json_or_raw_json>
bon-login profile wipe <id|name>
bon-login profile delete <id|name|--group <g>|--all>
bon-login profile backup [--out ./backup.json]
bon-login profile restore ./backup.json
```

## 3. Proxy Manager (`bon-login proxy ...`)

```bash
bon-login proxy list [--tag <t>]

# Add single proxy or import multi-line proxy file (supports host:port:user:pass:name, socks5://user:pass@host:port)
bon-login proxy add "socks5:160.250.60.55:45042:user1:pass1:VN Proxy 01" --tag VN-ISP --expire +30d
bon-login proxy add ./proxies.txt --protocol socks5 --tag US-Resi --expire 24/12/2026

# Check live GeoIP & latency through LocalProxyTunnel
bon-login proxy check <id|name|--tag <t>|--all>

# Extend expiration (+days), Assign to profiles (round-robin if --tag), or Delete
bon-login proxy extend <id|name|--tag <t>|--all> +30d
bon-login proxy assign <proxy_id|name|--tag <t>> --to <profile_id|name|--group <g>|--all>
bon-login proxy delete <id|name|--tag <t>|--all>
```

## 4. Groups & Proxy Tags (`bon-login group ...` / `bon-login tag ...`)

```bash
bon-login group list
bon-login group add "AirDrop"
bon-login group move <profile_id|name> "AirDrop"
bon-login group delete "AirDrop"

bon-login tag list
bon-login tag add "US-Resi"
bon-login tag delete "US-Resi"
```

## 5. Extensions (`bon-login ext ...`) & Kernel (`bon-login kernel ...`)

```bash
bon-login ext list
bon-login ext enable <id|name>
bon-login ext disable <id|name>
bon-login ext add <local_crx_zip_dir_or_chrome_store_url_or_32char_id>
bon-login ext remove <id|name>
bon-login ext open <ext_id|name> --profile <profile_id|name>

bon-login kernel status
bon-login kernel install
```

## 6. Stealth Guardrails

Never call `agent-browser set viewport|device|geo|media|headers` or `--user-agent|--proxy|--args` on a BonLogin profile—those invoke CDP `Emulation.*` overrides that expose automation on BrowserScan/CreepJS. Always mutate fingerprint or proxy settings via `bon-login profile update` instead.
