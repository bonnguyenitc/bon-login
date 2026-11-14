# 006 — IP quality gate, human behavior engine, and profile trust ramp

- **Status**: DONE
- **Commit**: be48bcd
- **Severity**: HIGH
- **Category**: Anti-detection — network reputation & behavior (new audit axis)
- **Estimated scope**: `src/models.rs`, `src/geoip.rs`, `src/db.rs`, `src/launcher.rs`, `src/control.rs` (`print_cli_help` + `parse_profile_cli_flags`), `src/human.rs` *(new)*, `src/bookmarks.rs`, `src/ui/profile_list.rs`, `src/ui/profile_modal.rs`, `src/ui/actions.rs`, `README.md`, `CLAUDE.md`

## Problem

BonLogin already defeats *browser-level* bot checks, but a freshly created profile is still flagged by
platform risk engines (抖音 / 小红书 / TikTok web) because three human signals are missing.

1. **No IP reputation signal.** `GeoInfo` (`src/models.rs:425-433`) only carries
   `ip, country_code, timezone, locale, accept_lang, latency_ms`. It cannot tell a residential
   connection from an AWS/Vultr datacenter IP, has no `city` (抖音 exposes `IP归属地`), no ASN, and no
   abuse/fraud score. A perfect fingerprint on a hosting IP is still an instant flag — this is the
   single largest detection vector left. `resolve_geo_via_port` (`src/geoip.rs:158-162`) only asks for
   country/timezone, even though the `ip-api.com` fallback already supports `proxy,hosting,mobile,city,as,isp`
   for the same request budget.
2. **Zero behavioral signal.** `run_cookie_robot_warmup_in` (`src/launcher.rs:3298-3355`) performs
   exactly: `open url → sleep 800ms → scroll down 420px → sleep dwell → scroll up 160px`. No mouse
   movement, no hover, no focus/blur, no key events, no variable scroll inertia, no reading dwell
   distribution. A brand-new account that opens a feed with no pointer movement, a fixed 420px scroll
   and then idles is trivially classified as automation by client-side risk SDKs.
3. **No device/account age model.** New profiles are byte-identical to a fresh Chromium install
   (0 cookies, 0 history, empty `Local State`) and nothing stops an operator from publishing on day 0.
   There is no `trust_stage`, no accumulated attention minutes, and no gate on "too young to publish".
4. **Argument hygiene gaps** in `build_chromium_args_with_extensions` (`src/launcher.rs:651-787`):
   - No `--disable-breakpad` / `--disable-crash-reporter` / `--disable-background-networking` /
     `--disable-component-update` / `--no-pings` / `--disable-domain-reliability`, so crashpad and
     component updater run and can reach the network outside the tunnel.
   - `--disable-features` is emitted only conditionally (line 744). Any future flag added elsewhere
     silently overrides it, because duplicate `--disable-features` switches do not merge.
   - `GpuSpoofMode::NativePassthrough` + `os_platform != MacOS` is an incoherent combination
     (a "Windows" browser reporting an Apple Metal GPU). `disabled_spoofing_csv`
     (`src/models.rs:901-917`) emits `gpu` regardless of platform.
   - Chromium 148 rejects `--disable-blink-features=AutomationControlled` and shows an unsupported-flag
     infobar. Do not pass it. README line 39 is the `Runtime.enable` row, unrelated.

## Target

### Phase 0 — Argument hygiene & coherence guard (done)

1. One `--disable-features=` on every launch: always `OptimizationHints`; append
   `DisableLoadExtensionCommandLineSwitch` only when `--load-extension` is set. Chromium keeps the last
   value and does not merge duplicates. Keep `Translate` **enabled**.
2. Telemetry flags: `--disable-breakpad`, `--disable-crash-reporter`, `--disable-background-networking`,
   `--disable-component-update`, `--no-pings`, `--disable-domain-reliability`, plus
   Không truyền `--disable-blink-features=AutomationControlled`: Chromium 148 hiện infobar "cờ không được hỗ trợ". `navigator.webdriver` vẫn false vì không có `--enable-automation`.
3. `disabled_spoofing_csv()` pushes `gpu` only for macOS + `NativePassthrough`.
   `gpu_coherence_warning()` is shown on the hardware tab when the platform is not macOS.
   `parse_profile_cli_flags` coerces Windows/Linux + `--gpu native` back to seed GPU.

### Phase 1 — IP quality gate (done)

1. Extend `GeoInfo` with `#[serde(default)]` fields so existing serialized profiles keep deserializing:
   `city`, `region`, `asn`, `isp`, `ip_kind: IpKind`, `is_hosting: Option<bool>`, `is_mobile: Option<bool>`.
   No `abuse_score` — none of the current free providers return one. Add:
   ```rust
   pub enum IpKind { Unknown, Residential, Business, Mobile, Hosting }
   ```
2. Keep the existing 3-way race in `resolve_geo_via_port` (first success wins). Do **not** switch the
   primary to `ip-api.com` (HTTP-only, 45 req/min, non-commercial ToS). Widen each parser to keep
   city/ASN/`hosting` when that body has them (`ipwho.is` `security.hosting` + `connection.asn`,
   `ip-api.com` `hosting,proxy,mobile,as,isp,city`). A body with no hosting bit stays `IpKind::Unknown`.
   **Unknown never blocks a launch.** Fail-Closed stays "proxy dead", not "metadata missing".
3. `ip_reputation` cache (`ip TEXT PRIMARY KEY, payload TEXT, checked_at INTEGER`), TTL 24h, so profiles
   that share an exit IP pay for one lookup.
4. `Profile.ip_policy: IpPolicy` (`Any` default, `NoHosting`, `ResidentialOrMobile`) via
   `ALTER TABLE profiles ADD COLUMN ip_policy TEXT NOT NULL DEFAULT 'any'`.
   CLI values are exactly `any|no-hosting|residential` (one name, not a second enum spelling).
5. Enforce only on a **fresh** probe that actually contains a hosting bit, before spawn, for proxy
   launches (those already re-probe). Direct launches that skip probe because geo is cached
   (`launch_profile_with_kernel_in`, no-proxy branch) stay `Unknown` and launch.
   Error shape: `"Proxy check failed (Fail-Closed): exit IP 1.2.3.4 is Hosting (AS16509 Amazon), policy requires residential"`.
6. Shared-IP guard (warning only): same exit IP on other non-deleted profiles, plus same `proxy_id`
   when that is the operator-visible signal. Row badge only, not a launch block.
7. Surfaces: profile row + drawer (`Residential · Hangzhou` / `Hosting`), proxy pool column,
   editor + CLI `--ip-policy <any|no-hosting|residential>` on `profile create|update`, and `print_cli_help`.

### Phase 2 — Human behavior engine + trust ramp (done)

1. New `src/human.rs`. Distribution is stable per identity, paths are not: seed
   `StdRng` from `profile.seed` mixed with the session counter (or UTC day). A path replayed from
   `seed` alone is itself a signature. No `thread_rng()`.
2. Primitives dispatched through the existing in-process `CdpClient` (`src/launcher.rs:1904`) — **never**
   through `agent-browser`, and never `Runtime.enable` / `Emulation.*`:
   - `mouse_path(from, to)` — cubic Bézier + jitter + slight overshoot + micro-pauses, emitted as
     `Input.dispatchMouseEvent` `mouseMoved` with `buttons: 0`. `CdpClient::call` is one round-trip
     per event (600ms read timeout), so pace with sleeps the way sync already does. Do not target 90 Hz.
   - `click_at(x, y)` — `mouseMoved → mousePressed(buttons:1) → mouseReleased`, 40-120 ms hold,
     `clickCount: 1`.
   - `scroll(direction, px)` — 8-20 `mouseWheel` events with decaying `deltaY` (inertia), random
     120-600 ms gaps, occasional 1-2 event reverse ("回看").
   - `dwell(kind)` — log-normal seconds (feed video 8-95 s, article 20-180 s, profile page 3-12 s).
   - `type_text(..)` — replace the fixed `20ms` in `cdp_type_as_human` (`src/launcher.rs:2255`) with
     45-180 ms jitter, 250-600 ms pause after punctuation.
   - `idle(..)` — small pointer drift. `Page.bringToFront` is allowed. No focus/blur API:
     `Emulation.setFocusEmulationEnabled` is banned by `validate_stealth_agent_args`.
   Each primitive clamps coordinates to the last known viewport (`Page.getLayoutMetrics`, command only,
   no enable) and no-ops on a zero-size viewport.
3. Replace the internals of `run_cookie_robot_warmup_in` (`src/launcher.rs:3298`) with these primitives
   while keeping its signature, CLI (`profile warmup`) and cookie-export tail unchanged.
4. Trust ramp: `Profile.trust_stage: TrustStage { New, Warming, Mature, Restricted, Banned }` +
   `seeded_at: Option<i64>`; new table
   `profile_activity(profile_id TEXT, day TEXT, attention_seconds INTEGER, sessions INTEGER, PRIMARY KEY(profile_id, day))`,
   written from warmup and from supervisor session duration. There is no publish action in the app.
   `can_publish()` and any disabled publish button belong to plan 007, not this plan.

### Phase 3 — Profile seeding & audit report (done)

1. `bon-login profile seed <id|name>` + UI action: **one** warmup pass over a locale-appropriate public
   list, then record `seeded_at`. Not a multi-day daemon. Days of trust come from `profile_activity`.
2. `bon-login audit <id|name>` — extend the existing `bon://preflight` card with IP kind/ASN/city,
   timezone & locale coherence, WebRTC status, and `navigator.webdriver`; capture a PNG via
   `cdp_screenshot` plus a JSON sidecar under `audits/<short_id>-<ts>.{png,json}` for before/after
   comparison.

## Repo conventions to follow

- Keep the "no JS injection" rule: every new signal comes from C++ kernel flags, CDP `Input.*`, or the
  profile tunnel — never `Object.defineProperty`, `Runtime.enable`, or `Emulation.*`
  (`validate_stealth_agent_args`, `src/launcher.rs:2980`).
- New `GeoInfo`/`Profile` fields use `#[serde(default)]` and new columns use the `ALTER TABLE` list in
  `src/db.rs:579-592` so existing databases migrate silently.
- Probe/launch failures keep the `(Fail-Closed): <reason>` suffix so UI and tests match on it.
- Deterministic randomness goes through `seed`-derived `StdRng`, never `thread_rng()` in behavior code.
- UI status colors: reuse `Profile::tag_badge_colors` semantics — emerald only for verified-good state.

## Steps

1. **Phase 0 (done)** — one `--disable-features`, telemetry flags, no `AutomationControlled`,
   `gpu` only on macOS in `disabled_spoofing_csv`, `gpu_coherence_warning()` on the hardware tab,
   CLI coerces non-macOS `--gpu native`, README line 116 + `CLAUDE.md` sample match the spawn args.
   Tests: `test_chromium_args_one_disable_features_and_windows_native_gpu`,
   `test_windows_native_gpu_is_not_passthrough`.
2. **Phase 1a** — extend `GeoInfo` + `IpKind`; update `parse_ipapi_json` / `parse_ipwho_json` field mapping;
   add fixture tests with real `hosting:true` and `mobile:true` payloads.
3. **Phase 1b** — add `ip_reputation` table + cache read/write; add `ip_policy` column, `IpPolicy` enum,
   CLI flag parsing in `parse_profile_cli_flags` (`src/control.rs:104`).
4. **Phase 1c** — enforce the policy + shared-IP warning in `launch_profile_with_kernel_in`; add tests:
   hosting IP + `NoHosting` ⇒ `Err` containing `Fail-Closed`, `Unknown` ⇒ launch proceeds.
5. **Phase 2a** — add `src/human.rs` primitives + unit tests (path stays in bounds, wheel sum matches
   requested pixels, deterministic across two runs with the same seed).
6. **Phase 2b** — rewire `run_cookie_robot_warmup_in` to use them; add an integration-style test that
   asserts the produced CDP method names are a subset of `{Input.dispatchMouseEvent, Page.getLayoutMetrics,
   Page.bringToFront, Page.navigate}` (mirrors the existing `Runtime.enable` assertion at `src/launcher.rs:5992`).
7. **Phase 2c** — add `trust_stage`, `seeded_at`, `profile_activity`; show the trust stage on the profile
   row. Do not add `can_publish()` or a publish control here.
8. **Phase 3** — `profile seed` CLI/UI and `audit` command + report writer.

## Boundaries

- Do NOT implement like/comment/follow/DM automation in this plan. Phase 2 is **passive viewing only**
  (move, scroll, dwell, type into a field the operator already navigated to).
- Do NOT increase concurrency defaults; behavior loops must sleep, not busy-spin.
- Do NOT mutate `--fingerprint=<seed>` semantics, kernel files, or `resolved_geo` for existing profiles.
- Do NOT block launches on `IpKind::Unknown` (provider outage must not brick the app).
- Do NOT add JS shims for `webdriver`/plugins/languages — the C++ kernel already owns that layer.

## Verification

- **Mechanical**: `cargo test --quiet` passes, including the new arg, parser, policy, and determinism tests.
- **Phase 0**: launch a Windows profile with `NativePassthrough` — no `gpu` inside `--disable-spoofing=`;
  `ps -o command= -p <pid>` shows exactly one `--disable-features=` and no crashpad handler upload.
- **Phase 1**: `bon-login audit <profile>` against a known AWS IP reports `Hosting` + ASN; with
  `--ip-policy residential` the launch aborts with `(Fail-Closed): ... Hosting`; against a residential
  proxy the same profile launches and the row badge turns emerald.
- **Phase 2**: screen-record a warm-up session — pointer path is curved with stops, scroll has inertia,
  dwell varies; `bon-login agent <id> eval "navigator.webdriver"` still returns `false`; CreepJS
  `trustScore` does not regress versus the `be48bcd` baseline.
- **Phase 3**: one `profile seed` pass leaves cookies or history and sets `seeded_at`. Trust stage
  moves off `New` only after `profile_activity` has attention on more than one day.
- **Done when**: three consecutive new profiles pass Phase 0-2 checks, a probe that included a hosting
  bit shows that kind plus city/timezone on the audit card, `Unknown` still launches, and dead proxies
  still Fail-Closed.

## Open questions

1. Do not make free `ip-api.com` the primary probe. Parse hosting from whichever raced response has the
   bit. A paid provider can replace the parsers later; `Unknown` must still launch.
2. `NoHosting` stays opt-in (`Any` default), not a new-profile default.
3. Behavior amplitude needs field tuning per platform; ship constants in one table in `human.rs` so
   tuning does not touch call sites.
