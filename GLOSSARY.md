# BonLogin

An anti-detect multilogin browser command center and stealth automation environment for managing isolated browser identities.

## Language

**Profile**:
A persistent, isolated browser identity with a deterministic hardware/software fingerprint seed, cookie/storage state, bookmarks, 2FA secret, and optional proxy assignment.
_Avoid_: Account, instance, container

**Workspace**:
The root-scoped local repository holding all profiles, saved proxies, groups, tags, unpacked extensions, recorded flows, and sidecar state files.
_Avoid_: AppData, store, bucket

**RuntimeSupervisor**:
The coordinator governing the live lifecycle of browser sessions—enforcing fail-closed proxy checks on launch, reconciling active windows, and flushing cookies on shutdown regardless of whether a session was started interactively or headless.
_Avoid_: ProcessManager, daemon, runner

**SavedProxy**:
A reusable upstream HTTP or SOCKS5 proxy endpoint managed in the proxy pool, optionally carrying an expiration date, rotation webhook, and cached exit GeoIP.
_Avoid_: ProxyServer, node

**ProxyTunnel**:
A per-session local loopback forwarder that authenticates to a profile's upstream proxy and delegates domain resolution remotely without leaking local DNS.
_Avoid_: VPN, relay

**AgentFlow**:
A recorded, parameterized sequence of semantic browser interactions that replays across profiles without AI token consumption and self-heals when page selectors shift.
_Avoid_: Macro, script, workflow

**BrowserExtension**:
An unpacked Chrome MV3 extension managed in the workspace and loaded into launched profiles with deterministic extension identity.
_Avoid_: Plugin, add-on
