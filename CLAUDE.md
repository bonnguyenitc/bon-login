# BonLogin — Architecture & Engineering Constitution (`CLAUDE.md`)

> **Mục tiêu tối thượng:** Xây dựng ứng dụng Anti-Detect / Multilogin Browser Desktop cho **macOS** viết **thuần 100% bằng Rust (`GPUI`)**, điều khiển nhân **`adryfish/fingerprint-chromium`** và tương thích hoàn toàn với **`Patchright`** cũng như **`agent-browser`** (hoặc chạy trực tiếp không qua Node/Python daemon).
>
> Tài liệu này là **hiến pháp kỹ thuật** chống lan man (anti-scope-creep). Mọi quyết định thiết kế và code phải tuân thủ nghiêm ngặt các quy tắc dưới đây.

---

## 1. Triết lý & Ranh giới Kiến trúc (Non-Negotiables)

1. **100% Pure Rust trên Desktop (macOS-first):**
   - Giao diện người dùng: **`gpui-kit = "0.9.0"`** (gói tích hợp chính thức từ `longbridge/gpui-component` gồm `gpui-pre = "=0.3.11"`, `gpui-component` và `gpui-kit-assets`, render GPU 120fps).
   - **KHÔNG** nhúng Electron, Tauri/WebView, Python runtime hay Node.js runtime để mở trình duyệt cơ bản.
2. **Cách kết hợp `fingerprint-chromium` + `Patchright` + `agent-browser` trong kiến trúc Pure Rust:**
   - **Khi người dùng mở Profile thủ công (Manual Multilogin):** Rust trực tiếp spawn tiến trình `Chromium.app` (`adryfish/fingerprint-chromium`) với bộ cờ **Patchright Stealth Args** (`--disable-blink-features=AutomationControlled`, bỏ `--enable-automation`, `--no-first-run`, `--fingerprint=<seed>`, v.v.) + mở sẵn `--remote-debugging-port=<cdp_port>`. Vì không có trình điều khiển nào gửi `Runtime.enable`, trình duyệt đạt độ tàng hình **100% giống hoặc cao hơn Patchright** mà tốn **0MB RAM** phụ trợ.
   - **Khi người dùng chạy kịch bản tự động hóa (`Patchright` hoặc `agent-browser`):**
     - **Với `Patchright` (Kịch bản code cố định Python/Node):** Rust cung cấp `http://127.0.0.1:<cdp_port>` (hoặc đọc `ws://...` từ `<user-data-dir>/DevToolsActivePort`) để `connect_over_cdp` nối thẳng vào profile đang mở.
     - **Với `vercel-labs/agent-browser` (`v0.41.2` — AI Agent tự hành):** Nhờ nhân C++ của `adryfish/fingerprint-chromium` đã vá sẵn leak `Runtime.enable`, CLI kết nối qua full WebSocket URL đọc từ `DevToolsActivePort`: `agent-browser --session bon_<id8> --input-mode human connect "ws://127.0.0.1:<cdp_port><ws_path>"` (kèm `AGENT_BROWSER_IDLE_TIMEOUT_MS=0`, cô lập thư mục tải về `downloads/bon_<id8>`, và `--pin-tab` nếu chạy đa agent trên cùng profile). Cách truyền thẳng `ws://...` giúp tránh lỗi `/json/version` 404 hoặc prompt trùng trên Chromium 144+ (Issue `#628`, `#1210`). Khi AI gọi `agent-browser close`, nó chỉ ngắt kết nối daemon chứ không tắt trình duyệt của người dùng.
     - **Headless CLI Control Plane & Stealth Guardrails (`bon-login list|launch|stop|sync|agent`):** Binary `bon-login` hỗ trợ AI Agent điều khiển trực tiếp từ terminal (`bon-login list`, `bon-login launch <id|name> [--pin-tab <tag>] [--url <u>]`, `bon-login sync <id>`, `bon-login stop <id|--all>`, và `bon-login agent <id> <args...>`). Chế độ `bon-login agent` tự động chặn các cờ/lệnh CDP `Emulation.*` làm lộ vân tay (`set viewport|device|geo|media|headers`, `--user-agent`, `--proxy`) và đồng bộ trạng thái 2 chiều với giao diện GPUI qua `bon_runtime.json`.
     - **KHÔNG nhúng `jev-ultrafast` vào lõi:** Vì `jev-ultrafast` gọi `Emulation.setDeviceMetricsOverride` và tiêm `window.__jevFast` vào Main World, làm hỏng vân tay Viewport/DOM trên BrowserScan/CreepJS.
3. **Giải quyết triệt để 6 "Bẫy" thực tế của `adryfish/fingerprint-chromium` ngay trong nhân Rust:**
   - **Bẫy 1 (Proxy có `user:pass`, SOCKS5 Auth & Rò rỉ DNS):** Chromium CLI (`--proxy-server`) không nhận `user:pass`. BonLogin giải quyết bằng **Module `proxy_tunnel` viết thuần bằng `tokio` trong Rust**: Mở một cổng local `http://127.0.0.1:<ephemeral_port>` không mật khẩu cho từng Profile đang chạy, tự động đóng gói xác thực chuyển tiếp lên upstream `HTTP Proxy` (kèm header `Proxy-Authorization: Basic ...`) hoặc `SOCKS5 Proxy` (RFC 1928/1929 Username/Password handshake). **Tuyệt đối không phân giải DNS ở máy Mac**: với SOCKS5 phải gửi thẳng tên miền (ATYP `0x03` Domain Name) cho proxy từ xa tự phân giải, đồng thời truyền cờ `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` cho Chromium để chặn đứt mọi rò rỉ DNS local.
   - **Bẫy 2 (Lộ thương hiệu `Chromium` & lệch `platform-version` trong Client Hints):** Luôn ép cứng `--fingerprint-brand=Chrome`, `--fingerprint-brand-version=<exact_chromium_version>` (ví dụ `148.0.7778.215`), và truyền khớp `--fingerprint-platform-version=<os_version>` (ví dụ Windows 11 = `15.0.0`, macOS = `15.2.0`) để không bị CreepJS/PixelScan bắt lỗi OS Mismatch.
   - **Bẫy 3 (Lệch GPU trên BrowserScan khi chạy macOS):** Trên macOS Apple Silicon / Intel có GPU thật, mặc định bật `--disable-spoofing=gpu` (cho phép WebGL/WebGPU passthrough phần cứng thật của Mac, xanh 100% trên BrowserScan) trong khi **vẫn giữ nguyên** C++ noise cho Canvas, Audio, Fonts, ClientRects, CPU, RAM theo `--fingerprint=<seed>`. Nếu người dùng chọn giả lập Windows (`--fingerprint-platform=windows`), mới bật GPU spoofing của `adryfish`.
   - **Bẫy 4 (Rò rỉ WebRTC qua STUN/Interface phụ trên macOS):** Ngoài `--disable-non-proxied-udp` và `--webrtc-ip-handling-policy=disable_non_proxied_udp`, luôn khóa cứng thêm `--force-webrtc-ip-handling-policy` và `--enforce-webrtc-ip-permission-check`.
   - **Bẫy 5 (Mở trình duyệt khi Proxy đã chết — Fail-Open):** Luôn áp dụng nguyên tắc **Fail-Closed**: Nếu Profile có cấu hình Proxy, bắt buộc phải khởi chạy `LocalProxyTunnel` trước rồi đi qua chính tunnel đó gọi `geoip` (timeout `8s`). Nếu proxy chết, sai mật khẩu hoặc timeout $\rightarrow$ hủy tunnel ngay, **tuyệt đối không spawn Chromium** và báo lỗi đỏ trên dòng Profile.
   - **Bẫy 6 (Race condition cổng CDP, Socket Leak & Tiến trình mồ côi):**
     - **CDP Port:** Không dùng `TcpListener` xin port rồi đóng (dễ bị race condition khi mở nhiều profile cùng lúc). Truyền thẳng `--remote-debugging-port=0` để chính Chromium tự bind port trống và ghi vào dòng 1 của `<user-data-dir>/DevToolsActivePort`, sau đó Rust đọc file này để lấy chính xác `cdp_port` và `ws_url`.
     - **Chống Socket Leak:** Mọi kết nối từ `proxy_tunnel` lên upstream phải bọc `tokio::time::timeout(10s)` khi bắt tay và quản lý trong `JoinSet` (hoặc `AbortHandle`) của phiên đó để hủy sạch ngay khi Chromium thoát.
     - **Graceful Shutdown:** Khi đóng BonLogin mà còn Profile đang chạy, gửi `SIGTERM` cho toàn bộ Chromium PID để trình duyệt flush sạch SQLite Cookies xuống đĩa trước khi đóng `proxy_tunnel`.

---

## 2. Sơ đồ Kiến trúc & Luồng Khởi chạy (System Architecture & Launch Flow)

```
+-----------------------------------------------------------------------------------+
|                            BonLogin Desktop App (GPUI)                            |
|  +-----------------------------------------------------------------------------+  |
|  | Header Bar: Kernel Status (Chromium 148) | [+ New Profile]                  |  |
|  +-----------------------------------------------------------------------------+  |
|  | Single Main Workspace (No extra sidebar tabs)                               |  |
|  | - Profile Table (Name, OS, Proxy, Exit IP/Geo, Runtime State & CDP Port)    |  |
|  | - Row Actions: [Launch/Stop] [Check Proxy] [Copy CDP / Agent CLI] [Edit]    |  |
|  | - Create / Edit Profile Modal (Inline Proxy input + Seed/OS/GPU settings)   |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                         Core Services Layer (Pure Rust)                           |
|                                                                                   |
|  +-------------------+   +----------------------+   +--------------------------+  |
|  | Storage (SQLite)  |   | Proxy & GeoIP Engine |   | Process & CDP Supervisor |  |
|  | - Single table:   |   | - Tokio Local Tunnel |   | - Locate & unquarantine  |  |
|  |   `profiles`      |   |   (ATYP 0x03 domain, |   |   Chromium.app           |  |
|  |   (proxy & geo    |   |    10s timeout,      |   | - Spawn with --remote-   |  |
|  |    stored inline) |   |    JoinSet cleanup)  |   |   debugging-port=0       |  |
|  |   (rusqlite)      |   | - Fail-closed GeoIP  |   | - Read DevToolsActivePort|  |
|  +-------------------+   +----------------------+   +--------------------------+  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|              External Binary & Isolated Profile Directories (macOS)               |
|  ~/Library/Application Support/com.bonlogin.app/                                  |
|  ├── bonlogin.sqlite3                  # Cơ sở dữ liệu cấu hình                   |
|  ├── kernels/                                                                     |
|  │   └── chromium-148.0.7778.215/      # adryfish/fingerprint-chromium (macOS)    |
|  │       └── Chromium.app/Contents/MacOS/Chromium                                 |
|  └── profiles/                                                                    |
|      ├── <profile-uuid-1>/             # --user-data-dir cô lập hoàn toàn         |
|      └── <profile-uuid-2>/                                                        |
+-----------------------------------------------------------------------------------+
```

### Luồng Khởi chạy Fail-Closed & Kết nối CDP (`agent-browser` / `Patchright`)

```mermaid
sequenceDiagram
    autonumber
    actor User as User / AI Agent
    participant UI as GPUI Desktop (gpui-kit 0.9.0)
    participant DB as SQLite (db.rs - 1 table `profiles`)
    participant Tunnel as LocalProxyTunnel (proxy_tunnel.rs)
    participant Geo as GeoIP Engine (geoip.rs)
    participant Sup as Process Supervisor (launcher.rs)
    participant Chr as adryfish Chromium 148
    participant Agent as agent-browser / Patchright

    User->>UI: Click [Launch] trên Profile
    UI->>DB: Đọc Profile (seed, os, proxy, gpu_spoofing)
    alt Có cấu hình Proxy (HTTP / SOCKS5 user:pass)
        UI->>Tunnel: Bind 127.0.0.1:0 (JoinSet + 10s handshake timeout)
        Tunnel-->>UI: local_proxy_port (VD: 58123)
        UI->>Geo: Check IP/Timezone qua http://127.0.0.1:58123 (timeout 8s)
        alt Proxy chết / Timeout (Fail-Closed)
            Geo-->>UI: Err(ProxyDead)
            UI->>Tunnel: abort_all() & đóng port ngay
            UI-->>User: Báo lỗi đỏ trên dòng Profile (KHÔNG mở Chromium)
        else Proxy sống
            Geo-->>UI: Ok(GeoInfo { ip, timezone, locale, country })
            UI->>DB: Lưu cache resolved_geo
        end
    end
    UI->>Sup: Xóa DevToolsActivePort cũ & Spawn Chromium (--remote-debugging-port=0)
    Sup->>Chr: Truyền cờ adryfish + Patchright Stealth + --host-resolver-rules
    Chr-->>Sup: Ghi <port> (dòng 1) & <ws_path> (dòng 2) vào DevToolsActivePort
    Sup-->>UI: Running { pid, cdp_port, ws_url, tunnel_port }
    User->>UI: Click [Copy Agent CLI]
    UI-->>User: agent-browser --session bon_<id8> --input-mode human connect "ws://127.0.0.1:<port><ws_path>"
    User->>Agent: Chạy lệnh connect / snapshot -i / click @e1
    Agent->>Chr: Điều khiển qua CDP (C++ đã vá Runtime.enable -> 100% Stealth)
```

---

## 3. Cấu trúc Thư mục Dự án

Tuyệt đối giữ cấu trúc phẳng, rõ ràng, không tạo abstraction thừa:

```text
bon-login/
├── AGENTS.md                  # Ponytail ruleset (lazy senior dev mode)
├── CLAUDE.md                  # File kiến trúc & quy tắc chống lan man này
├── Cargo.toml                 # Dependencies tối giản, biên dịch nhanh
└── src/
    ├── main.rs                # Điểm vào GPUI App, khởi tạo Window & SIGTERM cleanup hook
    ├── models.rs              # Structs: Profile, ProxyConfig, GeoInfo, RuntimeSession & AppState
    ├── db.rs                  # SQLite CRUD (rusqlite) với duy nhất 1 bảng `profiles`
    ├── proxy_tunnel.rs        # Tokio local HTTP proxy -> Upstream HTTP/SOCKS5 (ATYP 0x03, JoinSet)
    ├── geoip.rs               # Kiểm tra Proxy qua local tunnel (timeout 8s) -> IP, Timezone, Locale
    ├── launcher.rs            # Định vị/xattr Chromium.app, build flags, spawn & đọc DevToolsActivePort
    └── ui/
        ├── mod.rs             # Layout chính (Header + Profile Table + Modal, không làm Sidebar thừa)
        ├── theme.rs           # Bảng màu Dark Mode hiện đại, sắc nét
        ├── profile_list.rs    # Bảng Profile + Launch/Stop/Check Proxy/Copy CDP & Agent CLI
        └── profile_modal.rs   # Form Tạo / Sửa Profile (Random Seed, OS, Proxy, GPU mode)
```

---

## 4. Thiết kế Chi tiết các Module Lõi

### 4.1. Data Model & Single-Table SQLite (`src/models.rs` & `src/db.rs`)

Chỉ sử dụng **duy nhất 1 bảng `profiles`** trong SQLite (lưu inline các cột proxy và geo, không tách bảng `proxies` hay `app_settings` dư thừa). Mỗi `Profile` chứa đầy đủ thông tin để tái tạo chính xác 1 máy tính duy nhất qua nhiều tháng:

- `id`: `String` (UUID v4)
- `name`: `String` (VD: `"FB Ads - US 01"`)
- `group_tag`: `String` (VD: `"Facebook"`, `"TikTok"`, `"AirDrop"`)
- `seed`: `u32` (Số nguyên 32-bit sinh ngẫu nhiên lúc tạo profile, truyền vào `--fingerprint=<seed>`)
- `os_platform`: `PlatformType` (`MacOS` | `Windows` | `Linux`)
- `os_version`: `String` (Mặc định `"15.2.0"` cho macOS, `"15.0.0"` cho Windows 11 — truyền vào `--fingerprint-platform-version`)
- `brand`: `BrowserBrand` (`Chrome` | `Edge` — mặc định `Chrome`)
- `brand_version`: `String` (Mặc định `"148.0.7778.215"`)
- `hardware_concurrency`: `u8` (`4`, `8`, `10`, `12`, `16`)
- `gpu_spoofing`: `GpuSpoofMode` (`NativePassthrough` -> `--disable-spoofing=gpu` | `SeedGenerated` -> để `adryfish` tự fake)
- `proxy`: `Option<ProxyConfig>`:
  - `protocol`: `Http` | `Socks5`
  - `host`: `String`
  - `port`: `u16`
  - `username`: `Option<String>`
  - `password`: `Option<String>`
- `resolved_geo`: `Option<GeoInfo>` (Lưu cache kết quả check proxy: `ip`, `timezone`, `locale`, `country_code`)
- `startup_url`: `String` (Mặc định `"https://browserscan.net"` để kiểm tra vân tay ngay khi mở)
- `notes`: `String`
- `created_at` / `last_launched_at`: `i64` (Unix timestamp)

### 4.2. Giải bài toán Proxy Auth, Chống DNS Leak & Socket Leak (`src/proxy_tunnel.rs`)

Khi Profile có `ProxyConfig`:

1. `LocalProxyTunnel::start(proxy_config)` bind một `tokio::net::TcpListener` tại `127.0.0.1:0` (OS tự cấp port trống, ví dụ `58123`) và quản lý toàn bộ kết nối con trong một `tokio::task::JoinSet` (kèm `CancellationToken` / `AbortHandle`).
2. Nhận kết nối HTTP `CONNECT host:port HTTP/1.1` hoặc HTTP thường từ Chromium. Mọi bước mở kết nối tới upstream proxy đều bọc `tokio::time::timeout(Duration::from_secs(10), ...)` để chống treo socket.
3. Nếu upstream là **HTTP Proxy**: Mở TCP tới `upstream_host:upstream_port`, gửi `CONNECT target_host:target_port HTTP/1.1\r\nHost: target_host:target_port\r\nProxy-Authorization: Basic <base64>\r\n\r\n`, sau khi nhận `200` thì dùng `tokio::io::copy_bidirectional` nối thông 2 chiều.
4. Nếu upstream là **SOCKS5 Proxy**: Thực thi RFC 1928/1929 nối tới `upstream_host:upstream_port`, gửi gói `CONNECT` với **ATYP = `0x03` (Domain Name)** chứa nguyên chuỗi `target_host` (tuyệt đối không phân giải DNS ở máy Mac) để SOCKS5 server từ xa tự phân giải DNS, trả về `HTTP/1.1 200 Connection Established\r\n\r\n` cho Chromium rồi `copy_bidirectional`.
5. Khi Chromium dừng (hoặc bị tắt), `LocalProxyTunnel::stop()` gọi `join_set.abort_all()` giải phóng ngay lập tức cả cổng listener lẫn toàn bộ kết nối TCP đang mở.

### 4.3. Tự động đồng bộ GeoIP theo cơ chế Fail-Closed (`src/geoip.rs`)

Trước khi mở trình duyệt (hoặc khi bấm nút **"Check Proxy"**):

1. Bắt buộc đi qua chính `http://127.0.0.1:<local_proxy_port>` vừa bật của profile đó (với timeout tổng `8s`) gọi theo chuỗi fallback HTTPS chống bị chặn IP/rate-limit:
   - Ưu tiên 1: `https://ipwho.is/`
   - Ưu tiên 2: `https://ipinfo.io/json`
   - Ưu tiên 3 (Fallback): `http://ip-api.com/json/?fields=status,message,countryCode,query,timezone`
2. **Fail-Closed:** Nếu cả 3 nguồn đều lỗi (proxy chết, sai user/pass, hết băng thông) $\rightarrow$ trả về `Err`, đóng `LocalProxyTunnel` ngay lập tức và **không mở Chromium** để tránh lộ IP/sai lệch múi giờ.
3. Khi thành công, lưu cache `GeoInfo` vào bảng `profiles` và tự động suy ra:
   - `timezone`: VD `"America/Los_Angeles"` $\rightarrow$ truyền vào `--timezone=America/Los_Angeles`
   - `locale` & `accept_lang`: Từ `countryCode` (VD `US` $\rightarrow$ `en-US,en`, `VN` $\rightarrow$ `vi-VN,vi,en-US`, `JP` $\rightarrow$ `ja-JP,ja,en-US`) $\rightarrow$ truyền vào `--lang` và `--accept-lang`.

### 4.4. Bộ cờ chuẩn kết hợp `adryfish` + `Patchright` + `agent-browser` (`src/launcher.rs`)

Trước khi spawn, xóa file `<user-data-dir>/DevToolsActivePort` cũ (nếu có). Hàm `build_chromium_args(profile, local_proxy_port, user_data_dir)` sinh chính xác các cờ sau:

```rust
vec![
    // 1. Cô lập dữ liệu Profile
    format!("--user-data-dir={}", user_data_dir.display()),
    // 2. Cờ nhân adryfish/fingerprint-chromium (Fix Bẫy 2 & 3)
    format!("--fingerprint={}", profile.seed),
    format!("--fingerprint-platform={}", profile.os_platform.as_cli_str()),
    format!("--fingerprint-platform-version={}", profile.os_version),
    format!("--fingerprint-brand={}", profile.brand.as_cli_str()), // Luôn là "Chrome"
    format!("--fingerprint-brand-version={}", profile.brand_version),
    format!("--fingerprint-hardware-concurrency={}", profile.hardware_concurrency),
    format!("--timezone={}", timezone),
    format!("--lang={}", locale),
    format!("--accept-lang={}", accept_lang),
    // Nếu trên macOS muốn BrowserScan xanh 100% GPU:
    // "--disable-spoofing=gpu" (khi GpuSpoofMode::NativePassthrough)
    // 3. Khóa DNS qua Proxy Tunnel & Chống rò rỉ WebRTC UDP tuyệt đối (khi có Proxy)
    // (Nếu có local_proxy_port):
    // format!("--proxy-server=http://127.0.0.1:{}", local_proxy_port),
    // "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1".to_string(),
    "--disable-non-proxied-udp".to_string(),
    "--webrtc-ip-handling-policy=disable_non_proxied_udp".to_string(),
    "--force-webrtc-ip-handling-policy".to_string(),
    "--enforce-webrtc-ip-permission-check".to_string(),

    // 4. Cờ Stealth chuẩn của Patchright (Loại bỏ dấu vết Automation)
    "--disable-blink-features=AutomationControlled".to_string(),
    "--no-first-run".to_string(),
    "--no-default-browser-check".to_string(),
    "--no-service-autorun".to_string(),
    "--password-store=basic".to_string(),
    "--use-mock-keychain".to_string(),

    // 5. Để Chromium tự cấp phát cổng CDP trống (tránh race condition) và ghi vào DevToolsActivePort
    "--remote-debugging-port=0".to_string(),
    "--remote-debugging-address=127.0.0.1".to_string(),
]
```

## Sau khi spawn `Chromium`, `launcher.rs` chờ tối đa `5s` (poll mỗi `100ms`) cho tới khi file `<user-data-dir>/DevToolsActivePort` xuất hiện, đọc dòng 1 lấy `cdp_port` và dòng 2 lấy đường dẫn WebSocket (`ws://127.0.0.1:<cdp_port><ws_path>`).

## 5. Lộ trình Triển khai (Implementation Phases — Không nhảy cóc)

- **Phase 1 — Foundation & Core Backend (Rust):**
  1. Khởi tạo `Cargo.toml` với `gpui-kit = "0.9.0"`, `rusqlite = { version = "0.32", features = ["bundled"] }`, `tokio`, `reqwest`, `serde`, `serde_json`, `uuid`, `anyhow`.
  2. Viết `models.rs` và `db.rs` (1 bảng `profiles` duy nhất trong SQLite, CRUD + tạo sẵn 2 Profile mẫu để test).
  3. Viết `proxy_tunnel.rs` (Local HTTP Proxy nối thẳng lên HTTP/SOCKS5 có `user:pass`, gửi domain ATYP `0x03`, timeout `10s`, quản lý bằng `JoinSet`) + unit test kiểm chứng.
  4. Viết `geoip.rs` (Đi qua `proxy_tunnel` kiểm tra IP, Timezone, Country/Locale theo cơ chế Fail-Closed).
  5. Viết `launcher.rs` (Định vị binary `adryfish/fingerprint-chromium` trên macOS, tự chạy `xattr -cr`, spawn với `--remote-debugging-port=0`, đọc `DevToolsActivePort`, và gửi `SIGTERM` dọn sạch PID khi đóng app).
- **Phase 2 — Giao diện Desktop với GPUI (`src/ui/`):**
  1. Dựng cửa sổ macOS Native với `gpui` (Dark theme hiện đại, thanh Titlebar chuẩn macOS).
  2. Xây dựng **Profile Dashboard**:
     - Hiển thị danh sách Profile: Tên, Seed, OS, Proxy, Exit IP + Quốc gia/Timezone, Trạng thái (`Stopped` / `Starting...` / `Running (PID, CDP Port)`).
     - Các nút thao tác trực tiếp: **`Launch`**, **`Stop`**, **`Check Proxy`**, **`Copy CDP / Agent CLI`** (hỗ trợ cả `Patchright` lẫn `agent-browser --session bon_<id8> --input-mode human connect "ws://127.0.0.1:<cdp_port><ws_path>"`), **`New Profile`**, **`Delete`**.
  3. Xây dựng **Create/Edit Profile Panel**:
     - Cho phép đổi tên, bấm **"Randomize Seed"**, chọn OS (`macOS` / `Windows`), bật/tắt `Native GPU Passthrough`, nhập chuỗi Proxy nhanh định dạng `host:port:user:pass` hoặc `socks5://user:pass@host:port`.

- **Phase 3 — Tích hợp Kernel `adryfish` & Smoke Test thực tế:**
  1. Kiểm tra/tải bản `ungoogled-chromium_148.0.7778.215-1.1_macos.dmg` (bản macOS mới nhất của `adryfish/fingerprint-chromium`).
  2. Biên dịch `cargo build` và chạy ứng dụng GPUI thực tế trên macOS.
  3. Mở thử Profile từ giao diện GPUI, kiểm tra trực tiếp trên `https://browserscan.net` và `https://abrahamjuliot.github.io/creepjs/`.

---

## 6. Quy tắc Chống Lan Man (Anti-Bloat Rules)

- **KHÔNG** viết hệ thống đăng nhập tài khoản đám mây (Cloud Sync / Auth Server) — đây là ứng dụng Local-First tốc độ cao.
- **KHÔNG** cài thêm ORM nặng nề (như Diesel/SeaORM) — chỉ dùng `rusqlite` với truy vấn SQL thuần, rõ ràng.
- **KHÔNG** tạo quá nhiều file nhỏ hoặc trait trừu tượng khi chỉ có 1 implementation duy nhất.
- Mỗi khi sửa code Rust, phải đảm bảo `cargo check` sạch lỗi trước khi chuyển bước tiếp theo.
- **Gặp API/thư viện/kỹ thuật chưa quen thuộc (VD: `gpui`, `gpui-component`, `adryfish/fingerprint-chromium`, `Patchright`...):** Bắt buộc tìm kiếm và tham khảo code thực tế trên **GitHub** trước khi tự suy đoán hoặc viết code thử sai.
