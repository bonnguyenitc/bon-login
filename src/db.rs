use crate::models::{
    BrowserBrand, BrowserExtension, GeoInfo, GpuSpoofMode, PlatformType, Profile, ProxyConfig,
    ProxyProtocol, SavedProxy, unix_now,
};
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::LazyLock;

static APP_DATA_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir = dirs::data_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Library/Application Support")))
        .unwrap_or_else(std::env::temp_dir)
        .join("com.bonlogin.app");
    for sub in ["profiles", "kernels", "states", "screenshots", "extensions", "backups"] {
        let _ = std::fs::create_dir_all(dir.join(sub));
    }
    dir
});

pub fn app_data_dir() -> anyhow::Result<PathBuf> {
    Ok(APP_DATA_DIR.clone())
}

fn apply_fast_pragmas(conn: &Connection) {
    let _ = conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 67108864;
         PRAGMA cache_size = -16000;",
    );
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open_default() -> anyhow::Result<Self> {
        let db_path = app_data_dir()?.join("bonlogin.sqlite3");
        let conn = Connection::open(db_path)?;
        apply_fast_pragmas(&conn);
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_fast() -> anyhow::Result<Self> {
        let db_path = APP_DATA_DIR.join("bonlogin.sqlite3");
        let conn = Connection::open(db_path)?;
        apply_fast_pragmas(&conn);
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        apply_fast_pragmas(&conn);
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn with_transaction<T>(&self, f: impl FnOnce(&Self) -> anyhow::Result<T>) -> anyhow::Result<T> {
        self.conn.execute_batch("SAVEPOINT bon_batch")?;
        match f(self) {
            Ok(val) => {
                self.conn.execute_batch("RELEASE SAVEPOINT bon_batch")?;
                Ok(val)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK TO SAVEPOINT bon_batch; RELEASE SAVEPOINT bon_batch");
                Err(err)
            }
        }
    }

    fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS profiles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                group_tag TEXT NOT NULL,
                seed INTEGER NOT NULL,
                os_platform TEXT NOT NULL,
                os_version TEXT NOT NULL,
                brand TEXT NOT NULL,
                brand_version TEXT NOT NULL,
                hardware_concurrency INTEGER NOT NULL,
                gpu_spoofing TEXT NOT NULL,
                spoof_canvas INTEGER NOT NULL DEFAULT 1,
                spoof_audio INTEGER NOT NULL DEFAULT 1,
                spoof_font INTEGER NOT NULL DEFAULT 1,
                spoof_client_rects INTEGER NOT NULL DEFAULT 1,
                window_size TEXT NOT NULL DEFAULT '1440,900',
                custom_timezone TEXT,
                custom_locale TEXT,
                proxy_protocol TEXT,
                proxy_host TEXT,
                proxy_port INTEGER,
                proxy_username TEXT,
                proxy_password TEXT,
                geo_ip TEXT,
                geo_country TEXT,
                geo_timezone TEXT,
                geo_locale TEXT,
                geo_accept_lang TEXT,
                geo_latency_ms INTEGER,
                startup_url TEXT NOT NULL,
                notes TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_launched_at INTEGER,
                tags TEXT NOT NULL DEFAULT '',
                totp_secret TEXT NOT NULL DEFAULT '',
                deleted_at INTEGER,
                proxy_change_ip_url TEXT
            );
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                group_tag TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT,
                password TEXT,
                geo_ip TEXT,
                geo_country TEXT,
                geo_timezone TEXT,
                geo_locale TEXT,
                geo_accept_lang TEXT,
                geo_latency_ms INTEGER,
                last_error TEXT,
                created_at INTEGER NOT NULL,
                expired_at INTEGER,
                change_ip_url TEXT
            );
            CREATE TABLE IF NOT EXISTS profile_groups (
                name TEXT PRIMARY KEY COLLATE NOCASE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS proxy_tags (
                name TEXT PRIMARY KEY COLLATE NOCASE,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS extensions (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                icon_label TEXT NOT NULL,
                icon_bg INTEGER NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 0,
                source_url TEXT NOT NULL DEFAULT '',
                folder_path TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_profiles_created_at ON profiles(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_profiles_group_tag ON profiles(group_tag COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS idx_proxies_created_at ON proxies(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_proxies_group_tag ON proxies(group_tag COLLATE NOCASE);
            INSERT OR IGNORE INTO profile_groups (name, created_at)
                SELECT DISTINCT TRIM(group_tag), created_at FROM profiles WHERE TRIM(group_tag) != '';
            INSERT OR IGNORE INTO proxy_tags (name, created_at)
                SELECT DISTINCT TRIM(group_tag), created_at FROM proxies WHERE TRIM(group_tag) != '';",
        )?;

        for alter in [
            "ALTER TABLE profiles ADD COLUMN spoof_canvas INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE profiles ADD COLUMN spoof_audio INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE profiles ADD COLUMN spoof_font INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE profiles ADD COLUMN spoof_client_rects INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE profiles ADD COLUMN window_size TEXT NOT NULL DEFAULT '1440,900'",
            "ALTER TABLE profiles ADD COLUMN custom_timezone TEXT",
            "ALTER TABLE profiles ADD COLUMN custom_locale TEXT",
            "ALTER TABLE profiles ADD COLUMN geo_latency_ms INTEGER",
            "ALTER TABLE profiles ADD COLUMN tags TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE profiles ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE profiles ADD COLUMN deleted_at INTEGER",
            "ALTER TABLE proxies ADD COLUMN expired_at INTEGER",
            "ALTER TABLE profiles ADD COLUMN proxy_change_ip_url TEXT",
            "ALTER TABLE proxies ADD COLUMN change_ip_url TEXT",
        ] {
            let _ = self.conn.execute(alter, []);
        }

        let default_extensions: &[(&str, &str, &str, i64, &str, i64)] = &[
            (
                "ublock-origin-lite",
                "uBlock Origin Lite",
                "🛡️",
                0xDC2626,
                "ddkjiahejlhfcafbddmgiahcphecmpfh",
                1,
            ),
            (
                "authenticator-2fa",
                "Authenticator (2FA)",
                "🔐",
                0x2563EB,
                "bhghoamapcdpbohphigoooaddinpkbai",
                2,
            ),
            (
                "cookie-editor",
                "Cookie-Editor",
                "🍪",
                0xD97706,
                "hlkenndednhfkekhgcdicdfddnkalmdm",
                3,
            ),
            (
                "bitwarden",
                "Bitwarden",
                "🔑",
                0x1D4ED8,
                "nngceckbapebfimnlniiiahkandclblb",
                4,
            ),
            (
                "violentmonkey",
                "Violentmonkey",
                "🐒",
                0xEA580C,
                "https://github.com/violentmonkey/violentmonkey/releases/download/v2.50.0/Violentmonkey-mv3-v2.50.0.zip",
                5,
            ),
            (
                "capsolver",
                "CapSolver",
                "🤖",
                0x10B981,
                "pgojnojmmhpofjgdmaebadhbocahppod",
                6,
            ),
            (
                "simple-translate",
                "Simple Translate",
                "🌐",
                0x0284C7,
                "ibplnjkanclpjokhdolnendpplpjiace",
                7,
            ),
            (
                "metamask",
                "MetaMask",
                "🦊",
                0xEA580C,
                "nkbihfbeogaeaoehlefnkodbefgpgknn",
                8,
            ),
            (
                "rabby-wallet",
                "Rabby Wallet",
                "🐰",
                0x4F46E5,
                "acmacodkjbdgmoleebolmdjonilkdbch",
                9,
            ),
            (
                "phantom",
                "Phantom",
                "👻",
                0x7C3AED,
                "bfnaelmomeimhlpmgjnjophhpkkoljpa",
                10,
            ),
            (
                "okx-wallet",
                "OKX Wallet",
                "⬛",
                0x1E293B,
                "mcohilncbfahbmgdjkbpemcciiolgcge",
                11,
            ),
            (
                "cookie-token-grabber",
                "Cookie & Token Grabber",
                "📋",
                0x0D9488,
                "",
                12,
            ),
            (
                "ip-status-badge",
                "Proxy / IP Status Badge",
                "📡",
                0x0891B2,
                "",
                13,
            ),
            (
                "coordinates",
                "Coordinates Helper",
                "🎯",
                0x3B82F6,
                "",
                14,
            ),
        ];
        for &(id, name, icon_label, icon_bg, source_url, order) in default_extensions {
            self.conn.execute(
                "INSERT OR IGNORE INTO extensions (id, name, icon_label, icon_bg, is_default, enabled, source_url, folder_path, created_at)
                 VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, '', ?6)",
                params![id, name, icon_label, icon_bg, source_url, order],
            )?;
        }


        Ok(())
    }


    pub fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        self.query_profiles_sql(
            "SELECT
                id, name, group_tag, seed, os_platform, os_version,
                brand, brand_version, hardware_concurrency, gpu_spoofing,
                proxy_protocol, proxy_host, proxy_port, proxy_username, proxy_password,
                geo_ip, geo_country, geo_timezone, geo_locale, geo_accept_lang,
                startup_url, notes, created_at, last_launched_at,
                spoof_canvas, spoof_audio, spoof_font, spoof_client_rects,
                window_size, custom_timezone, custom_locale, geo_latency_ms,
                tags, totp_secret, deleted_at, proxy_change_ip_url
             FROM profiles
             WHERE deleted_at IS NULL
             ORDER BY created_at DESC",
        )
    }

    pub fn list_trashed_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        self.query_profiles_sql(
            "SELECT
                id, name, group_tag, seed, os_platform, os_version,
                brand, brand_version, hardware_concurrency, gpu_spoofing,
                proxy_protocol, proxy_host, proxy_port, proxy_username, proxy_password,
                geo_ip, geo_country, geo_timezone, geo_locale, geo_accept_lang,
                startup_url, notes, created_at, last_launched_at,
                spoof_canvas, spoof_audio, spoof_font, spoof_client_rects,
                window_size, custom_timezone, custom_locale, geo_latency_ms,
                tags, totp_secret, deleted_at, proxy_change_ip_url
             FROM profiles
             WHERE deleted_at IS NOT NULL
             ORDER BY deleted_at DESC",
        )
    }

    fn query_profiles_sql(&self, sql: &str) -> anyhow::Result<Vec<Profile>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt.query_map([], |row| {
            let os_str: String = row.get(4)?;
            let brand_str: String = row.get(6)?;
            let gpu_str: String = row.get(9)?;

            let proxy = match (
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<u16>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
            ) {
                (Some(proto), Some(host), Some(port), username, password) if !host.is_empty() => {
                    Some(ProxyConfig {
                        protocol: ProxyProtocol::from_str_lossy(&proto),
                        host,
                        port,
                        username,
                        password,
                        change_ip_url: row
                            .get::<_, Option<String>>(35)
                            .ok()
                            .flatten()
                            .filter(|s| !s.trim().is_empty()),
                    })
                }
                _ => None,
            };

            let resolved_geo = match (
                row.get::<_, Option<String>>(15)?,
                row.get::<_, Option<String>>(16)?,
                row.get::<_, Option<String>>(17)?,
                row.get::<_, Option<String>>(18)?,
                row.get::<_, Option<String>>(19)?,
            ) {
                (Some(ip), Some(country_code), Some(timezone), Some(locale), Some(accept_lang))
                    if !ip.is_empty() =>
                {
                    let latency_ms = row.get::<_, Option<u32>>(31).ok().flatten();
                    Some(GeoInfo {
                        ip,
                        country_code,
                        timezone,
                        locale,
                        accept_lang,
                        latency_ms,
                    })
                }
                _ => None,
            };

            let window_size: String = row
                .get::<_, Option<String>>(28)?
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| Profile::DEFAULT_WINDOW_SIZE.to_string());
            let raw_tags: String = row.get::<_, Option<String>>(32)?.unwrap_or_default();
            let totp_secret: String = row.get::<_, Option<String>>(33)?.unwrap_or_default();
            let deleted_at: Option<i64> = row.get(34).ok().flatten();

            Ok(Profile {
                id: row.get(0)?,
                name: row.get(1)?,
                group_tag: row.get(2)?,
                tags: Profile::parse_tags_csv(&raw_tags),
                seed: row.get(3)?,
                os_platform: PlatformType::from_str_lossy(&os_str),
                os_version: row.get(5)?,
                brand: BrowserBrand::from_str_lossy(&brand_str),
                brand_version: row.get(7)?,
                hardware_concurrency: row.get(8)?,
                gpu_spoofing: GpuSpoofMode::from_str_lossy(&gpu_str),
                spoof_canvas: row.get::<_, i64>(24).unwrap_or(1) != 0,
                spoof_audio: row.get::<_, i64>(25).unwrap_or(1) != 0,
                spoof_font: row.get::<_, i64>(26).unwrap_or(1) != 0,
                spoof_client_rects: row.get::<_, i64>(27).unwrap_or(1) != 0,
                window_size,
                custom_timezone: row
                    .get::<_, Option<String>>(29)?
                    .filter(|s| !s.trim().is_empty()),
                custom_locale: row
                    .get::<_, Option<String>>(30)?
                    .filter(|s| !s.trim().is_empty()),
                proxy,
                resolved_geo,
                startup_url: row.get(20)?,
                notes: row.get(21)?,
                totp_secret,
                created_at: row.get(22)?,
                last_launched_at: row.get(23)?,
                deleted_at,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn upsert_profile(&self, profile: &Profile) -> anyhow::Result<()> {
        let (
            proxy_protocol,
            proxy_host,
            proxy_port,
            proxy_username,
            proxy_password,
            proxy_change_ip_url,
        ) = match &profile.proxy {
            Some(p) => (
                Some(p.protocol.as_str()),
                Some(p.host.as_str()),
                Some(p.port),
                p.username.as_deref(),
                p.password.as_deref(),
                p.change_ip_url.as_deref(),
            ),
            None => (None, None, None, None, None, None),
        };

        let (geo_ip, geo_country, geo_timezone, geo_locale, geo_accept_lang, geo_latency_ms) =
            match &profile.resolved_geo {
                Some(g) => (
                    Some(g.ip.as_str()),
                    Some(g.country_code.as_str()),
                    Some(g.timezone.as_str()),
                    Some(g.locale.as_str()),
                    Some(g.accept_lang.as_str()),
                    g.latency_ms,
                ),
                None => (None, None, None, None, None, None),
            };
        let tags_csv = profile.tags_csv();

        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO profiles (
                id, name, group_tag, seed, os_platform, os_version,
                brand, brand_version, hardware_concurrency, gpu_spoofing,
                spoof_canvas, spoof_audio, spoof_font, spoof_client_rects,
                window_size, custom_timezone, custom_locale,
                proxy_protocol, proxy_host, proxy_port, proxy_username, proxy_password,
                geo_ip, geo_country, geo_timezone, geo_locale, geo_accept_lang, geo_latency_ms,
                startup_url, notes, created_at, last_launched_at,
                tags, totp_secret, deleted_at, proxy_change_ip_url
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6,
                ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14,
                ?15, ?16, ?17,
                ?18, ?19, ?20, ?21, ?22,
                ?23, ?24, ?25, ?26, ?27, ?28,
                ?29, ?30, ?31, ?32,
                ?33, ?34, ?35, ?36
            )
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                group_tag = excluded.group_tag,
                seed = excluded.seed,
                os_platform = excluded.os_platform,
                os_version = excluded.os_version,
                brand = excluded.brand,
                brand_version = excluded.brand_version,
                hardware_concurrency = excluded.hardware_concurrency,
                gpu_spoofing = excluded.gpu_spoofing,
                spoof_canvas = excluded.spoof_canvas,
                spoof_audio = excluded.spoof_audio,
                spoof_font = excluded.spoof_font,
                spoof_client_rects = excluded.spoof_client_rects,
                window_size = excluded.window_size,
                custom_timezone = excluded.custom_timezone,
                custom_locale = excluded.custom_locale,
                proxy_protocol = excluded.proxy_protocol,
                proxy_host = excluded.proxy_host,
                proxy_port = excluded.proxy_port,
                proxy_username = excluded.proxy_username,
                proxy_password = excluded.proxy_password,
                geo_ip = excluded.geo_ip,
                geo_country = excluded.geo_country,
                geo_timezone = excluded.geo_timezone,
                geo_locale = excluded.geo_locale,
                geo_accept_lang = excluded.geo_accept_lang,
                geo_latency_ms = excluded.geo_latency_ms,
                startup_url = excluded.startup_url,
                notes = excluded.notes,
                created_at = excluded.created_at,
                last_launched_at = excluded.last_launched_at,
                tags = excluded.tags,
                totp_secret = excluded.totp_secret,
                deleted_at = excluded.deleted_at,
                proxy_change_ip_url = excluded.proxy_change_ip_url",
        )?;
        stmt.execute(params![
            profile.id,
            profile.name,
            profile.group_tag,
            profile.seed,
            profile.os_platform.as_cli_str(),
            profile.os_version,
            profile.brand.as_cli_str(),
            profile.brand_version,
            profile.hardware_concurrency,
            profile.gpu_spoofing.as_str(),
            i64::from(profile.spoof_canvas),
            i64::from(profile.spoof_audio),
            i64::from(profile.spoof_font),
            i64::from(profile.spoof_client_rects),
            profile.window_size,
            profile.custom_timezone.as_deref(),
            profile.custom_locale.as_deref(),
            proxy_protocol,
            proxy_host,
            proxy_port,
            proxy_username,
            proxy_password,
            geo_ip,
            geo_country,
            geo_timezone,
            geo_locale,
            geo_accept_lang,
            geo_latency_ms,
            profile.startup_url,
            profile.notes,
            profile.created_at,
            profile.last_launched_at,
            tags_csv,
            profile.totp_secret,
            profile.deleted_at,
            proxy_change_ip_url,
        ])?;
        if !profile.group_tag.trim().is_empty() {
            let _ = self.insert_group(profile.group_tag.trim());
        }
        Ok(())
    }

    pub fn update_resolved_geo(
        &self,
        profile_id: &str,
        geo: Option<&GeoInfo>,
    ) -> anyhow::Result<()> {
        let (ip, country, tz, locale, accept_lang, latency_ms) = match geo {
            Some(g) => (
                Some(g.ip.as_str()),
                Some(g.country_code.as_str()),
                Some(g.timezone.as_str()),
                Some(g.locale.as_str()),
                Some(g.accept_lang.as_str()),
                g.latency_ms,
            ),
            None => (None, None, None, None, None, None),
        };
        let mut stmt = self.conn.prepare_cached(
            "UPDATE profiles
             SET geo_ip = ?1, geo_country = ?2, geo_timezone = ?3, geo_locale = ?4, geo_accept_lang = ?5, geo_latency_ms = ?6
             WHERE id = ?7",
        )?;
        stmt.execute(params![ip, country, tz, locale, accept_lang, latency_ms, profile_id])?;
        Ok(())
    }

    pub fn touch_last_launched(&self, profile_id: &str) -> anyhow::Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("UPDATE profiles SET last_launched_at = ?1 WHERE id = ?2")?;
        stmt.execute(params![unix_now(), profile_id])?;
        Ok(())
    }

    pub fn soft_delete_profile(&self, profile_id: &str) -> anyhow::Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("UPDATE profiles SET deleted_at = ?1 WHERE id = ?2")?;
        stmt.execute(params![unix_now(), profile_id])?;
        Ok(())
    }

    pub fn restore_profile(&self, profile_id: &str) -> anyhow::Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("UPDATE profiles SET deleted_at = NULL WHERE id = ?1")?;
        stmt.execute(params![profile_id])?;
        Ok(())
    }

    pub fn update_profile_quick_meta(
        &self,
        profile_id: &str,
        notes: &str,
        tags: &[String],
        totp_secret: &str,
    ) -> anyhow::Result<()> {
        let tags_csv = tags.join(",");
        let mut stmt = self.conn.prepare_cached(
            "UPDATE profiles SET notes = ?1, tags = ?2, totp_secret = ?3 WHERE id = ?4",
        )?;
        stmt.execute(params![notes.trim(), tags_csv, totp_secret.trim(), profile_id])?;
        Ok(())
    }

    pub fn delete_profile(&self, profile_id: &str) -> anyhow::Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("DELETE FROM profiles WHERE id = ?1")?;
        stmt.execute(params![profile_id])?;
        Ok(())
    }
    /// Exports all profiles to `~/Library/Application Support/com.bonlogin.app/backups/bonlogin_profiles_backup.json`.
    pub fn export_profiles_json(&self) -> anyhow::Result<(PathBuf, String)> {
        let profiles = self.list_profiles()?;
        let json = serde_json::to_string_pretty(&profiles)?;
        let path = app_data_dir()?
            .join("backups")
            .join("bonlogin_profiles_backup.json");
        std::fs::write(&path, &json)?;
        Ok((path, json))
    }

    /// Imports profiles from a JSON array string (generating new UUIDs if an ID already exists).
    pub fn import_profiles_json(&self, raw_json: &str) -> anyhow::Result<usize> {
        let parsed: Vec<Profile> = serde_json::from_str(raw_json.trim())?;
        let existing_ids: std::collections::HashSet<String> = self
            .list_profiles()?
            .into_iter()
            .chain(self.list_trashed_profiles()?)
            .map(|p| p.id)
            .collect();
        self.with_transaction(|db| {
            let mut count = 0;
            for mut p in parsed {
                if existing_ids.contains(&p.id) {
                    p.id = uuid::Uuid::new_v4().to_string();
                }
                db.upsert_profile(&p)?;
                count += 1;
            }
            Ok(count)
        })
    }

    // -----------------------------------------------------------------------
    // Saved Proxies & Proxy Groups CRUD
    // -----------------------------------------------------------------------

    pub fn list_proxies(&self) -> anyhow::Result<Vec<SavedProxy>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT
                id, name, group_tag, protocol, host, port, username, password,
                geo_ip, geo_country, geo_timezone, geo_locale, geo_accept_lang,
                geo_latency_ms, last_error, created_at, expired_at, change_ip_url
             FROM proxies
             ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let proto_str: String = row.get(3)?;
            let resolved_geo = match (
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, Option<String>>(12)?,
            ) {
                (Some(ip), Some(country_code), Some(timezone), Some(locale), Some(accept_lang))
                    if !ip.is_empty() =>
                {
                    Some(GeoInfo {
                        ip,
                        country_code,
                        timezone,
                        locale,
                        accept_lang,
                        latency_ms: row.get::<_, Option<u32>>(13).ok().flatten(),
                    })
                }
                _ => None,
            };

            Ok(SavedProxy {
                id: row.get(0)?,
                name: row.get(1)?,
                group_tag: row.get(2)?,
                config: ProxyConfig {
                    protocol: ProxyProtocol::from_str_lossy(&proto_str),
                    host: row.get(4)?,
                    port: row.get(5)?,
                    username: row.get(6)?,
                    password: row.get(7)?,
                    change_ip_url: row
                        .get::<_, Option<String>>(17)
                        .ok()
                        .flatten()
                        .filter(|s| !s.trim().is_empty()),
                },
                resolved_geo,
                last_error: row
                    .get::<_, Option<String>>(14)?
                    .filter(|s| !s.trim().is_empty()),
                created_at: row.get(15)?,
                expired_at: row.get(16)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn upsert_proxy(&self, proxy: &SavedProxy) -> anyhow::Result<()> {
        let (geo_ip, geo_country, geo_tz, geo_loc, geo_lang, geo_ms) = match &proxy.resolved_geo {
            Some(g) => (
                Some(g.ip.as_str()),
                Some(g.country_code.as_str()),
                Some(g.timezone.as_str()),
                Some(g.locale.as_str()),
                Some(g.accept_lang.as_str()),
                g.latency_ms,
            ),
            None => (None, None, None, None, None, None),
        };

        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO proxies (
                id, name, group_tag, protocol, host, port, username, password,
                geo_ip, geo_country, geo_timezone, geo_locale, geo_accept_lang,
                geo_latency_ms, last_error, created_at, expired_at, change_ip_url
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, ?18
            )
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                group_tag = excluded.group_tag,
                protocol = excluded.protocol,
                host = excluded.host,
                port = excluded.port,
                username = excluded.username,
                password = excluded.password,
                geo_ip = excluded.geo_ip,
                geo_country = excluded.geo_country,
                geo_timezone = excluded.geo_timezone,
                geo_locale = excluded.geo_locale,
                geo_accept_lang = excluded.geo_accept_lang,
                geo_latency_ms = excluded.geo_latency_ms,
                last_error = excluded.last_error,
                expired_at = excluded.expired_at,
                change_ip_url = excluded.change_ip_url",
        )?;
        stmt.execute(params![
                proxy.id,
                proxy.name,
                proxy.group_tag,
                proxy.config.protocol.as_str(),
                proxy.config.host,
                proxy.config.port,
                proxy.config.username.as_deref(),
                proxy.config.password.as_deref(),
                geo_ip,
                geo_country,
                geo_tz,
                geo_loc,
                geo_lang,
                geo_ms,
                proxy.last_error.as_deref(),
                proxy.created_at,
                proxy.expired_at,
                proxy.config.change_ip_url.as_deref(),
            ],
        )?;
        if !proxy.group_tag.trim().is_empty() {
            let _ = self.insert_tag(proxy.group_tag.trim());
        }
        Ok(())
    }

    pub fn update_saved_proxy_check(
        &self,
        proxy_id: &str,
        geo: Option<&GeoInfo>,
        err: Option<&str>,
    ) -> anyhow::Result<()> {
        let (ip, country, tz, locale, accept_lang, latency_ms) = match geo {
            Some(g) => (
                Some(g.ip.as_str()),
                Some(g.country_code.as_str()),
                Some(g.timezone.as_str()),
                Some(g.locale.as_str()),
                Some(g.accept_lang.as_str()),
                g.latency_ms,
            ),
            None => (None, None, None, None, None, None),
        };
        let mut stmt = self.conn.prepare_cached(
            "UPDATE proxies
             SET geo_ip = ?1, geo_country = ?2, geo_timezone = ?3, geo_locale = ?4,
                 geo_accept_lang = ?5, geo_latency_ms = ?6, last_error = ?7
             WHERE id = ?8",
        )?;
        stmt.execute(params![ip, country, tz, locale, accept_lang, latency_ms, err, proxy_id])?;
        Ok(())
    }

    /// Updates cached GeoIP across all saved proxies and profiles matching `(protocol, host, port)`.
    pub fn sync_geo_for_proxy_endpoint(
        &self,
        cfg: &ProxyConfig,
        geo: &GeoInfo,
    ) -> anyhow::Result<()> {
        let proto = cfg.protocol.as_str();
        self.with_transaction(|db| {
            db.conn
                .prepare_cached(
                    "UPDATE proxies
                     SET geo_ip = ?1, geo_country = ?2, geo_timezone = ?3, geo_locale = ?4,
                         geo_accept_lang = ?5, geo_latency_ms = ?6, last_error = NULL
                     WHERE protocol = ?7 AND host = ?8 AND port = ?9",
                )?
                .execute(params![
                    geo.ip,
                    geo.country_code,
                    geo.timezone,
                    geo.locale,
                    geo.accept_lang,
                    geo.latency_ms,
                    proto,
                    cfg.host,
                    cfg.port
                ])?;
            db.conn
                .prepare_cached(
                    "UPDATE profiles
                     SET geo_ip = ?1, geo_country = ?2, geo_timezone = ?3, geo_locale = ?4,
                         geo_accept_lang = ?5, geo_latency_ms = ?6
                     WHERE proxy_protocol = ?7 AND proxy_host = ?8 AND proxy_port = ?9",
                )?
                .execute(params![
                    geo.ip,
                    geo.country_code,
                    geo.timezone,
                    geo.locale,
                    geo.accept_lang,
                    geo.latency_ms,
                    proto,
                    cfg.host,
                    cfg.port
                ])?;
            Ok(())
        })
    }

    pub fn delete_proxy(&self, proxy_id: &str) -> anyhow::Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("DELETE FROM proxies WHERE id = ?1")?;
        stmt.execute(params![proxy_id])?;
        Ok(())
    }

    pub fn list_groups(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT name FROM profile_groups ORDER BY created_at ASC, name ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        // Return actual groups without re-seeding deleted defaults
        Ok(out)
    }

    pub fn insert_group(&self, name: &str) -> anyhow::Result<()> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let mut stmt = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO profile_groups (name, created_at) VALUES (?1, ?2)",
        )?;
        stmt.execute(params![trimmed, unix_now()])?;
        Ok(())
    }

    pub fn delete_group(&self, name: &str) -> anyhow::Result<()> {
        let trimmed = name.trim();
        self.with_transaction(|db| {
            db.conn
                .prepare_cached("DELETE FROM profile_groups WHERE name = ?1 COLLATE NOCASE")?
                .execute(params![trimmed])?;
            db.conn
                .prepare_cached(
                    "UPDATE profiles SET group_tag = '' WHERE group_tag = ?1 COLLATE NOCASE",
                )?
                .execute(params![trimmed])?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn list_tags(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT name FROM proxy_tags ORDER BY created_at ASC, name ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        // Return actual tags without re-seeding deleted defaults
        Ok(out)
    }

    pub fn insert_tag(&self, name: &str) -> anyhow::Result<()> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let mut stmt = self
            .conn
            .prepare_cached("INSERT OR IGNORE INTO proxy_tags (name, created_at) VALUES (?1, ?2)")?;
        stmt.execute(params![trimmed, unix_now()])?;
        Ok(())
    }

    pub fn delete_tag(&self, name: &str) -> anyhow::Result<()> {
        let trimmed = name.trim();
        self.with_transaction(|db| {
            db.conn
                .prepare_cached("DELETE FROM proxy_tags WHERE name = ?1 COLLATE NOCASE")?
                .execute(params![trimmed])?;
            db.conn
                .prepare_cached(
                    "UPDATE proxies SET group_tag = '' WHERE group_tag = ?1 COLLATE NOCASE",
                )?
                .execute(params![trimmed])?;
            Ok(())
        })?;
        Ok(())
    }

    pub fn list_extensions(&self) -> anyhow::Result<Vec<BrowserExtension>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, name, icon_label, icon_bg, is_default, enabled, source_url, folder_path, created_at
             FROM extensions
             ORDER BY is_default DESC, created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(BrowserExtension {
                id: row.get(0)?,
                name: row.get(1)?,
                icon_label: row.get(2)?,
                icon_bg: row.get(3)?,
                is_default: row.get::<_, i32>(4)? != 0,
                enabled: row.get::<_, i32>(5)? != 0,
                source_url: row.get(6)?,
                folder_path: row.get(7)?,
                created_at: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn upsert_extension(&self, ext: &BrowserExtension) -> anyhow::Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO extensions (id, name, icon_label, icon_bg, is_default, enabled, source_url, folder_path, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                icon_label = excluded.icon_label,
                icon_bg = excluded.icon_bg,
                enabled = excluded.enabled,
                source_url = excluded.source_url,
                folder_path = excluded.folder_path",
        )?;
        stmt.execute(params![
                ext.id,
                ext.name,
                ext.icon_label,
                ext.icon_bg,
                i32::from(ext.is_default),
                i32::from(ext.enabled),
                ext.source_url,
                ext.folder_path,
                ext.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn set_extension_enabled(&self, id: &str, enabled: bool) -> anyhow::Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("UPDATE extensions SET enabled = ?2 WHERE id = ?1")?;
        stmt.execute(params![id, i32::from(enabled)])?;
        Ok(())
    }

    pub fn delete_extension(&self, id: &str) -> anyhow::Result<bool> {
        let mut stmt = self
            .conn
            .prepare_cached("DELETE FROM extensions WHERE id = ?1 AND is_default = 0")?;
        let affected = stmt.execute(params![id])?;
        Ok(affected > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_crud() {
        let db = Database::open_in_memory().unwrap();
        assert!(db.list_profiles().unwrap().is_empty());

        let mut custom = Profile::new_default("FB Ads - US 01", PlatformType::Windows);
        custom.group_tag = "Facebook".to_string();
        custom.seed = 424242;
        custom.brand = BrowserBrand::Edge;
        custom.hardware_concurrency = 16;
        custom.gpu_spoofing = GpuSpoofMode::SeedGenerated;
        custom.spoof_font = false;
        custom.window_size = "1920,1080".to_string();
        custom.custom_timezone = Some("Europe/Berlin".to_string());
        custom.proxy = Some(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "198.51.100.10".to_string(),
            port: 1080,
            username: Some("user1".to_string()),
            password: Some("pass1".to_string()),
            change_ip_url: Some("http://rotate.local/api".to_string()),
        });
        custom.resolved_geo = Some(GeoInfo {
            ip: "198.51.100.10".to_string(),
            country_code: "DE".to_string(),
            timezone: "Europe/Berlin".to_string(),
            locale: "de-DE".to_string(),
            accept_lang: "de-DE,de,en-US;q=0.9".to_string(),
            latency_ms: Some(142),
        });
        db.upsert_profile(&custom).unwrap();

        let all = db.list_profiles().unwrap();
        assert_eq!(all.len(), 1);
        let fetched = &all[0];
        assert_eq!(fetched.id, custom.id);
        assert_eq!(
            fetched.resolved_geo.as_ref().and_then(|g| g.latency_ms),
            Some(142)
        );

        let json = serde_json::to_string(&vec![fetched.clone()]).unwrap();
        let imported = db.import_profiles_json(&json).unwrap();
        assert_eq!(imported, 1);
        assert_eq!(db.list_profiles().unwrap().len(), 2);
        db.delete_profile(&custom.id).unwrap();

        // Test SavedProxy CRUD & groups
        let sp = SavedProxy::new(
            "US Resi #01",
            "US-Residential",
            ProxyConfig {
                protocol: ProxyProtocol::Socks5,
                host: "203.0.113.55".to_string(),
                port: 1080,
                username: Some("u".to_string()),
                password: Some("p".to_string()),
                change_ip_url: None,
            },
        );
        let _ = sp;
        let mut sp = SavedProxy::new(
            "US Resi #01",
            "US-Residential",
            ProxyConfig {
                protocol: ProxyProtocol::Socks5,
                host: "203.0.113.55".to_string(),
                port: 1080,
                username: Some("u".to_string()),
                password: Some("p".to_string()),
                change_ip_url: Some("https://rotate.example.com/key".to_string()),
            },
        );
        sp.expired_at = SavedProxy::parse_expiration_input("24/03/2027");
        assert!(sp.expired_at.is_some());
        assert!(sp.format_expired_at().starts_with("24/03/2027"));
        db.upsert_proxy(&sp).unwrap();
        let proxies = db.list_proxies().unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].group_tag, "US-Residential");
        assert_eq!(proxies[0].expired_at, sp.expired_at);
        db.delete_proxy(&sp.id).unwrap();
        assert!(db.list_proxies().unwrap().is_empty());

        db.insert_group("Campaign-A").unwrap();
        assert!(db.list_groups().unwrap().contains(&"Campaign-A".to_string()));
        db.delete_group("Campaign-A").unwrap();
        assert!(!db.list_groups().unwrap().contains(&"Campaign-A".to_string()));

        db.insert_tag("ISP-VN").unwrap();
        assert!(db.list_tags().unwrap().contains(&"ISP-VN".to_string()));
        db.delete_tag("ISP-VN").unwrap();
        assert!(!db.list_tags().unwrap().contains(&"ISP-VN".to_string()));

        // Test Extensions CRUD & toggle
        let seeded = db.list_extensions().unwrap();
        assert_eq!(seeded.len(), 14);
        assert!(seeded.iter().all(|e| e.is_default && !e.enabled));
        let ext = BrowserExtension {
            id: "custom-ext".to_string(),
            name: "Custom Ext".to_string(),
            icon_label: "🧩".to_string(),
            icon_bg: 0xEA580C,
            is_default: false,
            enabled: false,
            source_url: "nkbihfbeogaeaoehlefnkodbefgpgknn".to_string(),
            folder_path: String::new(),
            created_at: 100,
        };
        db.upsert_extension(&ext).unwrap();
        db.set_extension_enabled("custom-ext", true).unwrap();
        assert!(
            db.list_extensions()
                .unwrap()
                .iter()
                .find(|e| e.id == "custom-ext")
                .unwrap()
                .enabled
        );
        assert!(!db.delete_extension("metamask").unwrap());
        assert!(db.delete_extension("custom-ext").unwrap());
        assert_eq!(db.list_extensions().unwrap().len(), 14);

        assert_eq!(
            BrowserExtension::extract_chrome_store_id(
                "https://chromewebstore.google.com/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm?hl=en"
            ),
            Some("hlkenndednhfkekhgcdicdfddnkalmdm".to_string())
        );
        // CRX3 header stripping test
        let mut fake_crx = Vec::new();
        fake_crx.extend_from_slice(b"Cr24");
        fake_crx.extend_from_slice(&3u32.to_le_bytes());
        fake_crx.extend_from_slice(&4u32.to_le_bytes());
        fake_crx.extend_from_slice(b"ABCD");
        fake_crx.extend_from_slice(b"PK\x03\x04ZIPDATA");
        let stripped = crate::launcher::strip_crx_header(&fake_crx).unwrap();
        assert_eq!(stripped, b"PK\x03\x04ZIPDATA");

        // Test savepoint transaction rollback on error and commit on success
        let before_len = db.list_profiles().unwrap().len();
        let err_res: anyhow::Result<()> = db.with_transaction(|tx| {
            let p = Profile::new_default("RolledBack", PlatformType::MacOS);
            tx.upsert_profile(&p)?;
            anyhow::bail!("simulated batch error");
        });
        assert!(err_res.is_err());
        assert_eq!(db.list_profiles().unwrap().len(), before_len);
    }
}
