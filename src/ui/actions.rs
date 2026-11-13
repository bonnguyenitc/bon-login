use super::*;

impl BonLoginApp {
    pub fn toggle_proxy_checked(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        if !self.checked_proxy_ids.remove(proxy_id) {
            self.checked_proxy_ids.insert(proxy_id.to_string());
        }
        cx.notify();
    }

    pub fn toggle_all_filtered_proxies_checked(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .filtered_proxy_indices()
            .into_iter()
            .map(|i| self.saved_proxies[i].id.clone())
            .collect();
        let all_checked = !ids.is_empty() && ids.iter().all(|id| self.checked_proxy_ids.contains(id));
        if all_checked {
            for id in ids {
                self.checked_proxy_ids.remove(&id);
            }
        } else {
            for id in ids {
                self.checked_proxy_ids.insert(id);
            }
        }
        cx.notify();
    }

    pub fn clear_checked_proxies(&mut self, cx: &mut Context<Self>) {
        self.checked_proxy_ids.clear();
        cx.notify();
    }

    pub fn copy_checked_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let lines: Vec<String> = self
            .saved_proxies
            .iter()
            .filter(|sp| self.checked_proxy_ids.contains(&sp.id))
            .map(|sp| sp.config.to_editable_string())
            .collect();
        if lines.is_empty() {
            return;
        }
        let count = lines.len();
        cx.write_to_clipboard(ClipboardItem::new_string(lines.join("\n")));
        self.banner_message = Some(format!("Copied {count} proxy(s) to clipboard"));
        cx.notify();
    }

    pub fn delete_checked_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.checked_proxy_ids.drain().collect();
        if ids.is_empty() {
            return;
        }
        let count = ids.len();
        for id in &ids {
            self.checking_proxy_ids.remove(id);
            if let Some(handle) = self.proxy_check_tasks.remove(id) {
                handle.abort();
            }
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &ids {
                    let _ = db.delete_proxy(id);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        self.banner_message = Some(format!("Deleted {count} proxy(s)"));
        cx.notify();
    }

    pub fn extend_saved_proxy_days(&mut self, proxy_id: &str, days: i64, cx: &mut Context<Self>) {
        let Some(mut sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let now = crate::models::unix_now();
        sp.expired_at = if days <= 0 {
            None
        } else {
            let base = sp.expired_at.unwrap_or(now).max(now);
            Some(base + days * 86_400)
        };
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_proxy(&sp);
        }
        self.reload_profiles();
        self.banner_message = Some(if days <= 0 {
            format!("Cleared expiration for '{}'", sp.name)
        } else {
            format!("Extended '{}' by +{days} days ({})", sp.name, sp.format_expired_at())
        });
        cx.notify();
    }

    pub fn extend_checked_saved_proxies_days(&mut self, days: i64, cx: &mut Context<Self>) {
        let checked = self.checked_proxy_ids.clone();
        if checked.is_empty() {
            return;
        }
        let now = crate::models::unix_now();
        let mut count = 0;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for sp in &self.saved_proxies {
                    if checked.contains(&sp.id) {
                        let mut updated = sp.clone();
                        let base = updated.expired_at.unwrap_or(now).max(now);
                        updated.expired_at = Some(base + days * 86_400);
                        let _ = db.upsert_proxy(&updated);
                        count += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        self.banner_message = Some(format!("Extended {count} proxy(s) by +{days} days"));
        cx.notify();
    }

    pub fn add_saved_proxies_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let group_tag = self.proxy_selected_tag.trim().to_string();
        let raw = self.proxy_raw_input.read(cx).value().to_string();
        let tokens: Vec<&str> = raw
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            self.banner_message =
                Some("Enter at least one proxy (e.g. http://192.168.1.1:3000:user:pass)".to_string());
            cx.notify();
            return;
        }

        let base_idx = self.saved_proxies.len() + 1;
        let default_proto = self.proxy_add_protocol;
        let expire_raw = self.proxy_expire_input.read(cx).value().to_string();
        let parsed_expired_at = match SavedProxy::parse_expiration_strict(&expire_raw) {
            Ok(exp) => exp,
            Err(msg) => {
                self.banner_message = Some(msg.to_string());
                cx.notify();
                return;
            }
        };
        let mut added = Vec::new();
        for (i, token) in tokens.into_iter().enumerate() {
            match ProxyConfig::parse_with_optional_name(token, default_proto) {
                Ok(Some((cfg, explicit_name))) => {
                    let name = explicit_name
                        .unwrap_or_else(|| format!("Proxy #{:02}", base_idx + i));
                    let mut sp = SavedProxy::new(name, group_tag.clone(), cfg);
                    sp.expired_at = parsed_expired_at;
                    added.push(sp);
                }
                Ok(None) => {}
                Err(e) => {
                    self.banner_message = Some(format!("Invalid proxy '{token}': {e}"));
                    cx.notify();
                    return;
                }
            }
        }

        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for sp in &added {
                    let _ = db.upsert_proxy(sp);
                }
                Ok(())
            });
        }
        let count = added.len();
        self.proxy_raw_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(6)
                .placeholder("One proxy per line (type:host:port:login:password:name)")
        });
        self.popup_modal = None;
        self.reload_profiles();
        self.selected_proxy_group = "All".to_string();
        self.banner_message = Some(format!("Added {count} proxy(s) (Tag: #{group_tag})"));
        cx.notify();
    }

    pub fn delete_saved_proxy(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        self.checked_proxy_ids.remove(proxy_id);
        self.checking_proxy_ids.remove(proxy_id);
        if let Some(handle) = self.proxy_check_tasks.remove(proxy_id) {
            handle.abort();
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_proxy(proxy_id);
        }
        self.reload_profiles();
        self.banner_message = Some("Deleted proxy".to_string());
        cx.notify();
    }

    pub fn check_saved_proxy(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        self.run_saved_proxy_action(proxy_id, false, cx);
    }

    pub fn rotate_saved_proxy_ip(&mut self, proxy_id: &str, cx: &mut Context<Self>) {
        self.run_saved_proxy_action(proxy_id, true, cx);
    }

    fn run_saved_proxy_action(&mut self, proxy_id: &str, rotate: bool, cx: &mut Context<Self>) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let pid = sp.id.clone();
        let proxy_name = sp.name.clone();
        let disp = sp.config.display_short();
        if let Some(prev) = self.proxy_check_tasks.remove(&pid) {
            prev.abort();
        }
        self.checking_proxy_ids.insert(pid.clone());
        self.banner_message = Some(if rotate {
            format!("Rotating IP for '{proxy_name}'...")
        } else {
            format!("Checking proxy '{proxy_name}' ({disp})...")
        });
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        let join_handle = tokio_handle.spawn(async move {
            crate::control::check_or_rotate_saved_proxy(&db, &sp, rotate).await
        });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.proxy_check_tasks.insert(pid.clone(), abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .proxy_check_tasks
                    .get(&pid)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.proxy_check_tasks.remove(&pid);
                    app.checking_proxy_ids.remove(&pid);
                }
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Join error: {e}")),
                };
                if !app.saved_proxies.iter().any(|p| p.id == pid) {
                    return;
                }
                match res {
                    Ok((rot_opt, geo)) => {
                        app.reload_profiles();
                        app.banner_message = Some(match rot_opt {
                            Some(rot) => format!(
                                "Rotated '{proxy_name}' ({rot}) -> {}",
                                geo.summary_badge()
                            ),
                            None => format!("Proxy '{proxy_name}' OK: {}", geo.summary_badge()),
                        });
                    }
                    Err(e) => {
                        app.reload_profiles();
                        app.banner_message =
                            Some(format!("Proxy '{proxy_name}' failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn check_filtered_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let filtered = self.filtered_proxy_indices();
        let ids: Vec<String> = if !self.checked_proxy_ids.is_empty() {
            filtered
                .into_iter()
                .filter_map(|i| {
                    let id = &self.saved_proxies[i].id;
                    self.checked_proxy_ids.contains(id).then(|| id.clone())
                })
                .collect()
        } else {
            filtered
                .into_iter()
                .map(|i| self.saved_proxies[i].id.clone())
                .collect()
        };
        for id in ids {
            self.check_saved_proxy(&id, cx);
        }
    }

    pub fn apply_saved_proxy_to_selected_profile(
        &mut self,
        proxy_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let Some(sel_id) = self.selected_profile_id.clone() else {
            self.banner_message = Some("Select a profile first".to_string());
            cx.notify();
            return;
        };
        let Some(mut prof) = self.profiles.iter().find(|p| p.id == sel_id).cloned() else {
            return;
        };
        prof.assign_saved_proxy(&sp);
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_profile(&prof);
        }
        self.reload_profiles();
        self.select_profile(&sel_id, window, cx);
        self.banner_message = Some(format!(
            "Assigned proxy '{}' (#{}) to profile '{}'",
            sp.name, sp.group_tag, prof.name
        ));
        cx.notify();
    }

    pub fn assign_filtered_proxies_to_profiles(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let proxy_indices = self.filtered_proxy_indices();
        if proxy_indices.is_empty() {
            return;
        }
        let target_indices = self.filtered_profile_indices();
        if target_indices.is_empty() {
            return;
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (idx, &prof_ix) in target_indices.iter().enumerate() {
                    let mut prof = self.profiles[prof_ix].clone();
                    let chosen = &self.saved_proxies[proxy_indices[idx % proxy_indices.len()]];
                    prof.assign_saved_proxy(chosen);
                    let _ = db.upsert_profile(&prof);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.active_view = WorkspaceView::Profiles;
        self.banner_message = Some(format!(
            "Assigned '{}' proxy group round-robin across profiles",
            self.selected_proxy_group
        ));
        cx.notify();
    }

    pub fn proxies_for_batch_group(&self) -> Vec<SavedProxy> {
        if self.batch_proxy_group == "None" {
            return Vec::new();
        }
        self.saved_proxies
            .iter()
            .filter(|sp| {
                self.batch_proxy_group == "All"
                    || sp.group_tag.eq_ignore_ascii_case(&self.batch_proxy_group)
            })
            .cloned()
            .collect()
    }

    fn cancel_modal_proxy_check(&mut self) {
        if let Some(handle) = self.modal_proxy_task.take() {
            handle.abort();
        }
        if let Some(m) = self.modal.as_mut() {
            m.checking_proxy = false;
        }
    }

    pub fn fill_modal_proxy_from_group(
        &mut self,
        group_name: Option<&str>,
        cx: &mut Context<Self>,
    ) {
        self.cancel_modal_proxy_check();
        let chosen_sp = group_name.and_then(|grp| {
            let candidates: Vec<&SavedProxy> = self
                .saved_proxies
                .iter()
                .filter(|sp| sp.group_tag.eq_ignore_ascii_case(grp))
                .collect();
            if candidates.is_empty() {
                None
            } else {
                let idx = (rand::random::<u32>() as usize) % candidates.len();
                Some(candidates[idx].clone())
            }
        });
        if let Some(m) = self.modal.as_mut() {
            match chosen_sp {
                Some(sp) => {
                    m.proxy_mode = ProxyEditMode::SavedPool;
                    m.draft.profile.assign_saved_proxy(&sp);
                    m.proxy_check_error = None;
                    self.banner_message = Some(format!(
                        "Picked proxy '{}' from group '#{}'",
                        sp.name, sp.group_tag
                    ));
                }
                None => {
                    m.draft.profile.clear_proxy();
                    m.proxy_check_error = None;
                }
            }
            cx.notify();
        }
    }

    pub fn set_modal_proxy_mode(
        &mut self,
        mode: ProxyEditMode,
        cx: &mut Context<Self>,
    ) {
        self.cancel_modal_proxy_check();
        if let Some(m) = self.modal.as_mut() {
            m.proxy_mode = mode;
            m.proxy_check_error = None;
            if mode == ProxyEditMode::Direct {
                m.draft.profile.clear_proxy();
            }
            cx.notify();
        }
    }

    pub fn select_saved_proxy_for_modal(
        &mut self,
        proxy_id: &str,
        cx: &mut Context<Self>,
    ) {
        self.cancel_modal_proxy_check();
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        if let Some(m) = self.modal.as_mut() {
            m.proxy_mode = ProxyEditMode::SavedPool;
            m.draft.profile.assign_saved_proxy(&sp);
            m.proxy_check_error = None;
            self.banner_message = Some(format!("Selected proxy '{}' (#{})", sp.name, sp.group_tag));
            cx.notify();
        }
    }

    pub fn set_modal_region_preset(
        &mut self,
        tz: &str,
        loc: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(m) = self.modal.as_mut() {
            let tz_s = tz.to_string();
            let loc_s = loc.to_string();
            m.custom_tz_input = cx.new(|cx| InputState::new(window, cx).default_value(tz_s));
            m.custom_locale_input = cx.new(|cx| InputState::new(window, cx).default_value(loc_s));
            cx.notify();
        }
    }

    pub fn check_modal_proxy(&mut self, cx: &mut Context<Self>) {
        self.cancel_modal_proxy_check();
        let Some(m) = self.modal.as_mut() else {
            return;
        };
        let Some(cfg) = m.draft.profile.proxy.clone() else {
            m.proxy_check_error =
                Some("Select a proxy from Proxy manager before checking".to_string());
            cx.notify();
            return;
        };
        m.checking_proxy = true;
        m.proxy_check_error = None;
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        let cfg_for_db = cfg.clone();

        let join_handle = tokio_handle.spawn(async move {
            crate::control::check_proxy_config_live(&cfg).await
        });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.modal_proxy_task = Some(abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .modal_proxy_task
                    .as_ref()
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.modal_proxy_task = None;
                }
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Join error: {e}")),
                };
                if let Some(m) = app.modal.as_mut() {
                    m.checking_proxy = false;
                    match res {
                        Ok(geo) => {
                            m.draft.profile.resolved_geo = Some(geo.clone());
                            m.proxy_check_error = None;
                            if let Ok(db_guard) = db.lock() {
                                let _ = db_guard.sync_geo_for_proxy_endpoint(&cfg_for_db, &geo);
                            }
                            app.reload_profiles();
                            app.banner_message =
                                Some(format!("Proxy OK: {}", geo.summary_badge()));
                        }
                        Err(e) => {
                            m.draft.profile.resolved_geo = None;
                            m.proxy_check_error = Some(e.to_string());
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn select_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.selected_profile_id = Some(profile_id.to_string());
        self.refresh_selected_bookmarks();
        self.refresh_selected_disk_usage(cx);
        if self.active_view == WorkspaceView::EditProfile
            && let Some(p) = self.profiles.iter().find(|p| p.id == profile_id).cloned()
        {
            self.modal = Some(ProfileModalState::from_profile(
                &self.workspace_root,
                &p,
                true,
                window,
                cx,
            ));
        }
        cx.notify();
    }

    pub fn open_edit_view(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.active_view = WorkspaceView::EditProfile;
        self.select_profile(profile_id, window, cx);
    }

    pub fn open_edit_cookies_view(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.active_view = WorkspaceView::EditProfile;
        self.select_profile(profile_id, window, cx);
        if let Some(m) = self.modal.as_mut() {
            m.active_tab = profile_modal::ProfileEditorTab::Cookies;
        }
        cx.notify();
    }

    pub fn randomize_profile_seed(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(mut p) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        p.reseed();
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_profile(&p);
        }
        self.reload_profiles();
        self.select_profile(profile_id, window, cx);
        self.banner_message = Some(format!("Reseeded '{}' -> #{}", p.name, p.seed));
        cx.notify();
    }

    pub fn generate_batch_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let prefix = {
            let s = self.batch_prefix_input.read(cx).value().trim().to_string();
            if s.is_empty() {
                "Account".to_string()
            } else {
                s
            }
        };
        let group = self.batch_selected_group.trim().to_string();
        let pool = self.proxies_for_batch_group();
        let requested_count = self
            .batch_count_input
            .read(cx)
            .value()
            .trim()
            .parse::<usize>()
            .unwrap_or(5)
            .clamp(1, 50);

        let mut created = Vec::new();
        let base_idx = self.profiles.len() + 1;

        for i in 0..requested_count {
            let mut p =
                Profile::new_default(format!("{prefix}-{:02}", base_idx + i), self.batch_os);
            p.set_brand(self.batch_brand);
            p.group_tag = group.clone();
            if !pool.is_empty() {
                p.assign_saved_proxy(&pool[i % pool.len()]);
            }
            created.push(p);
        }

        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for p in &created {
                    let _ = db.upsert_profile(p);
                }
                Ok(())
            });
        }
        let count = created.len();
        let last_id = created.last().map(|p| p.id.clone());
        self.reload_profiles();
        if let Some(id) = last_id {
            self.select_profile(&id, window, cx);
        }
        self.active_view = WorkspaceView::Profiles;
        self.banner_message = Some(if group.is_empty() {
            format!("Created {count} profiles")
        } else {
            format!("Created {count} profiles in folder '{group}'")
        });
        cx.notify();
    }

    pub fn export_all_profiles_backup(&mut self, cx: &mut Context<Self>) {
        if let Ok(db) = self.db.lock() {
            match db.export_profiles_json() {
                Ok((path, json)) => {
                    cx.write_to_clipboard(ClipboardItem::new_string(json));
                    self.banner_message = Some(format!(
                        "Exported all profiles JSON to clipboard & {}",
                        path.display()
                    ));
                }
                Err(e) => {
                    self.banner_message = Some(format!("Export failed: {e}"));
                }
            }
            cx.notify();
        }
    }

    pub fn cancel_extension_task(&mut self, ext_id: &str) -> bool {
        if let Some((handle, flag)) = self.ext_tasks.remove(ext_id) {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            handle.abort();
            true
        } else {
            false
        }
    }

    pub fn close_popup_modal(&mut self, cx: &mut Context<Self>) {
        if let Some((handle, flag)) = self.ext_url_task.take() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            handle.abort();
        }
        if self.downloading_ext {
            self.downloading_ext = false;
            self.banner_message = Some("Canceled extension download".to_string());
        }
        self.popup_modal = None;
        cx.notify();
    }

    pub fn toggle_extension(&mut self, ext_id: &str, cx: &mut Context<Self>) {
        let Some(ext) = self.extensions.iter().find(|e| e.id == ext_id).cloned() else {
            return;
        };
        let was_downloading = self.cancel_extension_task(ext_id);
        let next_enabled = !ext.enabled;
        if let Ok(db) = self.db.lock() {
            let _ = db.set_extension_enabled(ext_id, next_enabled);
        }
        self.reload_extensions_only();

        let target_dir = self.workspace_root.join("extensions").join(&ext.id);

        if next_enabled {
            if crate::extensions::needs_remote_extension_download_in(&self.workspace_root, &ext) {
                let eid = ext.id.clone();
                let ename = ext.name.clone();
                let ext_for_task = ext.clone();
                let root_for_task = self.workspace_root.clone();
                let tokio_handle = self.tokio_handle.clone();
                let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let flag_for_task = cancel_flag.clone();
                let flag_for_ui = cancel_flag.clone();

                let join_handle = tokio_handle.spawn(async move {
                    crate::extensions::activate_extension_cancellable_in(
                        &root_for_task,
                        ext_for_task,
                        &flag_for_task,
                    )
                    .await
                });
                self.ext_tasks
                    .insert(eid.clone(), (join_handle.abort_handle(), cancel_flag));
                self.banner_message = Some(format!("Downloading & activating {}...", ext.name));

                cx.spawn(async move |this, cx| {
                    let res = join_handle.await;
                    let _ = this.update(cx, |app, cx| {
                        if app
                            .ext_tasks
                            .get(&eid)
                            .is_some_and(|(_, f)| Arc::ptr_eq(f, &flag_for_ui))
                        {
                            app.ext_tasks.remove(&eid);
                        }
                        let still_enabled = app
                            .extensions
                            .iter()
                            .any(|e| e.id == eid && e.enabled);
                        if flag_for_ui.load(std::sync::atomic::Ordering::SeqCst) || !still_enabled {
                            cx.notify();
                            return;
                        }
                        match res {
                            Ok(Ok(updated_ext)) => {
                                if let Ok(db) = app.db.lock() {
                                    let _ = db.upsert_extension(&updated_ext);
                                }
                                app.reload_extensions_only();
                                app.banner_message =
                                    Some(format!("Activated & synced extension: {ename}"));
                            }
                            Ok(Err(e)) => {
                                if let Ok(db) = app.db.lock() {
                                    let _ = db.set_extension_enabled(&eid, false);
                                }
                                app.reload_extensions_only();
                                app.banner_message =
                                    Some(format!("Extension sync failed ({ename}): {e}"));
                            }
                            Err(e) if e.is_cancelled() => {}
                            Err(e) => {
                                if let Ok(db) = app.db.lock() {
                                    let _ = db.set_extension_enabled(&eid, false);
                                }
                                app.reload_extensions_only();
                                app.banner_message =
                                    Some(format!("Extension task error ({ename}): {e}"));
                            }
                        }
                        cx.notify();
                    });
                })
                .detach();
            } else {
                let _ = crate::extensions::ensure_extension_unpacked_in(&self.workspace_root, &ext);
                self.banner_message = Some(format!("Enabled extension: {}", ext.name));
            }
        } else {
            if was_downloading && crate::extensions::is_placeholder_extension_dir(&target_dir) {
                crate::extensions::remove_extension_files_in(&self.workspace_root, ext_id);
            }
            self.banner_message = Some(if was_downloading {
                format!("Stopped download & disabled extension: {}", ext.name)
            } else {
                format!("Disabled extension: {}", ext.name)
            });
        }
        cx.notify();
    }

    pub fn open_or_copy_extension_agent_cli(&mut self, ext_id: &str, cx: &mut Context<Self>) {
        let Some(ext) = self.extensions.iter().find(|e| e.id == ext_id).cloned() else {
            return;
        };
        let Some((_runtime_id, entry_url)) =
            crate::extensions::resolve_extension_runtime_info_in(&self.workspace_root, &ext)
        else {
            self.banner_message = Some(format!("Enable '{}' first to unpack its manifest", ext.name));
            cx.notify();
            return;
        };

        let running_target = self
            .selected_profile_id
            .as_ref()
            .and_then(|pid| {
                let prof = self.profiles.iter().find(|p| &p.id == pid)?;
                match self.statuses.get(pid) {
                    Some(ProfileStatus::Running(info)) => {
                        Some((prof.short_id(), info.ws_url.clone()))
                    }
                    _ => None,
                }
            })
            .or_else(|| {
                self.profiles.iter().find_map(|p| match self.statuses.get(&p.id) {
                    Some(ProfileStatus::Running(info)) => {
                        Some((p.short_id(), info.ws_url.clone()))
                    }
                    _ => None,
                })
            });

        if let Some((short_id, ws_url)) = running_target {
            let cli = format!(
                "agent-browser --session bon_{short_id} tab new \"{entry_url}\" && agent-browser --session bon_{short_id} snapshot -i"
            );
            cx.write_to_clipboard(ClipboardItem::new_string(cli));
            let ename = ext.name.clone();
            let tokio_handle = self.tokio_handle.clone();
            self.banner_message = Some(format!(
                "Opening {} in bon_{short_id} & copied Agent CLI...",
                ext.name
            ));
            cx.notify();
            let root_dir = self.workspace_root.clone();
            cx.spawn(async move |this, cx| {
                let res = tokio_handle
                    .spawn_blocking(move || {
                        crate::launcher::agent_open_extension_tab_in(
                            &root_dir, &short_id, &ws_url, &entry_url,
                        )
                    })
                    .await;
                let _ = this.update(cx, |app, cx| {
                    if let Ok(Ok(next_cmd)) = res {
                        app.banner_message =
                            Some(format!("Opened {ename} tab! Next: {next_cmd}"));
                    }
                    cx.notify();
                });
            })
            .detach();
        } else {
            let cli = format!("agent-browser tab new \"{entry_url}\" && agent-browser snapshot -i");
            cx.write_to_clipboard(ClipboardItem::new_string(cli));
            self.banner_message = Some(format!(
                "Copied {} Agent CLI ({entry_url})",
                ext.name
            ));
            cx.notify();
        }
    }
    fn choose_macos_file_blocking(prompt: &str, types: &[&str]) -> Option<String> {
        let type_clause = if types.is_empty() {
            String::new()
        } else {
            let quoted: Vec<String> = types.iter().map(|t| format!("\"{t}\"")).collect();
            format!(" of type {{{}}}", quoted.join(", "))
        };
        let script = format!("POSIX path of (choose file with prompt \"{prompt}\"{type_clause})");
        std::process::Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn pick_extension_file_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        let input_entity = self.ext_file_input.clone();
        cx.spawn_in(window, async move |this, cx| {
            let chosen = tokio_handle
                .spawn_blocking(|| {
                    Self::choose_macos_file_blocking("Choose Extension File (.CRX or .ZIP)", &[])
                })
                .await
                .ok()
                .flatten();

            if let Some(path_str) = chosen {
                let _ = this.update_in(cx, |app, window, cx| {
                    let _ = input_entity;
                    app.ext_file_input = cx.new(|cx| {
                        InputState::new(window, cx)
                            .placeholder("Path to .CRX or .ZIP file")
                            .default_value(path_str)
                    });
                    cx.notify();
                });
            }
        })
        .detach();
    }

    pub fn upload_extension_from_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let raw_path = self.ext_file_input.read(cx).value().trim().to_string();
        let tokio_handle = self.tokio_handle.clone();
        let db_arc = self.db.clone();
        let root_dir = self.workspace_root.clone();
        self.banner_message = Some("Installing extension...".to_string());
        cx.notify();

        cx.spawn_in(window, async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    let path_str = if raw_path.is_empty() {
                        Self::choose_macos_file_blocking(
                            "Choose Extension File (.CRX or .ZIP)",
                            &[],
                        )
                        .ok_or_else(|| anyhow::anyhow!("Canceled file selection"))?
                    } else {
                        raw_path
                    };
                    crate::extensions::install_extension_from_file_in(
                        &root_dir,
                        std::path::Path::new(&path_str),
                    )
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Upload task error: {e}")));

            let _ = this.update_in(cx, |app, window, cx| {
                match res {
                    Ok(ext) => {
                        let ext_name = ext.name.clone();
                        if let Ok(db) = db_arc.lock() {
                            let _ = db.upsert_extension(&ext);
                        }
                        workspace_views::invalidate_extension_icon_cache(&ext.id);
                        app.reload_profiles();
                        app.ext_file_input = cx.new(|cx| {
                            InputState::new(window, cx).placeholder("Path to .CRX or .ZIP file")
                        });
                        app.popup_modal = None;
                        app.banner_message = Some(format!("Uploaded extension: {ext_name}"));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if msg.contains("Canceled") {
                            app.banner_message = None;
                        } else {
                            app.banner_message = Some(format!("Upload Extension failed: {msg}"));
                        }
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn download_extension_from_url_input(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let url = self.ext_url_input.read(cx).value().trim().to_string();
        if url.is_empty() {
            self.banner_message = Some("Please paste a Chrome Web Store or .CRX/.ZIP URL".to_string());
            cx.notify();
            return;
        }
        if self.downloading_ext {
            return;
        }
        if let Some((handle, flag)) = self.ext_url_task.take() {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            handle.abort();
        }
        self.downloading_ext = true;
        self.banner_message = Some("Downloading extension...".to_string());
        cx.notify();

        let db_arc = self.db.clone();
        let tokio_handle = self.tokio_handle.clone();
        let root_dir = self.workspace_root.clone();
        let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag_for_task = cancel_flag.clone();
        let flag_for_ui = cancel_flag.clone();
        self.ext_url_input = cx.new(|cx| InputState::new(window, cx).placeholder("Input URL"));

        let join_handle = tokio_handle.spawn(async move {
            crate::extensions::download_extension_from_url_cancellable_in(
                &root_dir,
                &url,
                None,
                &flag_for_task,
            )
            .await
        });
        self.ext_url_task = Some((join_handle.abort_handle(), cancel_flag));

        cx.spawn(async move |this, cx| {
            let res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .ext_url_task
                    .as_ref()
                    .is_some_and(|(_, f)| Arc::ptr_eq(f, &flag_for_ui))
                {
                    app.ext_url_task = None;
                    app.downloading_ext = false;
                }
                if flag_for_ui.load(std::sync::atomic::Ordering::SeqCst) {
                    cx.notify();
                    return;
                }
                match res {
                    Ok(Ok(ext)) => {
                        let ext_name = ext.name.clone();
                        if let Ok(db) = db_arc.lock() {
                            let _ = db.upsert_extension(&ext);
                        }
                        workspace_views::invalidate_extension_icon_cache(&ext.id);
                        app.reload_profiles();
                        app.popup_modal = None;
                        app.banner_message = Some(format!("Downloaded extension: {ext_name}"));
                    }
                    Ok(Err(e)) => {
                        app.banner_message = Some(format!("Download Extension error: {e}"));
                    }
                    Err(e) if e.is_cancelled() => {}
                    Err(e) => {
                        app.banner_message = Some(format!("Download task error: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn request_delete(&mut self, action: PendingDeleteAction, cx: &mut Context<Self>) {
        self.popup_modal = Some(ActivePopupModal::ConfirmDelete(action));
        cx.notify();
    }

    pub fn confirm_pending_delete(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::ConfirmDelete(action)) = self.popup_modal.take() else {
            self.popup_modal = None;
            cx.notify();
            return;
        };
        match action {
            PendingDeleteAction::Profile(id) => {
                self.delete_profile(&id, window, cx);
            }
            PendingDeleteAction::CheckedProfiles => {
                self.delete_checked_profiles(window, cx);
            }
            PendingDeleteAction::PermanentProfile(id) => {
                self.permanently_delete_profile(&id, window, cx);
            }
            PendingDeleteAction::EmptyTrash => {
                self.empty_trash(window, cx);
            }
            PendingDeleteAction::Group(grp) => {
                self.delete_group_and_reset(&grp, window, cx);
            }
            PendingDeleteAction::Proxy(pid) => {
                self.delete_saved_proxy(&pid, cx);
            }
            PendingDeleteAction::CheckedProxies => {
                self.delete_checked_saved_proxies(cx);
            }
            PendingDeleteAction::Tag(tag) => {
                self.delete_tag_and_reset(&tag, cx);
            }
            PendingDeleteAction::Extension(ext_id) => {
                self.cancel_extension_task(&ext_id);
                let ext_name = self
                    .extensions
                    .iter()
                    .find(|e| e.id == ext_id)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| ext_id.clone());
                let removed = self
                    .db
                    .lock()
                    .ok()
                    .and_then(|db| db.delete_extension(&ext_id).ok())
                    .unwrap_or(false);
                if removed {
                    crate::extensions::remove_extension_files_in(&self.workspace_root, &ext_id);
                    workspace_views::invalidate_extension_icon_cache(&ext_id);
                    self.reload_profiles();
                    self.banner_message = Some(format!("Removed extension: {ext_name}"));
                } else {
                    self.banner_message = Some("Default extensions cannot be deleted".to_string());
                }
                cx.notify();
            }
            PendingDeleteAction::WipeProfile(id) => {
                self.wipe_single_profile_data(&id, cx);
            }
        }
    }

    pub fn toggle_profile_sort(&mut self, col: ProfileSortColumn, cx: &mut Context<Self>) {
        if self.sort_col == Some(col) {
            self.sort_asc = !self.sort_asc;
        } else {
            self.sort_col = Some(col);
            self.sort_asc = !matches!(col, ProfileSortColumn::Updated | ProfileSortColumn::Status);
        }
        cx.notify();
    }

    pub fn filtered_profile_indices_rc(&self) -> std::rc::Rc<[usize]> {
        let rev = self.profile_data_rev;
        let status_sig = if self.sort_col == Some(ProfileSortColumn::Status) {
            self.statuses
                .iter()
                .fold(0usize, |acc, (k, st)| {
                    let r: usize = match st {
                        ProfileStatus::Running(_) => 3,
                        ProfileStatus::Starting => 2,
                        ProfileStatus::Error => 1,
                        ProfileStatus::Stopped => 0,
                    };
                    acc.wrapping_add(k.len().wrapping_mul(31).wrapping_add(r))
                })
        } else {
            0
        };
        if let Some((c_rev, c_q, c_grp, c_col, c_asc, c_sig, cached)) =
            self.profile_indices_cache.borrow().as_ref()
            && *c_rev == rev
            && c_q == &self.search_query
            && c_grp == &self.selected_group
            && *c_col == self.sort_col
            && *c_asc == self.sort_asc
            && *c_sig == status_sig
        {
            return cached.clone();
        }
        let group_opt = (self.selected_group != "All").then_some(self.selected_group.as_str());
        let mut out: Vec<usize> = self
            .profiles
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.matches_filter(&self.search_query, group_opt).then_some(i))
            .collect();
        if let Some(col) = self.sort_col {
            let asc = self.sort_asc;
            let status_rank = |id: &str| -> u8 {
                match self.statuses.get(id) {
                    Some(ProfileStatus::Running(_)) => 3,
                    Some(ProfileStatus::Starting) => 2,
                    Some(ProfileStatus::Error) => 1,
                    _ => 0,
                }
            };
            let cmp_ci = |s1: &str, s2: &str| {
                s1.bytes()
                    .map(|b| b.to_ascii_lowercase())
                    .cmp(s2.bytes().map(|b| b.to_ascii_lowercase()))
            };
            out.sort_by(|&ia, &ib| {
                let a = &self.profiles[ia];
                let b = &self.profiles[ib];
                let empty_ord = match col {
                    ProfileSortColumn::Tags => {
                        let a_empty = a.tags.is_empty() && a.group_tag.trim().is_empty();
                        let b_empty = b.tags.is_empty() && b.group_tag.trim().is_empty();
                        a_empty.cmp(&b_empty)
                    }
                    ProfileSortColumn::Notes => {
                        a.notes.trim().is_empty().cmp(&b.notes.trim().is_empty())
                    }
                    ProfileSortColumn::Proxy => a.proxy.is_none().cmp(&b.proxy.is_none()),
                    _ => std::cmp::Ordering::Equal,
                };
                if empty_ord != std::cmp::Ordering::Equal {
                    return empty_ord;
                }
                let ord = match col {
                    ProfileSortColumn::Id => cmp_ci(&a.id, &b.id),
                    ProfileSortColumn::Name => cmp_ci(&a.name, &b.name),
                    ProfileSortColumn::Tags => {
                        let a_lbl = a
                            .tags
                            .first()
                            .map(String::as_str)
                            .unwrap_or(a.group_tag.trim());
                        let b_lbl = b
                            .tags
                            .first()
                            .map(String::as_str)
                            .unwrap_or(b.group_tag.trim());
                        cmp_ci(a_lbl, b_lbl)
                    }
                    ProfileSortColumn::Notes => cmp_ci(a.notes.trim(), b.notes.trim()),
                    ProfileSortColumn::Proxy => match (&a.proxy, &b.proxy) {
                        (Some(pa), Some(pb)) => {
                            cmp_ci(&pa.host, &pb.host).then_with(|| pa.port.cmp(&pb.port))
                        }
                        _ => std::cmp::Ordering::Equal,
                    },
                    ProfileSortColumn::Updated => a
                        .last_launched_at
                        .unwrap_or(0)
                        .cmp(&b.last_launched_at.unwrap_or(0))
                        .then_with(|| a.created_at.cmp(&b.created_at)),
                    ProfileSortColumn::Status => status_rank(&a.id).cmp(&status_rank(&b.id)),
                };
                let final_ord = if asc { ord } else { ord.reverse() };
                final_ord.then_with(|| b.created_at.cmp(&a.created_at))
            });
        }
        let rc: std::rc::Rc<[usize]> = out.into();
        *self.profile_indices_cache.borrow_mut() = Some((
            rev,
            self.search_query.clone(),
            self.selected_group.clone(),
            self.sort_col,
            self.sort_asc,
            status_sig,
            rc.clone(),
        ));
        rc
    }

    pub fn filtered_profile_indices(&self) -> Vec<usize> {
        self.filtered_profile_indices_rc().to_vec()
    }

    pub fn distinct_groups_with_counts(&self) -> Vec<(String, usize)> {
        self.cached_group_counts.clone()
    }

    pub fn open_create_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let default_name = format!("Profile-{:02}", self.profiles.len() + 1);
        let template = Profile::new_default(default_name, PlatformType::MacOS);
        self.modal = Some(ProfileModalState::from_profile(
            &self.workspace_root,
            &template,
            false,
            window,
            cx,
        ));
        self.active_view = WorkspaceView::EditProfile;
        cx.notify();
    }

    pub fn save_modal_profile(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(m) = self.modal.as_mut() {
            let n = m.bookmark_name_input.clone();
            let u = m.bookmark_url_input.clone();
            profile_modal::push_bookmark_from_inputs(&mut m.bookmarks, &n, &u, window, cx);
        }
        let Some(modal) = self.modal.as_ref() else {
            return;
        };
        let cookies_raw = modal.cookies_input.read(cx).value().to_string();
        let bm_items = modal.bookmarks.clone();
        match modal.build_profile(cx) {
            Ok(profile) => {
                let save_res = self
                    .db
                    .lock()
                    .map_err(|_| anyhow::anyhow!("Database lock poisoned"))
                    .and_then(|db| db.save_profile_bundle(&profile, Some(&cookies_raw), Some(&bm_items)));
                let normalized_cookies = match save_res {
                    Ok(bundle_opt) => bundle_opt,
                    Err(e) => {
                        let msg = e.to_string();
                        if let Some(m) = self.modal.as_mut() {
                            if msg.contains("Bookmark") {
                                m.active_tab = profile_modal::ProfileEditorTab::Bookmarks;
                            } else if !cookies_raw.trim().is_empty() && !msg.contains("SQLite") {
                                m.active_tab = profile_modal::ProfileEditorTab::Cookies;
                            }
                            m.validation_error = Some(msg);
                        }
                        cx.notify();
                        return;
                    }
                };

                let saved_id = profile.id.clone();
                let saved_name = profile.name.clone();
                let live_pair = self.running_session_pair(&saved_id);
                self.reload_profiles();
                self.select_profile(&saved_id, window, cx);
                self.active_view = WorkspaceView::Profiles;
                if let (Some((sid, ws_url)), Some(bundle)) = (live_pair, normalized_cookies) {
                    let badge = bundle.summary_badge();
                    let state_str = bundle.to_state_json_pretty();
                    let tokio_handle = self.tokio_handle.clone();
                    let prof_name = saved_name.clone();
                    self.banner_message = Some(format!(
                        "Saved '{saved_name}' & injecting {badge} into live browser..."
                    ));
                    cx.notify();
                    let root_dir = self.workspace_root.clone();
                    cx.spawn(async move |this, cx| {
                        let res = tokio_handle
                            .spawn_blocking(move || {
                                crate::launcher::agent_import_state_or_cookies_in(
                                    &root_dir, &sid, &ws_url, &state_str,
                                )
                            })
                            .await
                            .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
                        let _ = this.update(cx, |app, cx| {
                            app.banner_message = Some(match res {
                                Ok(msg) => format!("Saved '{prof_name}' • {msg}"),
                                Err(e) => format!("Saved '{prof_name}', live cookie inject failed: {e}"),
                            });
                            cx.notify();
                        });
                    })
                    .detach();
                } else {
                    self.banner_message = Some(format!("Saved profile '{saved_name}'"));
                    cx.notify();
                }
            }
            Err(e) => {
                if let Some(m) = self.modal.as_mut() {
                    m.validation_error = Some(e.to_string());
                }
                cx.notify();
            }
        }
    }

    pub fn set_modal_cookies_text(
        &mut self,
        text: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(m) = self.modal.as_mut() else {
            return;
        };
        m.validation_error = None;
        m.cookies_input = cx.new(|cx| {
            crate::ui::input::TextareaState::new(window, cx)
                .rows(14)
                .placeholder("Paste Cookie-Editor JSON [...], State JSON, J2Team JSON, Netscape .txt, cURL, or key=value...")
                .default_value(text)
        });
        cx.notify();
    }

    pub fn pick_modal_cookie_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        let startup_url = self
            .modal
            .as_ref()
            .map(|m| m.startup_url_input.read(cx).value().to_string())
            .unwrap_or_default();
        cx.spawn_in(window, async move |this, cx| {
            let loaded = tokio_handle
                .spawn_blocking(move || -> anyhow::Result<Option<(String, String)>> {
                    let Some(path_str) = Self::choose_macos_file_blocking(
                        "Choose Cookie File (.json or .txt)",
                        &[],
                    ) else {
                        return Ok(None);
                    };
                    let raw = std::fs::read_to_string(&path_str)?;
                    Ok(Some((path_str, raw)))
                })
                .await
                .unwrap_or(Ok(None));

            let _ = this.update_in(cx, |app, window, cx| match loaded {
                Ok(Some((path_str, raw))) => {
                    match crate::launcher::parse_and_normalize_cookies(&raw, Some(&startup_url)) {
                        Ok(bundle) => {
                            let badge = bundle.summary_badge();
                            app.set_modal_cookies_text(bundle.to_state_json_pretty(), window, cx);
                            app.banner_message =
                                Some(format!("Imported {badge} from {path_str}"));
                        }
                        Err(e) => {
                            app.set_modal_cookies_text(raw, window, cx);
                            if let Some(m) = app.modal.as_mut() {
                                m.validation_error = Some(format!("Cookie file error: {e}"));
                            }
                        }
                    }
                    cx.notify();
                }
                Ok(None) => {}
                Err(e) => {
                    app.banner_message = Some(format!("Failed to read cookie file: {e}"));
                    cx.notify();
                }
            });
        })
        .detach();
    }

    pub fn paste_modal_cookies_from_clipboard(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(clip) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            self.banner_message = Some("Clipboard is empty".to_string());
            cx.notify();
            return;
        };
        if clip.trim().is_empty() {
            self.banner_message = Some("Clipboard text is empty".to_string());
            cx.notify();
            return;
        }
        let startup_url = self
            .modal
            .as_ref()
            .map(|m| m.startup_url_input.read(cx).value().to_string())
            .unwrap_or_default();
        match crate::launcher::parse_and_normalize_cookies(&clip, Some(&startup_url)) {
            Ok(bundle) => {
                let badge = bundle.summary_badge();
                self.set_modal_cookies_text(bundle.to_state_json_pretty(), window, cx);
                self.banner_message = Some(format!("Pasted & normalized {badge}"));
            }
            Err(_) => {
                self.set_modal_cookies_text(clip, window, cx);
                self.banner_message = Some("Pasted raw text from clipboard".to_string());
            }
        }
        cx.notify();
    }

    pub fn format_modal_cookies(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(m) = self.modal.as_ref() else {
            return;
        };
        let raw = m.cookies_input.read(cx).value().to_string();
        let startup_url = m.startup_url_input.read(cx).value().to_string();
        if raw.trim().is_empty() {
            return;
        }
        match crate::launcher::parse_and_normalize_cookies(&raw, Some(&startup_url)) {
            Ok(bundle) => {
                let badge = bundle.summary_badge();
                self.set_modal_cookies_text(bundle.to_state_json_pretty(), window, cx);
                self.banner_message = Some(format!("Normalized {badge}"));
            }
            Err(e) => {
                if let Some(m) = self.modal.as_mut() {
                    m.validation_error = Some(format!("Cookie format error: {e}"));
                }
            }
        }
        cx.notify();
    }

    pub fn clone_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(orig) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let Some(cloned) = self
            .db
            .lock()
            .ok()
            .and_then(|db| db.clone_profiles(&orig, 1, None).ok())
            .and_then(|mut v| v.pop())
        else {
            return;
        };
        let new_id = cloned.id.clone();
        self.reload_profiles();
        self.select_profile(&new_id, window, cx);
        self.banner_message = Some(format!(
            "Cloned '{}' -> seed #{}",
            cloned.name, cloned.seed
        ));
        cx.notify();
    }
    pub fn open_clone_modal(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(orig) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let orig_name = orig.name.clone();
        let target_id = orig.id.clone();
        let count_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("1–50")
                .default_value("3")
        });
        let prefix_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Name prefix")
                .default_value(format!("{orig_name} Copy"))
        });
        self.popup_modal = Some(ActivePopupModal::CloneProfile(CloneProfileModalState {
            target_id,
            count_input,
            prefix_input,
        }));
        cx.notify();
    }

    pub fn submit_clone_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::CloneProfile(cm)) = self.popup_modal.take() else {
            return;
        };
        let Some(src) = self.profiles.iter().find(|p| p.id == cm.target_id).cloned() else {
            return;
        };
        let count = cm
            .count_input
            .read(cx)
            .value()
            .trim()
            .parse::<usize>()
            .unwrap_or(1)
            .clamp(1, 50);
        let prefix = cm.prefix_input.read(cx).value().trim().to_string();
        let last_id = self
            .db
            .lock()
            .ok()
            .and_then(|db| db.clone_profiles(&src, count, Some(&prefix)).ok())
            .and_then(|v| v.last().map(|p| p.id.clone()));
        self.popup_modal = None;
        self.reload_profiles();
        if let Some(id) = last_id {
            self.select_profile(&id, window, cx);
        }
        self.banner_message = Some(format!("Cloned {count} profile(s) from '{}'", src.name));
        cx.notify();
    }

    pub fn wipe_single_profile_data(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        if matches!(
            self.statuses.get(profile_id),
            Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
        ) {
            self.banner_message =
                Some("Stop the browser before wiping profile data".to_string());
            cx.notify();
            return;
        }
        if let Some(prev) = self.profile_aux_tasks.remove(profile_id) {
            prev.abort();
        }
        let pid = prof.id.clone();
        let pid_done = pid.clone();
        let name = prof.name.clone();
        if self.selected_profile_id.as_deref() == Some(profile_id) {
            self.selected_disk_usage = "0 B".to_string();
        }
        self.banner_message = Some(format!("Wiping browser data for '{name}'..."));
        cx.notify();
        let root_dir = self.workspace_root.clone();
        let tokio_handle = self.tokio_handle.clone();
        let join_handle =
            tokio_handle.spawn_blocking(move || crate::launcher::wipe_profile_data_in(&root_dir, &pid));
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.profile_aux_tasks
            .insert(profile_id.to_string(), abort_handle);
        cx.spawn(async move |this, cx| {
            let res = join_handle
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                if app
                    .profile_aux_tasks
                    .get(&pid_done)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.profile_aux_tasks.remove(&pid_done);
                }
                app.banner_message = Some(match res {
                    Ok(()) => format!("Wiped browser data for '{name}' (profile config kept)"),
                    Err(e) => format!("Wipe data failed: {e}"),
                });
                cx.notify();
            });
        })
        .detach();
    }

    pub fn reseed_checked_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        if targets.is_empty() {
            return;
        }
        let count = targets.len();
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for mut p in targets {
                    p.reseed();
                    let _ = db.upsert_profile(&p);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(format!("Reseeded fingerprints for {count} profile(s)"));
        cx.notify();
    }

    pub fn rotate_proxies_for_checked(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| {
                self.checked_profile_ids.contains(&p.id)
                    && p.proxy
                        .as_ref()
                        .and_then(|px| px.change_ip_url.as_ref())
                        .is_some()
            })
            .map(|p| p.id.clone())
            .collect();
        if ids.is_empty() {
            self.banner_message =
                Some("No checked profiles have a proxy rotation URL configured".to_string());
            cx.notify();
            return;
        }
        for id in ids {
            self.rotate_profile_proxy_ip(&id, cx);
        }
    }

    pub fn rotate_checked_saved_proxies(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .saved_proxies
            .iter()
            .filter(|sp| {
                self.checked_proxy_ids.contains(&sp.id) && sp.config.change_ip_url.is_some()
            })
            .map(|sp| sp.id.clone())
            .collect();
        if ids.is_empty() {
            self.banner_message =
                Some("No selected proxies have a rotation URL (|http://...)".to_string());
            cx.notify();
            return;
        }
        for id in ids {
            self.rotate_saved_proxy_ip(&id, cx);
        }
    }

    pub fn open_edit_proxy_modal(
        &mut self,
        proxy_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let name_val = sp.name.clone();
        let rot_val = sp.config.change_ip_url.clone().unwrap_or_default();
        let exp_val = sp
            .expired_at
            .map(crate::models::format_unix_dd_mm_yyyy)
            .unwrap_or_default();
        let name_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Proxy name")
                .default_value(name_val)
        });
        let rotate_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Rotation webhook URL (http://...)")
                .default_value(rot_val)
        });
        let expire_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("DD/MM/YYYY or days (empty = no expiry)")
                .default_value(exp_val)
        });
        self.popup_modal = Some(ActivePopupModal::EditProxy(EditProxyModalState {
            proxy_id: sp.id,
            selected_tag: sp.group_tag,
            name_input,
            rotate_input,
            expire_input,
        }));
        cx.notify();
    }

    pub fn save_edit_proxy_modal(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::EditProxy(em)) = self.popup_modal.as_ref() else {
            return;
        };
        let Some(mut sp) = self
            .saved_proxies
            .iter()
            .find(|p| p.id == em.proxy_id)
            .cloned()
        else {
            self.popup_modal = None;
            return;
        };
        let rot_raw = em.rotate_input.read(cx).value().trim().to_string();
        let next_rot = if rot_raw.is_empty()
            || rot_raw.eq_ignore_ascii_case("none")
            || rot_raw.eq_ignore_ascii_case("clear")
        {
            None
        } else if rot_raw.starts_with("http://") || rot_raw.starts_with("https://") {
            Some(rot_raw)
        } else {
            self.banner_message =
                Some("Rotation URL must start with http:// or https:// (or leave empty)".to_string());
            cx.notify();
            return;
        };
        let exp_raw = em.expire_input.read(cx).value().trim().to_string();
        let next_exp = match crate::models::SavedProxy::parse_expiration_strict(&exp_raw) {
            Ok(exp) => exp,
            Err(msg) => {
                self.banner_message = Some(msg.to_string());
                cx.notify();
                return;
            }
        };
        let new_name = em.name_input.read(cx).value().trim().to_string();
        if !new_name.is_empty() {
            sp.name = new_name;
        }
        sp.group_tag = em.selected_tag.trim().to_string();
        sp.config.change_ip_url = next_rot;
        sp.expired_at = next_exp;
        if let Ok(db) = self.db.lock() {
            let _ = db.upsert_proxy(&sp);
        }
        self.popup_modal = None;
        self.reload_profiles();
        self.banner_message = Some(format!("Updated proxy '{}'", sp.name));
        cx.notify();
    }

    pub fn pick_and_import_json_ui(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        cx.spawn_in(window, async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || -> anyhow::Result<Option<(String, usize)>> {
                    let Some(path_str) = Self::choose_macos_file_blocking(
                        "Choose BonLogin Profiles JSON Backup",
                        &["json"],
                    ) else {
                        return Ok(None);
                    };
                    let raw = std::fs::read_to_string(&path_str)?;
                    let count = db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("DB lock error"))?
                        .import_profiles_json(&raw)?;
                    Ok(Some((path_str, count)))
                })
                .await
                .unwrap_or(Ok(None));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(Some((path_str, count))) => {
                        app.reload_profiles();
                        app.banner_message =
                            Some(format!("Imported {count} profile(s) from JSON ({path_str})"));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        app.banner_message = Some(format!("JSON import failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn broadcast_totp_to_checked_running(&mut self, cx: &mut Context<Self>) {
        let targets: Vec<(Profile, u16)> = self
            .profiles
            .iter()
            .filter(|p| {
                (self.checked_profile_ids.is_empty() || self.checked_profile_ids.contains(&p.id))
                    && !p.totp_secret.trim().is_empty()
            })
            .filter_map(|p| match self.statuses.get(&p.id) {
                Some(ProfileStatus::Running(info)) => Some((p.clone(), info.cdp_port)),
                _ => None,
            })
            .collect();
        if targets.is_empty() {
            self.banner_message =
                Some("No running profiles with 2FA secret configured".to_string());
            cx.notify();
            return;
        }
        let total = targets.len();
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let ok_count = tokio_handle
                .spawn_blocking(move || {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = targets
                            .into_iter()
                            .map(|(p, port)| {
                                s.spawn(move || crate::launcher::cdp_type_totp(&p, port).is_ok())
                            })
                            .collect();
                        handles
                            .into_iter()
                            .filter_map(|h| h.join().ok().filter(|&ok| ok))
                            .count()
                    })
                })
                .await
                .unwrap_or(0);
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(format!(
                    "Typed 2FA TOTP code across {ok_count}/{total} running browser(s)"
                ));
                cx.notify();
            });
        })
        .detach();
    }

    pub fn copy_pinned_tab_cli(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let short_id = prof.short_id();
        let cmd = if let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id).cloned() {
            let sid = short_id.clone();
            let ws = info.ws_url.clone();
            let root_dir = self.workspace_root.clone();
            self.tokio_handle.spawn_blocking(move || {
                let _ = crate::launcher::ensure_agent_browser_pinned_tab_in(
                    &root_dir, &sid, "tab1", &ws, None,
                );
            });
            format!(
                "{} && agent-browser --session bon_{short_id}_tab1 snapshot -i -c",
                info.pinned_tab_cli(&short_id, "tab1")
            )
        } else {
            format!("bon-login launch {short_id} --pin-tab tab1")
        };
        cx.write_to_clipboard(ClipboardItem::new_string(cmd));
        self.banner_message = Some(format!(
            "Copied Pinned-Tab Agent CLI (session bon_{short_id}_tab1)"
        ));
        cx.notify();
    }

    pub fn open_agent_flows_modal(
        &mut self,
        profile_id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.saved_flows = crate::flows::list_saved_flows_in(&self.workspace_root);
        let save_name_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Flow name (e.g. login_flow)")
        });
        let vars_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Vars: key=val, pass=123 (optional)")
        });
        self.popup_modal = Some(ActivePopupModal::AgentFlows(AgentFlowsModalState {
            target_id: profile_id,
            expanded_flow_name: None,
            save_name_input,
            vars_input,
        }));
        cx.notify();
    }

    pub fn save_history_as_flow_ui(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::AgentFlows(af)) = self.popup_modal.clone() else {
            return;
        };
        let raw_name = af.save_name_input.read(cx).value().trim().to_string();
        if raw_name.is_empty() {
            self.banner_message = Some("Enter a flow name first".to_string());
            cx.notify();
            return;
        }
        let target_prof = af
            .target_id
            .as_ref()
            .or(self.selected_profile_id.as_ref())
            .and_then(|id| self.profiles.iter().find(|p| &p.id == id))
            .cloned();
        let Some(prof) = target_prof else {
            self.banner_message = Some("Select a profile first".to_string());
            cx.notify();
            return;
        };
        let raw_vars = af.vars_input.read(cx).value().to_string();
        let var_pairs: Vec<(String, String)> =
            crate::flows::parse_flow_vars_text(&raw_vars)
                .into_iter()
                .collect();
        match crate::flows::save_profile_history_as_flow_in(
            &self.workspace_root,
            &raw_name,
            &prof,
            &var_pairs,
        ) {
            Ok(flow) => {
                if let Some(ActivePopupModal::AgentFlows(m)) = self.popup_modal.as_mut() {
                    m.save_name_input = cx.new(|cx| {
                        InputState::new(window, cx).placeholder("Flow name (e.g. login_flow)")
                    });
                }
                self.saved_flows = crate::flows::list_saved_flows_in(&self.workspace_root);
                self.banner_message = Some(format!(
                    "Saved flow '{}' ({} steps from '{}')",
                    flow.name,
                    flow.steps.len(),
                    prof.name
                ));
            }
            Err(e) => {
                self.banner_message = Some(format!("Save flow failed: {e}"));
            }
        }
        cx.notify();
    }

    pub fn clear_profile_flow_history_ui(&mut self, cx: &mut Context<Self>) {
        let flow_target_id = match &self.popup_modal {
            Some(ActivePopupModal::AgentFlows(af)) => af.target_id.clone(),
            _ => None,
        };
        let target_prof = flow_target_id
            .as_ref()
            .or(self.selected_profile_id.as_ref())
            .and_then(|id| self.profiles.iter().find(|p| &p.id == id))
            .cloned();
        if let Some(prof) = target_prof {
            crate::flows::clear_flow_session_cache_in(&self.workspace_root, &prof.short_id());
            self.banner_message =
                Some(format!("Cleared recorded DOM steps for '{}'", prof.name));
            cx.notify();
        }
    }

    pub fn delete_saved_flow_ui(&mut self, flow_name: &str, cx: &mut Context<Self>) {
        if let Ok(path) = crate::flows::flow_file_path_in(&self.workspace_root, flow_name) {
            let _ = std::fs::remove_file(path);
        }
        if let Some(ActivePopupModal::AgentFlows(m)) = self.popup_modal.as_mut()
            && m.expanded_flow_name.as_deref() == Some(flow_name)
        {
            m.expanded_flow_name = None;
        }
        self.saved_flows = crate::flows::list_saved_flows_in(&self.workspace_root);
        self.banner_message = Some(format!("Deleted flow '{flow_name}'"));
        cx.notify();
    }

    pub fn toggle_expanded_flow_ui(&mut self, flow_name: &str, cx: &mut Context<Self>) {
        if let Some(ActivePopupModal::AgentFlows(m)) = self.popup_modal.as_mut() {
            if m.expanded_flow_name.as_deref() == Some(flow_name) {
                m.expanded_flow_name = None;
            } else {
                m.expanded_flow_name = Some(flow_name.to_string());
            }
            cx.notify();
        }
    }

    pub fn mutate_flow_step_ui(
        &mut self,
        flow_name: &str,
        step_idx: usize,
        action: &str,
        cx: &mut Context<Self>,
    ) {
        match crate::flows::mutate_flow_step_in(&self.workspace_root, flow_name, step_idx, action) {
            Ok(_) => {
                self.saved_flows = crate::flows::list_saved_flows_in(&self.workspace_root);
            }
            Err(e) => {
                self.banner_message = Some(format!("Flow step update failed: {e}"));
            }
        }
        cx.notify();
    }

    pub fn run_saved_flow_ui(&mut self, flow_name: &str, cx: &mut Context<Self>) {
        let (flow_target_id, extra_vars) = match &self.popup_modal {
            Some(ActivePopupModal::AgentFlows(af)) => (
                af.target_id.clone(),
                crate::flows::parse_flow_vars_text(&af.vars_input.read(cx).value()),
            ),
            _ => (None, std::collections::HashMap::new()),
        };
        let target_ids: Vec<String> = if let Some(pid) = &flow_target_id {
            vec![pid.clone()]
        } else if !self.checked_profile_ids.is_empty() {
            self.checked_profile_ids.iter().cloned().collect()
        } else if let Some(sel) = &self.selected_profile_id {
            vec![sel.clone()]
        } else {
            Vec::new()
        };
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| target_ids.contains(&p.id))
            .cloned()
            .collect();
        if targets.is_empty() {
            self.banner_message = Some("Select at least 1 profile to run flow".to_string());
            cx.notify();
            return;
        }
        let flow_name_str = flow_name.to_string();
        self.popup_modal = None;
        self.banner_message = Some(format!(
            "Running flow '{flow_name_str}' on {} profile(s)...",
            targets.len()
        ));
        cx.notify();

        for prof in targets {
            let pid = prof.id.clone();
            let pid_task = pid.clone();
            let prof_name = prof.name.clone();
            let fn_cl = flow_name_str.clone();
            let vars_cl = extra_vars.clone();
            let existing_ws = match self.statuses.get(&pid) {
                Some(ProfileStatus::Starting) => continue,
                Some(ProfileStatus::Running(info)) => Some(info.ws_url.clone()),
                _ => None,
            };
            if let Some(prev) = self.profile_tasks.remove(&pid) {
                prev.abort();
            }
            if existing_ws.is_none() {
                self.statuses.insert(pid.clone(), ProfileStatus::Starting);
            }
            let tokio_handle = self.tokio_handle.clone();
            let db = self.db.clone();
            let sup = self.supervisor.clone();
            let root_for_flow = self.workspace_root.clone();
            let join_handle = tokio_handle.spawn(async move {
                let ws_url = if let Some(ws) = existing_ws {
                    ws
                } else {
                    sup.ensure_launched(&db, &prof).await?.ws_url
                };
                tokio::task::spawn_blocking(move || {
                    crate::flows::run_flow_on_live_session_in(
                        &root_for_flow,
                        &fn_cl,
                        &prof,
                        &ws_url,
                        &vars_cl,
                    )
                })
                .await?
            });
            self.profile_tasks
                .insert(pid_task.clone(), join_handle.abort_handle());
            let fn_done = flow_name_str.clone();
            cx.spawn(async move |this, cx| {
                let join_res = join_handle.await;
                let _ = this.update(cx, |app, cx| {
                    app.profile_tasks.remove(&pid_task);
                    let res = match join_res {
                        Ok(r) => r,
                        Err(e) if e.is_cancelled() => return,
                        Err(e) => Err(anyhow::anyhow!("Flow task error: {e}")),
                    };
                    let live_info = app.supervisor.live_info(&pid_task);
                    match res {
                        Ok(steps) => {
                            if let Some(info) = live_info {
                                app.statuses
                                    .insert(pid_task.clone(), ProfileStatus::Running(info));
                            }
                            app.reload_profiles();
                            app.banner_message = Some(format!(
                                "Flow '{fn_done}' finished on '{prof_name}' ({steps} steps OK)"
                            ));
                        }
                        Err(e) => {
                            if let Some(info) = live_info {
                                app.statuses
                                    .insert(pid_task.clone(), ProfileStatus::Running(info));
                            } else {
                                app.statuses.insert(pid_task.clone(), ProfileStatus::Error);
                            }
                            app.reload_profiles();
                            app.banner_message =
                                Some(format!("Flow '{fn_done}' failed on '{prof_name}': {e}"));
                        }
                    }
                    cx.notify();
                });
            })
            .detach();
        }
    }

    pub fn toggle_http_api_server(&mut self, cx: &mut Context<Self>) {
        if let Some(handle) = self.http_api_task.take() {
            handle.abort();
            self.http_api_port = None;
            self.banner_message = Some("Stopped Local HTTP Control API".to_string());
            cx.notify();
            return;
        }
        let port = 19820u16;
        let std_listener = match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(l) if l.set_nonblocking(true).is_ok() => l,
            Ok(_) => {
                self.banner_message = Some("Failed to set non-blocking socket".to_string());
                cx.notify();
                return;
            }
            Err(e) => {
                self.banner_message =
                    Some(format!("Local API port {port} busy or failed to bind: {e}"));
                cx.notify();
                return;
            }
        };
        let (mut_tx, mut mut_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let engine = crate::control::ControlEngine::attached(
            self.db.clone(),
            self.supervisor.clone(),
            Arc::new(move || {
                let _ = mut_tx.send(());
            }),
        );
        let tokio_handle = self.tokio_handle.clone();
        let join_handle = tokio_handle.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener)?;
            crate::control::serve_control_http_with_engine(listener, engine).await
        });
        self.http_api_task = Some(join_handle.abort_handle());
        self.http_api_port = Some(port);
        cx.spawn(async move |this, cx| {
            while mut_rx.recv().await.is_some() {
                while mut_rx.try_recv().is_ok() {}
                let alive = this
                    .update(cx, |app, cx| {
                        app.reload_profiles();
                        for p in &app.profiles {
                            match app.supervisor.live_info(&p.id) {
                                Some(info) => {
                                    app.statuses
                                        .insert(p.id.clone(), ProfileStatus::Running(info));
                                }
                                None if matches!(
                                    app.statuses.get(&p.id),
                                    Some(ProfileStatus::Running(_))
                                ) =>
                                {
                                    app.statuses.insert(p.id.clone(), ProfileStatus::Stopped);
                                }
                                None => {}
                            }
                        }
                        cx.notify();
                    })
                    .is_ok();
                if !alive {
                    break;
                }
            }
        })
        .detach();
        cx.write_to_clipboard(ClipboardItem::new_string(format!(
            "http://127.0.0.1:{port}/profiles"
        )));
        self.banner_message = Some(format!(
            "Local HTTP API online at http://127.0.0.1:{port} (copied URL)"
        ));
        cx.notify();
    }

    pub fn set_arrange_size_text(
        &mut self,
        text: String,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.arrange_size_input
            .update(cx, |input, cx| input.set_value(text, window, cx));
        cx.notify();
    }

    pub fn running_targets_for_arrange(&self) -> Vec<(u16, String)> {
        let use_checked = self.profiles.iter().any(|p| {
            self.checked_profile_ids.contains(&p.id)
                && matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_)))
        });
        self.profiles
            .iter()
            .filter(|p| !use_checked || self.checked_profile_ids.contains(&p.id))
            .filter_map(|p| match self.statuses.get(&p.id) {
                Some(ProfileStatus::Running(info)) => Some((info.cdp_port, info.ws_url.clone())),
                _ => None,
            })
            .collect()
    }

    pub fn arrange_open_browsers(&mut self, cx: &mut Context<Self>) {
        let targets = self.running_targets_for_arrange();
        if targets.is_empty() {
            self.banner_message = Some("No open browsers to arrange".to_string());
            cx.notify();
            return;
        }
        let raw_size = self.arrange_size_input.read(cx).value().to_string();
        let Some((win_w, win_h)) = crate::launcher::parse_window_size(&raw_size) else {
            self.banner_message =
                Some("Invalid window size (use Width,Height e.g. 960,600)".to_string());
            cx.notify();
            return;
        };

        let display_rects = crate::launcher::macos_active_display_rects();
        let disp_idx = self
            .arrange_display_idx
            .min(display_rects.len().saturating_sub(1));
        self.arrange_display_idx = disp_idx;
        let (mon_x, mon_y, mon_w, mon_h) = display_rects
            .get(disp_idx)
            .copied()
            .unwrap_or((0, 0, 1440, 900));
        let tokio_handle = self.tokio_handle.clone();
        let disp_num = disp_idx + 1;
        cx.spawn(async move |this, cx| {
            let (ok_count, total, applied_w, applied_h) = tokio_handle
                .spawn_blocking(move || {
                    crate::control::tile_window_targets(
                        &targets,
                        (mon_x, mon_y, mon_w, mon_h),
                        win_w,
                        win_h,
                    )
                })
                .await
                .unwrap_or((0, 0, win_w, win_h));
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(format!(
                    "Arranged {ok_count}/{total} open browser(s) to {applied_w}×{applied_h} on Display {disp_num}"
                ));
                cx.notify();
            });
        })
        .detach();
    }


    pub fn delete_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(handle) = self.profile_tasks.remove(profile_id) {
            handle.abort();
        }
        let short_id = self
            .profiles
            .iter()
            .find(|p| p.id == profile_id)
            .map(|p| p.short_id())
            .unwrap_or_default();
        let sup = self.supervisor.clone();
        let pid_s = profile_id.to_string();
        self.tokio_handle.spawn_blocking(move || {
            sup.stop(&pid_s, &short_id);
        });
        if let Ok(db) = self.db.lock() {
            let _ = db.soft_delete_profile(profile_id);
        }
        self.statuses.remove(profile_id);
        self.checked_profile_ids.remove(profile_id);
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        } else {
            self.selected_profile_id = None;
            self.modal = None;
        }
        self.banner_message =
            Some("Moved profile to Trash (restore anytime from Trash tab)".to_string());
        cx.notify();
    }

    pub fn permanently_delete_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(handle) = self.profile_tasks.remove(profile_id) {
            handle.abort();
        }
        let short_id = self
            .profiles
            .iter()
            .chain(self.trashed_profiles.iter())
            .find(|p| p.id == profile_id)
            .map(|p| p.short_id())
            .unwrap_or_default();
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_profile(profile_id);
        }
        let sup = self.supervisor.clone();
        let wipe_id = profile_id.to_string();
        self.tokio_handle.spawn_blocking(move || {
            let _ = sup.stop_and_wipe(&wipe_id, &short_id);
        });
        self.statuses.remove(profile_id);
        self.checked_profile_ids.remove(profile_id);
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        }
        self.banner_message = Some("Permanently deleted profile and wiped browser data".to_string());
        cx.notify();
    }

    pub fn restore_trashed_profile(
        &mut self,
        profile_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Ok(db) = self.db.lock() {
            let _ = db.restore_profile(profile_id);
        }
        self.reload_profiles();
        self.select_profile(profile_id, window, cx);
        self.banner_message = Some("Restored profile from Trash".to_string());
        cx.notify();
    }

    pub fn restore_all_trashed_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.trashed_profiles.iter().map(|p| p.id.clone()).collect();
        let count = ids.len();
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &ids {
                    let _ = db.restore_profile(id);
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        }
        self.profile_sub_tab = ProfileSubTab::Local;
        self.banner_message = Some(format!("Restored {count} profile(s) from Trash"));
        cx.notify();
    }

    pub fn empty_trash(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let pairs: Vec<(String, String)> = self
            .trashed_profiles
            .iter()
            .map(|p| (p.id.clone(), p.short_id()))
            .collect();
        let count = pairs.len();
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (id, _) in &pairs {
                    let _ = db.delete_profile(id);
                }
                Ok(())
            });
        }
        let sup = self.supervisor.clone();
        self.tokio_handle.spawn_blocking(move || {
            crate::launcher::parallel_map(&pairs, |(id, sid)| {
                let _ = sup.stop_and_wipe(id, sid);
            });
        });
        self.reload_profiles();
        self.banner_message = Some(format!("Emptied Trash ({count} profile(s) permanently deleted)"));
        cx.notify();
    }

    pub fn copy_profile_totp(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        if let Some((code, rem)) = prof.current_totp() {
            cx.write_to_clipboard(ClipboardItem::new_string(code.clone()));
            if let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id).cloned() {
                let cdp_port = info.cdp_port;
                let code_to_type = format!("{code}\n");
                let prof_name = prof.name.clone();
                let tokio_handle = self.tokio_handle.clone();
                self.banner_message = Some(format!(
                    "Copied & auto-typing 2FA {code} ({rem}s) into '{prof_name}'..."
                ));
                cx.notify();
                cx.spawn(async move |this, cx| {
                    let ok = tokio_handle
                        .spawn_blocking(move || {
                            crate::launcher::cdp_type_as_human(cdp_port, &code_to_type).is_ok()
                        })
                        .await
                        .unwrap_or(false);
                    if ok {
                        let _ = this.update(cx, |app, cx| {
                            app.banner_message = Some(format!(
                                "Typed & copied 2FA code for '{prof_name}': {code} ({rem}s)"
                            ));
                            cx.notify();
                        });
                    }
                })
                .detach();
                return;
            }
            self.banner_message = Some(format!(
                "Copied 2FA code for '{}': {code} (valid {rem}s)",
                prof.name
            ));
        } else {
            self.banner_message = Some("Invalid or empty 2FA secret on this profile".to_string());
        }
        cx.notify();
    }

    pub fn capture_profile_screenshot(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id).cloned() else {
            self.banner_message = Some("Start the profile first to capture a screenshot".to_string());
            cx.notify();
            return;
        };
        let sid = prof.short_id();
        let name = prof.name.clone();
        let cdp_port = info.cdp_port;
        let root_dir = self.workspace_root.clone();
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    crate::launcher::cdp_capture_screenshot_in(&root_dir, &sid, cdp_port, None)
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(path) => {
                        let path_s = path.display().to_string();
                        cx.write_to_clipboard(ClipboardItem::new_string(path_s.clone()));
                        app.banner_message = Some(format!(
                            "Saved screenshot for '{name}': {path_s} (copied path)"
                        ));
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Screenshot failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn focus_profile_browser(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id).cloned() else {
            self.banner_message = Some("Profile is not running".to_string());
            cx.notify();
            return;
        };
        let pid_s = prof.id;
        let name = prof.name;
        let pid = info.pid;
        let cdp_port = info.cdp_port;
        let ws_url = info.ws_url;
        let tokio_handle = self.tokio_handle.clone();
        let root_dir = self.workspace_root.clone();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    crate::launcher::cdp_focus_window_in(&root_dir, &pid_s, pid, cdp_port, &ws_url)
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(match res {
                    Ok(()) => format!("Focused browser window for '{name}'"),
                    Err(e) => format!("Focus failed for '{name}': {e}"),
                });
                cx.notify();
            });
        })
        .detach();
    }

    pub fn open_quick_meta_modal(
        &mut self,
        profile_id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let (tags, note, totp, bookmarks) = if let Some(pid) = &profile_id
            && let Some(p) = self.profiles.iter().find(|x| &x.id == pid)
        {
            let bm_list = crate::launcher::read_profile_bookmarks_in(&self.workspace_root, p);
            (p.tags.clone(), p.notes.clone(), p.totp_secret.clone(), bm_list)
        } else {
            (Vec::new(), String::new(), String::new(), Vec::new())
        };
        let tag_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Custom tag (e.g. Shop-01, Tier1)...")
        });
        let note_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(3)
                .placeholder("Account note, recovery email, status...")
                .default_value(note)
        });
        let totp_input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Base32 2FA Secret or otpauth:// URI...")
                .default_value(totp)
        });
        let bm_name_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Title (optional)")
        });
        let bm_url_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("URL (e.g. seller.tiktok.com)")
        });
        self.popup_modal = Some(ActivePopupModal::QuickMeta(QuickMetaModalState {
            profile_id,
            tags,
            tag_input,
            note_input,
            totp_input,
            bookmarks,
            bm_name_input,
            bm_url_input,
        }));
        cx.notify();
    }

    pub fn add_quick_meta_bookmark_from_inputs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(ActivePopupModal::QuickMeta(qm)) = self.popup_modal.as_mut() {
            let n = qm.bm_name_input.clone();
            let u = qm.bm_url_input.clone();
            profile_modal::push_bookmark_from_inputs(&mut qm.bookmarks, &n, &u, window, cx);
            cx.notify();
        }
    }

    pub fn open_or_copy_bookmark(&mut self, profile_id: &str, name: &str, url: &str, cx: &mut Context<Self>) {
        let url_s = url.to_string();
        let name_s = name.to_string();
        if let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id).cloned() {
            let cdp_port = info.cdp_port;
            let tokio_handle = self.tokio_handle.clone();
            cx.write_to_clipboard(ClipboardItem::new_string(url_s.clone()));
            self.banner_message = Some(format!("Opening bookmark '{name_s}' ({url_s})..."));
            cx.notify();
            cx.spawn(async move |this, cx| {
                let u_nav = url_s.clone();
                let res = tokio_handle
                    .spawn_blocking(move || crate::launcher::cdp_navigate_page(cdp_port, &u_nav))
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
                let _ = this.update(cx, |app, cx| {
                    app.banner_message = Some(match res {
                        Ok(()) => format!("Opened bookmark '{name_s}' in active tab"),
                        Err(_) => format!("Copied bookmark URL: {url_s}"),
                    });
                    cx.notify();
                });
            })
            .detach();
        } else {
            cx.write_to_clipboard(ClipboardItem::new_string(url_s.clone()));
            self.banner_message = Some(format!("Copied bookmark '{name_s}': {url_s}"));
            cx.notify();
        }
    }

    pub fn save_quick_meta_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::QuickMeta(qm)) = self.popup_modal.as_mut() else {
            return;
        };
        let n = qm.bm_name_input.clone();
        let u = qm.bm_url_input.clone();
        profile_modal::push_bookmark_from_inputs(&mut qm.bookmarks, &n, &u, window, cx);
        let profile_id_opt = qm.profile_id.clone();
        let tags = qm.tags.clone();
        let note = qm.note_input.read(cx).value().trim().to_string();
        let totp = qm.totp_input.read(cx).value().trim().to_string();
        let bms = qm.bookmarks.clone();

        if let Some(pid) = profile_id_opt {
            if let Some(prof) = self.profiles.iter().find(|p| p.id == pid) {
                let existing =
                    crate::launcher::read_profile_bookmarks_in(&self.workspace_root, prof);
                let is_live = self.running_session_pair(&pid).is_some()
                    || self.supervisor.live_info(&pid).is_some();
                if is_live && bms != existing {
                    self.banner_message = Some(format!(
                        "Stop running browser '{}' before editing disk Bookmarks",
                        prof.name
                    ));
                    cx.notify();
                    return;
                }
            }
            if let Ok(db) = self.db.lock() {
                let _ = db.update_profile_quick_meta(&pid, &note, &tags, &totp);
            }
            if self.running_session_pair(&pid).is_none()
                && self.supervisor.live_info(&pid).is_none()
                && let Ok(user_data_dir) =
                    crate::launcher::profile_user_data_dir_in(&self.workspace_root, &pid)
            {
                crate::launcher::write_profile_bookmarks_items(&user_data_dir, &bms);
            }
            self.banner_message = Some("Updated tags, bookmarks, note & 2FA".to_string());
        } else {
            let targets: Vec<Profile> = self
                .profiles
                .iter()
                .filter(|p| self.checked_profile_ids.contains(&p.id))
                .cloned()
                .collect();
            if !bms.is_empty()
                && targets.iter().any(|p| {
                    let is_live = self.running_session_pair(&p.id).is_some()
                        || self.supervisor.live_info(&p.id).is_some();
                    is_live
                        && bms != crate::launcher::read_profile_bookmarks_in(&self.workspace_root, p)
                })
            {
                self.banner_message =
                    Some("Stop running browsers before batch-editing disk Bookmarks".to_string());
                cx.notify();
                return;
            }
            let count = targets.len();
            if let Ok(db) = self.db.lock() {
                let _ = db.with_transaction(|db| {
                    for p in &targets {
                        let new_note = if note.is_empty() { &p.notes } else { &note };
                        let new_tags = if tags.is_empty() { &p.tags } else { &tags };
                        let _ =
                            db.update_profile_quick_meta(&p.id, new_note, new_tags, &p.totp_secret);
                        if !bms.is_empty()
                            && let Ok(user_data_dir) =
                                crate::launcher::profile_user_data_dir_in(&self.workspace_root, &p.id)
                        {
                            crate::launcher::write_profile_bookmarks_items(&user_data_dir, &bms);
                        }
                    }
                    Ok(())
                });
            }
            self.banner_message =
                Some(format!("Updated tags, bookmarks & note on {count} profile(s)"));
        }
        self.popup_modal = None;
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        cx.notify();
    }

    pub fn export_single_profile_zip(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if matches!(
            self.statuses.get(profile_id),
            Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
        ) || self.supervisor.live_info(profile_id).is_some()
        {
            self.banner_message =
                Some("Stop the browser before exporting a full .zip archive".to_string());
            cx.notify();
            return;
        }
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let name = prof.name.clone();
        let root_dir = self.workspace_root.clone();
        let out_dir = crate::db::export_dir_for_root(&root_dir);
        let tokio_handle = self.tokio_handle.clone();
        self.banner_message = Some(format!("Packing full .zip backup for '{name}'..."));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    crate::launcher::export_profile_archive_zip_in(&root_dir, &out_dir, &prof)
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(path) => {
                        let path_s = path.display().to_string();
                        cx.write_to_clipboard(ClipboardItem::new_string(path_s.clone()));
                        app.banner_message =
                            Some(format!("Exported backup (.zip): {path_s} (copied path)"));
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Backup export failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn clean_single_profile_cache(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        if matches!(
            self.statuses.get(&prof.id),
            Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
        ) {
            self.banner_message =
                Some("Stop the browser before cleaning profile disk cache".to_string());
            cx.notify();
            return;
        }
        let pid = prof.id.clone();
        let pid_for_ui = pid.clone();
        let name = prof.name.clone();
        let root_dir = self.workspace_root.clone();
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || crate::launcher::clean_profile_cache_in(&root_dir, &pid))
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(match res {
                    Ok((freed, rem)) => {
                        if app.selected_profile_id.as_deref() == Some(pid_for_ui.as_str()) {
                            app.selected_disk_usage = crate::launcher::format_bytes(rem);
                        }
                        format!(
                            "Cleaned '{name}': freed {} (remaining {})",
                            crate::launcher::format_bytes(freed),
                            crate::launcher::format_bytes(rem)
                        )
                    }
                    Err(e) => format!("Clean cache failed: {e}"),
                });
                cx.notify();
            });
        })
        .detach();
    }

    pub fn clean_all_or_checked_cache(&mut self, cx: &mut Context<Self>) {
        let use_checked = !self.checked_profile_ids.is_empty();
        let ids: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| !use_checked || self.checked_profile_ids.contains(&p.id))
            .filter(|p| {
                !matches!(
                    self.statuses.get(&p.id),
                    Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
                )
            })
            .map(|p| p.id.clone())
            .collect();
        if ids.is_empty() {
            self.banner_message = Some("No stopped profiles to clean cache".to_string());
            cx.notify();
            return;
        }
        let count = ids.len();
        let root_dir = self.workspace_root.clone();
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let total_freed = tokio_handle
                .spawn_blocking(move || {
                    crate::launcher::parallel_map(&ids, |id| {
                        crate::launcher::clean_profile_cache_in(&root_dir, id)
                            .map(|(f, _)| f)
                            .unwrap_or(0)
                    })
                    .into_iter()
                    .fold(0u64, u64::saturating_add)
                })
                .await
                .unwrap_or(0);
            let _ = this.update(cx, |app, cx| {
                app.refresh_selected_disk_usage(cx);
                app.banner_message = Some(format!(
                    "Cleaned cache on {count} profile(s): freed {}",
                    crate::launcher::format_bytes(total_freed)
                ));
                cx.notify();
            });
        })
        .detach();
    }

    pub fn export_profiles_csv_ui(&mut self, cx: &mut Context<Self>) {
        let res = self.db.lock().ok().and_then(|db| db.export_profiles_csv().ok());
        if let Some((path, _)) = res {
            let path_s = path.display().to_string();
            cx.write_to_clipboard(ClipboardItem::new_string(path_s.clone()));
            self.banner_message = Some(format!("Exported CSV: {path_s} (copied path)"));
        } else {
            self.banner_message = Some("Failed to export profiles CSV".to_string());
        }
        cx.notify();
    }

    pub fn pick_and_import_csv_ui(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        cx.spawn_in(window, async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || -> anyhow::Result<Option<(String, usize)>> {
                    let out = std::process::Command::new("osascript")
                        .args([
                            "-e",
                            "POSIX path of (choose file with prompt \"Choose Profiles CSV/TSV File\")",
                        ])
                        .output()?;
                    if !out.status.success() {
                        return Ok(None);
                    }
                    let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if path_str.is_empty() {
                        return Ok(None);
                    }
                    let raw = std::fs::read_to_string(&path_str)?;
                    let count = db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("DB lock error"))?
                        .import_profiles_csv(&raw)?;
                    Ok(Some((path_str, count)))
                })
                .await
                .unwrap_or(Ok(None));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(Some((path_str, count))) => {
                        app.reload_profiles();
                        app.banner_message =
                            Some(format!("Imported {count} profile(s) from {path_str}"));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        app.banner_message = Some(format!("CSV import failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn sync_clipboard_to_checked_running(&mut self, cx: &mut Context<Self>) {
        let Some(clip) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            self.banner_message = Some("Clipboard is empty".to_string());
            cx.notify();
            return;
        };
        let val = clip.trim().to_string();
        if val.is_empty() {
            self.banner_message = Some("Clipboard text is empty".to_string());
            cx.notify();
            return;
        }
        let use_checked = self.profiles.iter().any(|p| {
            self.checked_profile_ids.contains(&p.id)
                && matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_)))
        });
        let ports: Vec<u16> = self
            .profiles
            .iter()
            .filter(|p| !use_checked || self.checked_profile_ids.contains(&p.id))
            .filter_map(|p| match self.statuses.get(&p.id) {
                Some(ProfileStatus::Running(info)) => Some(info.cdp_port),
                _ => None,
            })
            .collect();
        if ports.is_empty() {
            self.banner_message = Some("No running profiles to sync".to_string());
            cx.notify();
            return;
        }
        let is_url = val.starts_with("http://") || val.starts_with("https://");
        let total = ports.len();
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let ok_count = tokio_handle
                .spawn_blocking(move || {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = ports
                            .into_iter()
                            .map(|port| {
                                let v = val.clone();
                                s.spawn(move || {
                                    if is_url {
                                        crate::launcher::cdp_navigate_page(port, &v).is_ok()
                                    } else {
                                        crate::launcher::cdp_type_as_human(port, &v).is_ok()
                                    }
                                })
                            })
                            .collect();
                        handles
                            .into_iter()
                            .filter_map(|h| h.join().ok().filter(|&ok| ok))
                            .count()
                    })
                })
                .await
                .unwrap_or(0);
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(if is_url {
                    format!("Synced URL navigation across {ok_count}/{total} running browser(s)")
                } else {
                    format!("Synced human-typing across {ok_count}/{total} running browser(s)")
                });
                cx.notify();
            });
        })
        .detach();
    }

    pub fn type_clipboard_as_human(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(clip) = cx.read_from_clipboard().and_then(|item| item.text()) else {
            self.banner_message = Some("Clipboard is empty".to_string());
            cx.notify();
            return;
        };
        if clip.is_empty() {
            self.banner_message = Some("Clipboard text is empty".to_string());
            cx.notify();
            return;
        }
        let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id).cloned() else {
            self.banner_message = Some("Start the profile first to human-type clipboard".to_string());
            cx.notify();
            return;
        };
        let cdp_port = info.cdp_port;
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || crate::launcher::cdp_type_as_human(cdp_port, &clip))
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                app.banner_message = Some(match res {
                    Ok(n) => format!("Human-typed {n} character(s) from clipboard"),
                    Err(e) => format!("Human-type failed: {e}"),
                });
                cx.notify();
            });
        })
        .detach();
    }

    pub fn export_checked_profiles_zip(&mut self, cx: &mut Context<Self>) {
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .filter(|p| !matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_))))
            .cloned()
            .collect();
        if targets.is_empty() {
            self.banner_message =
                Some("Stop running profiles before exporting full .zip archives".to_string());
            cx.notify();
            return;
        }
        let count = targets.len();
        let root_dir = self.workspace_root.clone();
        let out_dir = crate::db::export_dir_for_root(&root_dir);
        let tokio_handle = self.tokio_handle.clone();
        self.banner_message = Some(format!("Packing {count} profile archive(s) (.zip)..."));
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    let mut ok = 0usize;
                    let mut last_dir = String::new();
                    for prof in &targets {
                        if let Ok(path) = crate::launcher::export_profile_archive_zip_in(
                            &root_dir, &out_dir, prof,
                        ) {
                            ok += 1;
                            if let Some(parent) = path.parent() {
                                last_dir = parent.display().to_string();
                            }
                        }
                    }
                    (ok, last_dir)
                })
                .await
                .unwrap_or((0, String::new()));
            let _ = this.update(cx, |app, cx| {
                let (ok, dir) = res;
                app.banner_message =
                    Some(format!("Exported {ok}/{count} .zip archive(s) to {dir}"));
                cx.notify();
            });
        })
        .detach();
    }

    pub fn browse_and_import_backup_zip(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let chosen = tokio_handle
                .spawn_blocking(|| {
                    Self::choose_macos_file_blocking(
                        "Select BonLogin Profile Backup (.zip)",
                        &["zip"],
                    )
                })
                .await
                .ok()
                .flatten();
            if let Some(path) = chosen {
                let _ = this.update(cx, |app, cx| {
                    app.import_backup_zip_path(path, cx);
                });
            }
        })
        .detach();
    }

    pub fn open_import_backup_zip_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let zip_input = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Path to backup .zip file...")
        });
        self.popup_modal = Some(ActivePopupModal::ImportBackupZip(ImportBackupZipModalState {
            zip_input,
        }));
        cx.notify();
    }

    pub fn import_backup_zip_from_input(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::ImportBackupZip(ibz)) = self.popup_modal.as_ref() else {
            return;
        };
        let raw = ibz.zip_input.read(cx).value().trim().to_string();
        if raw.is_empty() {
            self.banner_message = Some("Select or paste a .zip backup file path first".to_string());
            cx.notify();
            return;
        }
        self.import_backup_zip_path(raw, cx);
    }

    fn import_backup_zip_path(&mut self, raw: String, cx: &mut Context<Self>) {
        let db = self.db.clone();
        let tokio_handle = self.tokio_handle.clone();
        self.popup_modal = None;
        self.banner_message = Some("Restoring profile backup (.zip)...".to_string());
        cx.notify();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || {
                    db.lock()
                        .map_err(|_| anyhow::anyhow!("DB lock error"))?
                        .import_profile_archive_zip(std::path::Path::new(&raw))
                })
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
            let _ = this.update(cx, |app, cx| {
                match res {
                    Ok(restored) => {
                        let rid = restored.id.clone();
                        let rname = restored.name.clone();
                        app.reload_profiles();
                        app.selected_profile_id = Some(rid);
                        app.banner_message =
                            Some(format!("Restored profile '{rname}' from .zip backup"));
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Failed to import .zip backup: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn open_cookie_robot_modal(
        &mut self,
        profile_id: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let urls_input = cx.new(|cx| {
            TextareaState::new(window, cx)
                .rows(6)
                .default_value("https://www.google.com\nhttps://www.youtube.com\nhttps://www.wikipedia.org")
        });
        self.popup_modal = Some(ActivePopupModal::CookieRobot(CookieRobotModalState {
            target_id: profile_id,
            urls_input,
            dwell_secs: 5,
        }));
        cx.notify();
    }

    pub fn start_cookie_robot(&mut self, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::CookieRobot(cr)) = self.popup_modal.take() else {
            return;
        };
        let raw_urls = cr.urls_input.read(cx).value().to_string();
        let urls: Vec<String> = raw_urls
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .collect();
        if urls.is_empty() {
            self.popup_modal = Some(ActivePopupModal::CookieRobot(cr));
            self.banner_message = Some("Enter at least 1 warm-up URL".to_string());
            cx.notify();
            return;
        }
        let dwell = cr.dwell_secs;
        let target_ids: Vec<String> = if let Some(pid) = &cr.target_id {
            vec![pid.clone()]
        } else {
            self.checked_profile_ids.iter().cloned().collect()
        };
        if target_ids.is_empty() {
            return;
        }
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| target_ids.contains(&p.id))
            .cloned()
            .collect();
        let total_urls = urls.len();
        self.banner_message = Some(format!(
            "Cookie Robot started for {} profile(s) ({total_urls} sites, {dwell}s each)...",
            targets.len()
        ));
        cx.notify();

        for prof in targets {
            let pid = prof.id.clone();
            let pid_task = pid.clone();
            let short_id = prof.short_id();
            let prof_name = prof.name.clone();
            let urls_clone = urls.clone();
            let existing_ws = match self.statuses.get(&pid) {
                Some(ProfileStatus::Starting) => continue,
                Some(ProfileStatus::Running(info)) => Some(info.ws_url.clone()),
                _ => None,
            };
            if let Some(prev) = self.profile_tasks.remove(&pid) {
                prev.abort();
            }
            if existing_ws.is_none() {
                self.statuses.insert(pid.clone(), ProfileStatus::Starting);
            }
            let tokio_handle = self.tokio_handle.clone();
            let db = self.db.clone();
            let sup = self.supervisor.clone();
            let root_for_robot = self.workspace_root.clone();
            let join_handle = tokio_handle.spawn(async move {
                let ws_url = if let Some(ws) = existing_ws {
                    ws
                } else {
                    sup.ensure_launched(&db, &prof).await?.ws_url
                };
                tokio::task::spawn_blocking(move || {
                    crate::launcher::run_cookie_robot_warmup_in(
                        &root_for_robot,
                        &short_id,
                        &ws_url,
                        &urls_clone,
                        dwell,
                    )
                })
                .await?
            });
            self.profile_tasks
                .insert(pid_task.clone(), join_handle.abort_handle());
            cx.spawn(async move |this, cx| {
                let join_res = join_handle.await;
                let _ = this.update(cx, |app, cx| {
                    app.profile_tasks.remove(&pid_task);
                    let res = match join_res {
                        Ok(r) => r,
                        Err(e) if e.is_cancelled() => return,
                        Err(e) => Err(anyhow::anyhow!("Warm-up task error: {e}")),
                    };
                    let live_info = app.supervisor.live_info(&pid_task);
                    match res {
                        Ok(visited) => {
                            if let Some(info) = live_info {
                                app.statuses.insert(pid_task.clone(), ProfileStatus::Running(info));
                            }
                            app.reload_profiles();
                            app.banner_message = Some(format!(
                                "Cookie Robot finished '{prof_name}': visited {visited}/{total_urls} sites & saved cookies"
                            ));
                        }
                        Err(e) => {
                            if let Some(info) = live_info {
                                app.statuses.insert(pid_task.clone(), ProfileStatus::Running(info));
                            } else {
                                app.statuses.insert(pid_task.clone(), ProfileStatus::Error);
                            }
                            app.banner_message =
                                Some(format!("Cookie Robot failed on '{prof_name}': {e}"));
                        }
                    }
                    cx.notify();
                });
            })
            .detach();
        }
    }


    pub fn toggle_check_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if !self.checked_profile_ids.remove(profile_id) {
            self.checked_profile_ids.insert(profile_id.to_string());
        }
        cx.notify();
    }

    pub fn toggle_check_all_filtered(&mut self, cx: &mut Context<Self>) {
        let filtered_ids: Vec<String> = self
            .filtered_profile_indices()
            .into_iter()
            .map(|i| self.profiles[i].id.clone())
            .collect();
        if filtered_ids.is_empty() {
            return;
        }
        let all_checked = filtered_ids
            .iter()
            .all(|id| self.checked_profile_ids.contains(id));
        if all_checked {
            for id in filtered_ids {
                self.checked_profile_ids.remove(&id);
            }
        } else {
            for id in filtered_ids {
                self.checked_profile_ids.insert(id);
            }
        }
        cx.notify();
    }

    pub fn launch_checked_profiles(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .filter(|p| !matches!(self.statuses.get(&p.id), Some(ProfileStatus::Running(_))))
            .map(|p| p.id.clone())
            .collect();
        for id in ids {
            self.launch_profile(&id, cx);
        }
    }

    pub fn stop_checked_profiles(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self
            .checked_profile_ids
            .iter()
            .filter(|id| {
                matches!(
                    self.statuses.get(*id),
                    Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
                )
            })
            .cloned()
            .collect();
        for id in ids {
            self.stop_profile(&id, cx);
        }
    }

    pub fn check_proxies_for_checked(&mut self, cx: &mut Context<Self>) {
        let ids: Vec<String> = self.checked_profile_ids.iter().cloned().collect();
        for id in ids {
            self.check_profile_proxy(&id, cx);
        }
    }

    pub fn move_checked_profiles_from_input(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let target_group = self.batch_selected_group.trim().to_string();
        let mut moved = 0usize;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for mut prof in self
                    .profiles
                    .iter()
                    .filter(|p| self.checked_profile_ids.contains(&p.id))
                    .cloned()
                {
                    prof.group_tag = target_group.clone();
                    if db.upsert_profile(&prof).is_ok() {
                        moved += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(if target_group.is_empty() {
            format!("Removed group from {moved} profile(s)")
        } else {
            format!("Moved {moved} profile(s) to folder '{target_group}'")
        });
        cx.notify();
    }

    pub fn copy_checked_ids_to_clipboard(&mut self, cx: &mut Context<Self>) {
        let rows: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .map(|p| {
                let proxy_str = p
                    .proxy
                    .as_ref()
                    .map(|px| px.display_short())
                    .unwrap_or_else(|| "direct".to_string());
                format!("{}\t{}\t{}\t{}", p.id, p.name, p.group_tag, proxy_str)
            })
            .collect();
        let count = rows.len();
        cx.write_to_clipboard(ClipboardItem::new_string(rows.join("\n")));
        self.banner_message = Some(format!(
            "Copied {count} profile row(s) (ID, Name, Folder, Proxy) to clipboard"
        ));
        cx.notify();
    }

    pub fn copy_checked_names_to_clipboard(&mut self, cx: &mut Context<Self>) {
        let names: Vec<String> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .map(|p| p.name.clone())
            .collect();
        let count = names.len();
        cx.write_to_clipboard(ClipboardItem::new_string(names.join("\n")));
        self.banner_message = Some(format!("Copied {count} profile name(s) to clipboard"));
        cx.notify();
    }

    pub fn batch_update_checked_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.checked_profile_ids.iter().any(|id| {
            matches!(
                self.statuses.get(id),
                Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
            )
        }) {
            self.banner_message =
                Some("Stop running browsers before batch-updating profiles".to_string());
            cx.notify();
            return;
        }
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        if targets.is_empty() {
            self.banner_message = Some("Check at least 1 profile first".to_string());
            cx.notify();
            return;
        }
        let prefix = self.batch_prefix_input.read(cx).value().trim().to_string();
        let group = self.batch_selected_group.trim().to_string();
        let target_os = self.batch_os;
        let target_brand = self.batch_brand;
        let mut updated = 0usize;

        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (idx, mut prof) in targets.into_iter().enumerate() {
                    prof.set_platform(target_os);
                    prof.set_brand(target_brand);
                    prof.reseed();
                    if !prefix.is_empty() && prefix != "Profile" {
                        prof.name = format!("{prefix}-{:02}", idx + 1);
                    }
                    if !group.is_empty() {
                        prof.group_tag = group.clone();
                    }
                    if db.upsert_profile(&prof).is_ok() {
                        updated += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.active_view = WorkspaceView::Profiles;
        self.banner_message = Some(format!(
            "Batch updated {updated} checked profile(s) ({})",
            target_os.label()
        ));
        cx.notify();
    }

    pub fn export_profile_cookies_json(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        if let Some((short_id, ws_url)) = self.running_session_pair(profile_id) {
            let prof_name = prof.name.clone();
            let root_for_exp = self.workspace_root.clone();
            let root_for_save = self.workspace_root.clone();
            let tokio_handle = self.tokio_handle.clone();
            self.banner_message = Some(format!("Exporting live cookies for '{prof_name}'..."));
            cx.notify();
            cx.spawn(async move |this, cx| {
                let sid = short_id.clone();
                let res = tokio_handle
                    .spawn_blocking(move || {
                        crate::launcher::agent_export_state_in(&root_for_exp, &sid, &ws_url)
                    })
                    .await
                    .unwrap_or_else(|e| Err(anyhow::anyhow!("Join error: {e}")));
                let _ = this.update(cx, |app, cx| {
                    match res {
                        Ok((_, json)) => {
                            let _ = crate::launcher::save_prelaunch_cookies_in(
                                &root_for_save,
                                &short_id,
                                &json,
                            );
                            let dl_path = crate::db::export_dir_for_root(&root_for_save)
                                .join(format!("bon_{short_id}_cookies.json"));
                            cx.write_to_clipboard(ClipboardItem::new_string(json.clone()));
                            app.banner_message = Some(match std::fs::write(&dl_path, &json) {
                                Ok(()) => format!(
                                    "Exported live cookies for '{prof_name}' to clipboard & {}",
                                    dl_path.display()
                                ),
                                Err(e) => format!(
                                    "Copied cookies to clipboard (file save failed: {e})"
                                ),
                            });
                        }
                        Err(e) => {
                            app.banner_message = Some(format!("Export cookies failed: {e}"));
                        }
                    }
                    cx.notify();
                });
            })
            .detach();
        } else {
            let sid = prof.short_id();
            let payload = crate::db::read_saved_cookies_in(&self.workspace_root, &sid)
                .unwrap_or_else(|| "[]".to_string());
            let dl_path = crate::db::export_dir_for_root(&self.workspace_root)
                .join(format!("bon_{sid}_cookies.json"));
            cx.write_to_clipboard(ClipboardItem::new_string(payload.clone()));
            self.banner_message = Some(match std::fs::write(&dl_path, &payload) {
                Ok(()) => format!(
                    "Exported cookies JSON for '{}' to clipboard & {}",
                    prof.name,
                    dl_path.display()
                ),
                Err(e) => format!(
                    "Copied cookies for '{}' to clipboard (file save failed: {e})",
                    prof.name
                ),
            });
            cx.notify();
        }
    }

    pub fn copy_single_profile_proxy(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let text = prof
            .proxy
            .as_ref()
            .map(|p| p.to_editable_string())
            .unwrap_or_else(|| "Local IP".to_string());
        cx.write_to_clipboard(ClipboardItem::new_string(text.clone()));
        self.banner_message = Some(format!("Copied proxy: {text}"));
        cx.notify();
    }

    pub fn copy_profile_id(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let short_id = prof.short_id();
        cx.write_to_clipboard(ClipboardItem::new_string(short_id.clone()));
        self.banner_message = Some(format!("Copied ID for '{}': {short_id}", prof.name));
        cx.notify();
    }

    pub fn copy_agent_browser_cli(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(prof) = self.profiles.iter().find(|p| p.id == profile_id) else {
            return;
        };
        let short_id = prof.short_id();
        let cmd = if let Some(ProfileStatus::Running(info)) = self.statuses.get(profile_id) {
            let sid = short_id.clone();
            let ws = info.ws_url.clone();
            let root_dir = self.workspace_root.clone();
            self.tokio_handle.spawn_blocking(move || {
                let _ = crate::launcher::agent_sync_targets_in(&root_dir, &sid, &ws);
            });
            format!(
                "{} && agent-browser --session bon_{short_id} snapshot -i -c",
                info.agent_browser_cli(&short_id)
            )
        } else {
            format!("bon-login agent {short_id} snapshot -i -c")
        };
        cx.write_to_clipboard(ClipboardItem::new_string(cmd.clone()));
        self.banner_message = Some(format!(
            "Copied Agent CLI & synced popups (session bon_{short_id})"
        ));
        cx.notify();
    }

    pub fn delete_group_and_reset(
        &mut self,
        group_name: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_group(group_name);
        }
        self.reload_profiles();
        if self.selected_group.eq_ignore_ascii_case(group_name) {
            self.selected_group = "All".to_string();
        }
        if self.batch_selected_group.eq_ignore_ascii_case(group_name) {
            self.batch_selected_group = self.saved_groups.first().cloned().unwrap_or_default();
        }
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(format!("Removed group '{group_name}'"));
        cx.notify();
    }

    pub fn create_group_from_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let g = self.batch_move_group_input.read(cx).value().trim().to_string();
        if g.is_empty() {
            return;
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.insert_group(&g);
        }
        self.batch_move_group_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Enter new group name..."));
        self.reload_profiles();
        self.batch_selected_group = g.clone();
        if let Some(m) = self.modal.as_mut() {
            m.draft.profile.group_tag = g.clone();
        }
        self.banner_message = Some(format!("Created group '{g}'"));
        cx.notify();
    }

    pub fn create_tag_from_modal(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let t = self.new_tag_input.read(cx).value().trim().to_string();
        if t.is_empty() {
            return false;
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.insert_tag(&t);
        }
        self.new_tag_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("Enter new tag name..."));
        self.reload_profiles();
        self.proxy_selected_tag = t.clone();
        self.banner_message = Some(format!("Created proxy tag '#{t}'"));
        cx.notify();
        true
    }

    pub fn delete_tag_and_reset(&mut self, tag_name: &str, cx: &mut Context<Self>) {
        if let Ok(db) = self.db.lock() {
            let _ = db.delete_tag(tag_name);
        }
        self.reload_profiles();
        if self.selected_proxy_group.eq_ignore_ascii_case(tag_name) {
            self.selected_proxy_group = "All".to_string();
        }
        if self.proxy_selected_tag.eq_ignore_ascii_case(tag_name) {
            self.proxy_selected_tag = self.saved_tags.first().cloned().unwrap_or_default();
        }
        self.banner_message = Some(format!("Removed proxy tag '#{tag_name}'"));
        cx.notify();
    }

    pub fn assign_single_saved_proxy_to_checked(
        &mut self,
        proxy_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(sp) = self.saved_proxies.iter().find(|p| p.id == proxy_id).cloned() else {
            return;
        };
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        let mut updated = 0usize;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for mut prof in targets {
                    prof.assign_saved_proxy(&sp);
                    if db.upsert_profile(&prof).is_ok() {
                        updated += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(format!(
            "Assigned proxy '{}' (#{}) to {updated} profile(s)",
            sp.name, sp.group_tag
        ));
        cx.notify();
    }

    pub fn batch_update_proxies_for_checked(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let targets: Vec<Profile> = self
            .profiles
            .iter()
            .filter(|p| self.checked_profile_ids.contains(&p.id))
            .cloned()
            .collect();
        if targets.is_empty() {
            return;
        }
        let pool = self.proxies_for_batch_group();
        if self.batch_proxy_group != "None" && pool.is_empty() {
            self.banner_message =
                Some("No proxies in Proxy manager yet. Open Proxy manager to add proxies first.".to_string());
            cx.notify();
            return;
        }
        let mut updated = 0usize;
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for (idx, mut prof) in targets.into_iter().enumerate() {
                    if self.batch_proxy_group == "None" {
                        prof.clear_proxy();
                    } else {
                        prof.assign_saved_proxy(&pool[idx % pool.len()]);
                    }
                    if db.upsert_profile(&prof).is_ok() {
                        updated += 1;
                    }
                }
                Ok(())
            });
        }
        self.reload_profiles();
        if let Some(sel) = self.selected_profile_id.clone() {
            self.select_profile(&sel, window, cx);
        }
        self.banner_message = Some(if self.batch_proxy_group == "None" {
            format!("Cleared proxy (Without proxy) on {updated} profile(s)")
        } else {
            format!("Updated proxies from Proxy manager on {updated} profile(s)")
        });
        cx.notify();
    }

    pub fn delete_checked_profiles(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let deletable_ids: Vec<String> = self
            .checked_profile_ids
            .iter()
            .filter(|id| !matches!(self.statuses.get(*id), Some(ProfileStatus::Running(_))))
            .cloned()
            .collect();
        if deletable_ids.is_empty() {
            self.banner_message =
                Some("Stop running profiles before moving them to Trash".to_string());
            cx.notify();
            return;
        }
        let count = deletable_ids.len();
        for id in &deletable_ids {
            if let Some(handle) = self.profile_tasks.remove(id) {
                handle.abort();
            }
        }
        if let Ok(db) = self.db.lock() {
            let _ = db.with_transaction(|db| {
                for id in &deletable_ids {
                    let _ = db.soft_delete_profile(id);
                }
                Ok(())
            });
        }
        for id in &deletable_ids {
            self.statuses.remove(id);
            self.checked_profile_ids.remove(id);
        }
        self.reload_profiles();
        if let Some(first) = self.profiles.first().map(|p| p.id.clone()) {
            self.select_profile(&first, window, cx);
        } else {
            self.selected_profile_id = None;
            self.modal = None;
        }
        self.banner_message = Some(format!(
            "Moved {count} profile(s) to Trash (restore anytime from Trash tab)"
        ));
        cx.notify();
    }

    pub fn check_profile_proxy(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        self.run_profile_proxy_action(profile_id, false, cx);
    }

    pub fn rotate_profile_proxy_ip(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        self.run_profile_proxy_action(profile_id, true, cx);
    }

    fn run_profile_proxy_action(
        &mut self,
        profile_id: &str,
        rotate: bool,
        cx: &mut Context<Self>,
    ) {
        let Some(profile) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        if rotate && profile.proxy.is_none() {
            self.banner_message = Some("Profile has no proxy configured".to_string());
            cx.notify();
            return;
        }
        let pid = profile.id.clone();
        let prof_name = profile.name.clone();
        if let Some(prev) = self.profile_aux_tasks.remove(&pid) {
            prev.abort();
        }
        self.banner_message = Some(if rotate {
            format!("Rotating proxy IP for '{prof_name}'...")
        } else {
            format!("Checking proxy for '{prof_name}'...")
        });
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        let join_handle = tokio_handle.spawn(async move {
            crate::control::check_or_rotate_profile_proxy(&db, &profile, rotate).await
        });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.profile_aux_tasks.insert(pid.clone(), abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .profile_aux_tasks
                    .get(&pid)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.profile_aux_tasks.remove(&pid);
                }
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Task join error: {e}")),
                };
                if !app.profiles.iter().any(|p| p.id == pid) {
                    return;
                }
                let still_running =
                    matches!(app.statuses.get(&pid), Some(ProfileStatus::Running(_)));
                match res {
                    Ok((rot_opt, geo)) => {
                        app.reload_profiles();
                        if !still_running
                            && matches!(app.statuses.get(&pid), Some(ProfileStatus::Error))
                        {
                            app.statuses.insert(pid.clone(), ProfileStatus::Stopped);
                        }
                        app.banner_message = Some(match rot_opt {
                            Some(rot) => format!(
                                "Rotated '{prof_name}' ({rot}) -> {}",
                                geo.summary_badge()
                            ),
                            None => format!("Proxy OK: {}", geo.summary_badge()),
                        });
                    }
                    Err(e) => {
                        let err_s = e.to_string();
                        if !still_running
                            && !matches!(app.statuses.get(&pid), Some(ProfileStatus::Starting))
                        {
                            app.statuses.insert(pid.clone(), ProfileStatus::Error);
                        }
                        app.banner_message = Some(format!("Proxy failed: {err_s}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn launch_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if matches!(
            self.statuses.get(profile_id),
            Some(ProfileStatus::Running(_) | ProfileStatus::Starting)
        ) {
            return;
        }
        let Some(profile) = self.profiles.iter().find(|p| p.id == profile_id).cloned() else {
            return;
        };
        let pid = profile.id.clone();
        let short_id = profile.short_id();
        if let Some(prev) = self.profile_tasks.remove(&pid) {
            prev.abort();
        }
        if let Some(aux) = self.profile_aux_tasks.remove(&pid) {
            aux.abort();
        }
        self.statuses.insert(pid.clone(), ProfileStatus::Starting);
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        let db = self.db.clone();
        let sup = self.supervisor.clone();
        let join_handle = tokio_handle.spawn(async move { sup.ensure_launched(&db, &profile).await });
        let abort_handle = join_handle.abort_handle();
        let task_id = abort_handle.id();
        self.profile_tasks.insert(pid.clone(), abort_handle);

        cx.spawn(async move |this, cx| {
            let join_res = join_handle.await;
            let _ = this.update(cx, |app, cx| {
                if app
                    .profile_tasks
                    .get(&pid)
                    .is_some_and(|h| h.id() == task_id)
                {
                    app.profile_tasks.remove(&pid);
                }
                let still_starting =
                    matches!(app.statuses.get(&pid), Some(ProfileStatus::Starting));
                let res = match join_res {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => return,
                    Err(e) => Err(anyhow::anyhow!("Launch task error: {e}")),
                };
                if !still_starting || !app.profiles.iter().any(|p| p.id == pid) {
                    if res.is_ok() {
                        let sup_stop = app.supervisor.clone();
                        let pid_stop = pid.clone();
                        let sid_stop = short_id.clone();
                        app.tokio_handle.spawn_blocking(move || {
                            sup_stop.stop(&pid_stop, &sid_stop);
                        });
                    }
                    return;
                }
                match res {
                    Ok(info) => {
                        app.reload_profiles();
                        app.statuses
                            .insert(pid.clone(), ProfileStatus::Running(info.clone()));
                        app.banner_message = Some(format!(
                            "Launched PID {} • Agent session: bon_{short_id} (port {})",
                            info.pid, info.cdp_port
                        ));
                    }
                    Err(e) => {
                        app.statuses.insert(pid.clone(), ProfileStatus::Error);
                        app.banner_message = Some(format!("Launch blocked: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }

    pub fn stop_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let cancelled_starting = if let Some(handle) = self.profile_tasks.remove(profile_id) {
            handle.abort();
            true
        } else {
            false
        };
        let short_id = self
            .profiles
            .iter()
            .find(|p| p.id == profile_id)
            .map(|p| p.short_id())
            .unwrap_or_default();
        let sup = self.supervisor.clone();
        let pid_s = profile_id.to_string();
        let had_owned = sup.contains_owned(profile_id);
        if had_owned || !cancelled_starting {
            self.tokio_handle.spawn_blocking(move || {
                sup.stop(&pid_s, &short_id);
            });
        }
        self.statuses
            .insert(profile_id.to_string(), ProfileStatus::Stopped);
        self.banner_message = Some(if cancelled_starting {
            "Stopped starting profile".to_string()
        } else {
            "Stopped browser session (cookies flushed)".to_string()
        });
        cx.notify();
    }

    fn running_session_pair(&self, profile_id: &str) -> Option<(String, String)> {
        let profile = self.profiles.iter().find(|p| p.id == profile_id)?;
        let ProfileStatus::Running(info) = self.statuses.get(profile_id)? else {
            return None;
        };
        Some((profile.short_id(), info.ws_url.clone()))
    }


    pub fn install_kernel(&mut self, cx: &mut Context<Self>) {
        self.install_kernel_opts(false, cx);
    }

    pub fn install_kernel_opts(&mut self, force: bool, cx: &mut Context<Self>) {
        if self.installing_kernel {
            return;
        }
        self.installing_kernel = true;
        self.banner_message = Some(
            "Downloading & installing adryfish/fingerprint-chromium 148.0.7778.215 (~140MB)..."
                .to_string(),
        );
        cx.notify();

        let tokio_handle = self.tokio_handle.clone();
        cx.spawn(async move |this, cx| {
            let res = tokio_handle
                .spawn_blocking(move || crate::launcher::install_adryfish_kernel_blocking_opts(force))
                .await
                .unwrap_or_else(|e| Err(anyhow::anyhow!("Kernel install join error: {e}")));

            let _ = this.update(cx, |app, cx| {
                app.installing_kernel = false;
                match res {
                    Ok(info) => {
                        app.banner_message = Some(format!(
                            "Kernel installed & unquarantined: {}",
                            info.path.display()
                        ));
                        app.kernel_info = Some(info);
                    }
                    Err(e) => {
                        app.banner_message = Some(format!("Kernel install failed: {e}"));
                    }
                }
                cx.notify();
            });
        })
        .detach();
    }
}
