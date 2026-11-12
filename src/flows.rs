use crate::launcher::{
    agent_browser_cmd_for_short_id_in, ensure_agent_browser_connected_in,
    should_reconnect_agent_session, validate_stealth_agent_args,
};
use crate::models::{Profile, unix_now};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

// Agent Flow Playbooks (Record @eN -> Stable Locators, Replay & Self-Heal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct SnapshotRefMeta {
    pub role: String,
    pub name: String,
    pub unique: bool,
    #[serde(default)]
    pub role_index: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefDomAttrs {
    pub data_testid: String,
    pub id: String,
    pub name: String,
    pub placeholder: String,
    pub aria_label: String,
    pub href: String,
    pub input_type: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct FlowStep {
    pub op: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_args: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct AgentFlow {
    pub name: String,
    #[serde(default)]
    pub domain: String,
    pub updated_at: i64,
    pub steps: Vec<FlowStep>,
}

pub fn flows_dir_in(root_dir: &Path) -> PathBuf {
    let dir = root_dir.join("flows");
    let _ = std::fs::create_dir_all(&dir);
    dir
}


pub fn sanitize_flow_name(raw: &str) -> Result<String> {
    let clean: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_matches('_').to_string();
    if clean.is_empty() {
        bail!("Invalid flow name '{raw}'");
    }
    Ok(clean)
}

pub fn flow_file_path_in(root_dir: &Path, name: &str) -> Result<PathBuf> {
    let clean = sanitize_flow_name(name)?;
    Ok(flows_dir_in(root_dir).join(format!("{clean}.json")))
}

pub(crate) fn snap_cache_path_in(root_dir: &Path, short_id: &str) -> PathBuf {
    flows_dir_in(root_dir).join(format!("_snap_{short_id}.json"))
}

pub fn history_flow_path_in(root_dir: &Path, short_id: &str) -> PathBuf {
    flows_dir_in(root_dir).join(format!("_history_{short_id}.json"))
}

pub fn clear_flow_session_cache_in(root_dir: &Path, short_id: &str) {
    let _ = std::fs::remove_file(snap_cache_path_in(root_dir, short_id));
    let _ = std::fs::remove_file(history_flow_path_in(root_dir, short_id));
}

pub(crate) fn load_snap_cache_in(
    root_dir: &Path,
    short_id: &str,
) -> std::collections::HashMap<String, SnapshotRefMeta> {
    std::fs::read_to_string(snap_cache_path_in(root_dir, short_id))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub(crate) fn save_snap_cache_in(
    root_dir: &Path,
    short_id: &str,
    map: &std::collections::HashMap<String, SnapshotRefMeta>,
) {
    if let Ok(json) = serde_json::to_string(map) {
        let _ = std::fs::write(snap_cache_path_in(root_dir, short_id), json);
    }
}

pub fn parse_snapshot_refs(
    stdout: &str,
) -> std::collections::HashMap<String, SnapshotRefMeta> {
    let mut raw_entries: Vec<(String, String, String)> = Vec::new();

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(stdout)
        && let Some(refs_obj) = val
            .get("data")
            .and_then(|d| d.get("refs"))
            .and_then(|r| r.as_object())
    {
        for (k, v) in refs_obj {
            let key = k.trim_start_matches('@').to_string();
            let role = v
                .get("role")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            let name = v
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .trim()
                .to_string();
            raw_entries.push((key, role, name));
        }
        raw_entries.sort_by_key(|(k, _, _)| k.trim_start_matches('e').parse::<u32>().unwrap_or(0));
    }
    if raw_entries.is_empty() {
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("- ") {
                if let Some(ref_pos) = rest.find("ref=e") {
                    let after_ref = &rest[ref_pos + 4..];
                    let ref_key: String = after_ref
                        .chars()
                        .take_while(|c| *c == 'e' || c.is_ascii_digit())
                        .collect();
                    if ref_key.len() > 1 {
                        let before_bracket = rest[..ref_pos]
                            .rfind('[')
                            .map(|idx| rest[..idx].trim())
                            .unwrap_or(rest);
                        let role = before_bracket
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .to_string();
                        let name = if let Some(q1) = before_bracket.find('"')
                            && let Some(q2) = before_bracket.rfind('"')
                            && q2 > q1
                        {
                            before_bracket[q1 + 1..q2].replace("\\\"", "\"")
                        } else {
                            String::new()
                        };
                        raw_entries.push((ref_key, role, name));
                    }
                }
            } else if let Some(after_at) = trimmed.strip_prefix('@') {
                let ref_key: String = after_at
                    .chars()
                    .take_while(|c| *c == 'e' || c.is_ascii_digit())
                    .collect();
                if ref_key.starts_with('e')
                    && ref_key.len() > 1
                    && let Some(b1) = trimmed.find('[')
                    && let Some(b2) = trimmed[b1 + 1..].find(']')
                {
                    let bracket_inner = &trimmed[b1 + 1..b1 + 1 + b2];
                    let role = bracket_inner
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    let after_bracket = &trimmed[b1 + 1 + b2 + 1..];
                    let name = if let Some(q1) = after_bracket.find('"')
                        && let Some(q2) = after_bracket[q1 + 1..].find('"')
                    {
                        after_bracket[q1 + 1..q1 + 1 + q2].to_string()
                    } else {
                        String::new()
                    };
                    raw_entries.push((ref_key, role, name));
                }
            }
        }
    }

    let mut counts: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    for (_, role, name) in &raw_entries {
        if !role.is_empty() && !name.is_empty() {
            *counts.entry((role.clone(), name.clone())).or_insert(0) += 1;
        }
    }

    let mut role_indices: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut map = std::collections::HashMap::new();
    for (key, role, name) in raw_entries {
        let unique = !role.is_empty()
            && !name.is_empty()
            && counts
                .get(&(role.clone(), name.clone()))
                .copied()
                .unwrap_or(0)
                == 1;
        let role_counter = role_indices.entry(role.to_ascii_lowercase()).or_insert(0);
        let role_index = *role_counter;
        *role_counter += 1;
        map.insert(
            key,
            SnapshotRefMeta {
                role,
                name,
                unique,
                role_index,
            },
        );
    }
    map
}

pub fn build_jev_find_payload(
    step: &FlowStep,
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
) -> serde_json::Value {
    let mut sorted: Vec<(&String, &SnapshotRefMeta)> = snap_map.iter().collect();
    sorted.sort_by_key(|(k, _)| k.trim_start_matches('e').parse::<u32>().unwrap_or(0));
    let candidates: Vec<serde_json::Value> = sorted
        .into_iter()
        .filter(|(_, m)| !matches!(m.role.as_str(), "heading" | "paragraph"))
        .take(250)
        .map(|(k, m)| {
            let label = if m.name.is_empty() {
                format!("[@{k}] {}", m.role)
            } else {
                let short_name: String = m.name.chars().take(300).collect();
                format!("[@{k}] {} · {short_name}", m.role)
            };
            serde_json::json!({
                "id": format!("@{k}"),
                "text": label,
            })
        })
        .collect();
    serde_json::json!({
        "query": format!(
            "Interactive control for '{}' operation matching prior locators: {}",
            step.op,
            step.locators.join(", ")
        ),
        "candidates": candidates,
        "top_k": 3,
    })
}

pub fn split_shell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match in_quote {
            Some(q) if c == q => in_quote = None,
            Some('"') if c == '\\' => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => in_quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

fn is_ref_token(s: &str) -> bool {
    let rest = s.strip_prefix("@e").unwrap_or("");
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

fn css_attr_escape(val: &str) -> String {
    val.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn build_stable_locators(
    ref_token: &str,
    snap: Option<&SnapshotRefMeta>,
    attrs: &RefDomAttrs,
) -> Vec<String> {
    let mut out = Vec::new();
    fn push_unique(out: &mut Vec<String>, loc: String) {
        if !loc.is_empty() && !out.contains(&loc) {
            out.push(loc);
        }
    }

    if !attrs.data_testid.is_empty() {
        push_unique(
            &mut out,
            format!("[data-testid=\"{}\"]", css_attr_escape(&attrs.data_testid)),
        );
    }
    if !attrs.id.is_empty()
        && !attrs.id.contains(':')
        && !attrs.id.contains(' ')
        && !attrs.id.chars().all(|c| c.is_ascii_digit())
    {
        push_unique(
            &mut out,
            format!("[id=\"{}\"]", css_attr_escape(&attrs.id)),
        );
    }
    if !attrs.name.is_empty() {
        push_unique(
            &mut out,
            format!("[name=\"{}\"]", css_attr_escape(&attrs.name)),
        );
    }
    if let Some(s) = snap
        && !s.role.is_empty()
        && !s.name.is_empty()
        && s.unique
    {
        push_unique(&mut out, format!("role:{}:{}", s.role, s.name));
    }
    if !attrs.placeholder.is_empty() {
        push_unique(
            &mut out,
            format!("[placeholder=\"{}\"]", css_attr_escape(&attrs.placeholder)),
        );
    }
    if !attrs.aria_label.is_empty() {
        push_unique(
            &mut out,
            format!("[aria-label=\"{}\"]", css_attr_escape(&attrs.aria_label)),
        );
    }
    if let Some(s) = snap
        && !s.role.is_empty()
        && !s.name.is_empty()
    {
        push_unique(&mut out, format!("role:{}:{}", s.role, s.name));
    }
    if !attrs.href.is_empty()
        && !attrs.href.starts_with('#')
        && !attrs.href.starts_with("javascript:")
    {
        push_unique(
            &mut out,
            format!("a[href=\"{}\"]", css_attr_escape(&attrs.href)),
        );
    }
    if matches!(
        attrs.input_type.as_str(),
        "email" | "password" | "search" | "tel" | "url" | "submit" | "checkbox" | "radio" | "file"
    ) {
        push_unique(
            &mut out,
            format!("input[type=\"{}\"]", css_attr_escape(&attrs.input_type)),
        );
    }
    if out.is_empty()
        && let Some(s) = snap
        && !s.role.is_empty()
    {
        push_unique(&mut out, format!("role:{}:", s.role));
    }
    if out.is_empty() {
        push_unique(&mut out, ref_token.to_string());
    }
    out
}

pub fn match_ref_dom_attrs_from_nodes(
    refs: &[String],
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
    nodes: &[serde_json::Value],
) -> std::collections::HashMap<String, RefDomAttrs> {
    let mut map = std::collections::HashMap::new();
    for r in refs {
        let key = r.trim_start_matches('@');
        let Some(snap) = snap_map.get(key) else {
            continue;
        };
        let matched = if !snap.name.is_empty() {
            nodes
                .iter()
                .find(|n| {
                    let nr = n.get("role").and_then(|v| v.as_str()).unwrap_or_default();
                    let na = n
                        .get("accName")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    nr.eq_ignore_ascii_case(&snap.role) && na.eq_ignore_ascii_case(&snap.name)
                })
                .or_else(|| {
                    nodes.iter().find(|n| {
                        n.get("accName")
                            .and_then(|v| v.as_str())
                            .is_some_and(|na| na.eq_ignore_ascii_case(&snap.name))
                    })
                })
        } else {
            None
        }
        .or_else(|| {
            nodes
                .iter()
                .filter(|n| {
                    n.get("role")
                        .and_then(|v| v.as_str())
                        .is_some_and(|nr| nr.eq_ignore_ascii_case(&snap.role))
                })
                .nth(snap.role_index)
        });
        if let Some(node) = matched {
            let get_s = |field: &str| -> String {
                node.get(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            };
            map.insert(
                r.clone(),
                RefDomAttrs {
                    data_testid: get_s("testid"),
                    id: get_s("id"),
                    name: get_s("name"),
                    placeholder: get_s("placeholder"),
                    aria_label: get_s("ariaLabel"),
                    href: get_s("href"),
                    input_type: get_s("type"),
                },
            );
        }
    }
    map
}

fn fetch_refs_dom_attrs_in(
    root_dir: &Path,
    short_id: &str,
    session: &str,
    ws_url: &str,
    refs: &[String],
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
) -> std::collections::HashMap<String, RefDomAttrs> {
    if refs.is_empty() {
        return std::collections::HashMap::new();
    }
    let js = r#"JSON.stringify(Array.from(document.querySelectorAll('input,button,a,select,textarea,[role],[data-testid]')).slice(0, 300).map(el => ({
        role: (el.getAttribute('role') || (el.tagName==='BUTTON'||(el.tagName==='INPUT'&&/^(submit|button|reset)$/i.test(el.type))?'button':el.tagName==='A'?'link':el.tagName==='SELECT'?'combobox':el.tagName==='INPUT'&&el.type==='checkbox'?'checkbox':el.tagName==='INPUT'&&el.type==='radio'?'radio':(el.tagName==='INPUT'||el.tagName==='TEXTAREA')?'textbox':'')).toLowerCase(),
        accName: (el.getAttribute('aria-label') || (el.labels && el.labels[0] ? el.labels[0].innerText : '') || el.getAttribute('placeholder') || el.getAttribute('title') || el.innerText || el.value || '').trim(),
        testid: el.getAttribute('data-testid') || '',
        id: el.id || '',
        name: el.getAttribute('name') || '',
        placeholder: el.getAttribute('placeholder') || '',
        ariaLabel: el.getAttribute('aria-label') || '',
        href: el.getAttribute('href') || '',
        type: el.getAttribute('type') || ''
    })))"#;
    let Ok(out) = agent_browser_cmd_for_short_id_in(root_dir, short_id)
        .args([
            "--session",
            session,
            "--cdp",
            ws_url,
            "--input-mode",
            "human",
            "eval",
            js,
        ])
        .output()
    else {
        return std::collections::HashMap::new();
    };
    if !out.status.success() {
        return std::collections::HashMap::new();
    }
    let raw_out = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let json_str = serde_json::from_str::<String>(&raw_out).unwrap_or(raw_out);
    let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&json_str) else {
        return std::collections::HashMap::new();
    };
    match_ref_dom_attrs_from_nodes(refs, snap_map, &nodes)
}

fn strip_leading_agent_flags(tokens: &[String]) -> &[String] {
    let mut idx = 0;
    while idx < tokens.len() {
        match tokens[idx].as_str() {
            "--json" | "--bail" | "--omit-command" | "--headed" | "--full" | "-i" | "-c"
            | "--interactive" | "--compact" => idx += 1,
            _ => break,
        }
    }
    &tokens[idx..]
}

pub(crate) fn unpack_agent_commands(ab_args: &[String]) -> Vec<Vec<String>> {
    let trimmed = strip_leading_agent_flags(ab_args);
    if trimmed.first().is_some_and(|c| c == "batch") {
        let mut sub_cmds = Vec::new();
        for arg in &trimmed[1..] {
            if arg.starts_with('-') {
                continue;
            }
            let words = split_shell_words(arg);
            if !words.is_empty() {
                sub_cmds.push(words);
            }
        }
        sub_cmds
    } else if !trimmed.is_empty() {
        vec![trimmed.to_vec()]
    } else {
        Vec::new()
    }
}

pub fn build_flow_step_from_cmd(
    raw_tokens: &[String],
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
    dom_attrs: &std::collections::HashMap<String, RefDomAttrs>,
) -> Option<FlowStep> {
    let tokens = strip_leading_agent_flags(raw_tokens);
    let cmd = tokens.first()?.as_str();
    let resolve_target = |target: &str| -> Vec<String> {
        if is_ref_token(target) {
            let key = target.trim_start_matches('@');
            let snap = snap_map.get(key);
            let attrs = dom_attrs.get(target).cloned().unwrap_or_default();
            build_stable_locators(target, snap, &attrs)
        } else {
            vec![target.to_string()]
        }
    };

    match cmd {
        "open" | "goto" | "navigate" => {
            let url = tokens.iter().skip(1).find(|s| !s.starts_with('-'))?.clone();
            Some(FlowStep {
                op: "open".to_string(),
                locators: Vec::new(),
                value: Some(url),
                extra_args: Vec::new(),
                optional: false,
            })
        }
        "click" | "dblclick" | "hover" | "focus" | "check" | "uncheck" | "scrollintoview"
        | "scrollinto" => {
            let target = tokens.get(1)?;
            let op = if cmd == "scrollinto" {
                "scrollintoview"
            } else {
                cmd
            };
            Some(FlowStep {
                op: op.to_string(),
                locators: resolve_target(target),
                value: None,
                extra_args: tokens[2..].to_vec(),
                optional: false,
            })
        }
        "fill" | "type" | "select" | "upload" => {
            let target = tokens.get(1)?;
            let val = tokens.get(2)?.clone();
            Some(FlowStep {
                op: cmd.to_string(),
                locators: resolve_target(target),
                value: Some(val),
                extra_args: tokens[3..].to_vec(),
                optional: false,
            })
        }
        "press" | "key" => {
            let key = tokens.get(1)?.clone();
            Some(FlowStep {
                op: "press".to_string(),
                locators: Vec::new(),
                value: Some(key),
                extra_args: Vec::new(),
                optional: false,
            })
        }
        "scroll" => {
            let dir = tokens.get(1)?.clone();
            Some(FlowStep {
                op: "scroll".to_string(),
                locators: Vec::new(),
                value: Some(dir),
                extra_args: tokens[2..].to_vec(),
                optional: false,
            })
        }
        "wait" => {
            let first_arg = tokens.get(1)?;
            if is_ref_token(first_arg) {
                Some(FlowStep {
                    op: "wait".to_string(),
                    locators: resolve_target(first_arg),
                    value: None,
                    extra_args: tokens[2..].to_vec(),
                    optional: false,
                })
            } else {
                Some(FlowStep {
                    op: "wait".to_string(),
                    locators: Vec::new(),
                    value: None,
                    extra_args: tokens[1..].to_vec(),
                    optional: false,
                })
            }
        }
        "find" => {
            let kind = tokens.get(1)?.as_str();
            match kind {
                "role" => {
                    let role = tokens.get(2)?;
                    let action = tokens.get(3).map(String::as_str).unwrap_or("click");
                    let mut name = String::new();
                    let mut value: Option<String> = None;
                    let mut idx = 4;
                    while idx < tokens.len() {
                        match tokens[idx].as_str() {
                            "--name" => {
                                name = tokens.get(idx + 1).cloned().unwrap_or_default();
                                idx += 2;
                            }
                            "--exact" => idx += 1,
                            other if !other.starts_with('-') => {
                                value = Some(other.to_string());
                                idx += 1;
                            }
                            _ => idx += 1,
                        }
                    }
                    Some(FlowStep {
                        op: action.to_string(),
                        locators: vec![format!("role:{role}:{name}")],
                        value,
                        extra_args: Vec::new(),
                        optional: false,
                    })
                }
                "text" | "label" | "placeholder" | "testid" => {
                    let target_val = tokens.get(2)?;
                    let action = tokens.get(3).map(String::as_str).unwrap_or("click");
                    let value = tokens
                        .iter()
                        .skip(4)
                        .find(|s| !s.starts_with('-'))
                        .cloned();
                    let loc = match kind {
                        "text" => format!("text:{target_val}"),
                        "label" => format!("label:{target_val}"),
                        "placeholder" => {
                            format!("[placeholder=\"{}\"]", css_attr_escape(target_val))
                        }
                        "testid" => format!("[data-testid=\"{}\"]", css_attr_escape(target_val)),
                        _ => unreachable!(),
                    };
                    Some(FlowStep {
                        op: action.to_string(),
                        locators: vec![loc],
                        value,
                        extra_args: Vec::new(),
                        optional: false,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

pub(crate) fn prepare_recorded_steps_in(
    root_dir: &Path,
    short_id: &str,
    session: &str,
    ws_url: &str,
    ab_args: &[String],
) -> Vec<FlowStep> {
    let cmds = unpack_agent_commands(ab_args);
    if cmds.is_empty() {
        return Vec::new();
    }
    let mut refs_to_query = Vec::new();
    for c in &cmds {
        for tok in c {
            if is_ref_token(tok) && !refs_to_query.contains(tok) {
                refs_to_query.push(tok.clone());
            }
        }
    }
    let snap_map = load_snap_cache_in(root_dir, short_id);
    let dom_attrs = if refs_to_query.is_empty() {
        std::collections::HashMap::new()
    } else {
        fetch_refs_dom_attrs_in(root_dir, short_id, session, ws_url, &refs_to_query, &snap_map)
    };
    cmds.iter()
        .filter_map(|c| build_flow_step_from_cmd(c, &snap_map, &dom_attrs))
        .collect()
}

fn extract_domain_from_url(url: &str) -> String {
    let without_proto = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    without_proto
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .to_string()
}

pub fn load_flow_from_path(path: &Path, default_name: &str) -> Result<AgentFlow> {
    if !path.exists() {
        return Ok(AgentFlow {
            name: default_name.to_string(),
            domain: String::new(),
            updated_at: unix_now(),
            steps: Vec::new(),
        });
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read flow file {}", path.display()))?;
    serde_json::from_str::<AgentFlow>(&raw)
        .with_context(|| format!("Invalid JSON in flow file {}", path.display()))
}

pub(crate) static FLOW_FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn save_flow_to_path(path: &Path, flow: &mut AgentFlow) -> Result<()> {
    flow.updated_at = unix_now();
    if flow.domain.is_empty()
        && let Some(first_url) = flow
            .steps
            .iter()
            .find(|s| s.op == "open")
            .and_then(|s| s.value.as_deref())
    {
        flow.domain = extract_domain_from_url(first_url);
    }
    let json = serde_json::to_string_pretty(flow)?;
    let tmp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::write(&tmp_path, json)?;
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

pub(crate) fn promote_flow_step_locator(path: &Path, default_name: &str, step_idx: usize, winning_loc: &str) {
    let _guard = FLOW_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(mut fresh) = load_flow_from_path(path, default_name) else {
        return;
    };
    if let Some(st) = fresh.steps.get_mut(step_idx)
        && let Some(pos) = st.locators.iter().position(|l| l == winning_loc)
        && pos > 0
    {
        let winner = st.locators.remove(pos);
        st.locators.insert(0, winner);
        let _ = save_flow_to_path(path, &mut fresh);
    }
}

pub(crate) fn append_steps_to_flow_path(path: &Path, name: &str, new_steps: &[FlowStep]) {
    if new_steps.is_empty() {
        return;
    }
    let _guard = FLOW_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(mut flow) = load_flow_from_path(path, name) else {
        return;
    };
    for step in new_steps {
        if flow.steps.last() != Some(step) {
            flow.steps.push(step.clone());
        }
    }
    let _ = save_flow_to_path(path, &mut flow);
}

pub fn extract_flow_vars(flow: &AgentFlow) -> Vec<String> {
    let mut vars = Vec::new();
    let mut scan_str = |s: &str| {
        let mut rest = s;
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            if let Some(end) = after.find("}}") {
                let v = after[..end].trim();
                if !v.is_empty() && !vars.iter().any(|x| x == v) {
                    vars.push(v.to_string());
                }
                rest = &after[end + 2..];
            } else {
                break;
            }
        }
    };
    for step in &flow.steps {
        if let Some(v) = &step.value {
            scan_str(v);
        }
        for l in &step.locators {
            scan_str(l);
        }
        for a in &step.extra_args {
            scan_str(a);
        }
    }
    vars
}

pub fn parameterize_flow_steps(
    steps: &mut [FlowStep],
    literal_to_var: &[(String, String)],
) {
    let mut sorted: Vec<&(String, String)> = literal_to_var
        .iter()
        .filter(|(_, lit)| !lit.is_empty())
        .collect();
    sorted.sort_by_key(|(_, lit)| std::cmp::Reverse(lit.len()));
    for (var_name, literal) in sorted {
        let placeholder = format!("{{{{{var_name}}}}}");
        let is_secret_var = matches!(
            var_name.to_ascii_lowercase().as_str(),
            "pass" | "password" | "pwd" | "secret" | "otp" | "totp" | "pin" | "code"
        );
        let replace_field = |target: &mut String, is_open_url: bool| {
            if *target == *literal {
                *target = placeholder.clone();
            } else if literal.len() >= 4
                && (!is_open_url || (!is_secret_var && !literal.contains('@')))
                && target.contains(literal.as_str())
            {
                *target = target.replace(literal, &placeholder);
            }
        };
        for step in steps.iter_mut() {
            let is_open = step.op == "open";
            if let Some(val) = &mut step.value {
                replace_field(val, is_open);
            }
            for extra in &mut step.extra_args {
                replace_field(extra, is_open);
            }
        }
    }
}

pub fn substitute_flow_vars(
    input: &str,
    vars: &std::collections::HashMap<String, String>,
) -> String {
    let mut out = input.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}
pub(crate) fn parse_var_flag(args: &[String], idx: usize) -> Option<((String, String), usize)> {
    if args.get(idx)? == "--var" {
        let (k, v) = args.get(idx + 1)?.split_once('=')?;
        Some(((k.trim().to_string(), v.to_string()), 2))
    } else if let Some(kv) = args.get(idx)?.strip_prefix("--var=") {
        let (k, v) = kv.split_once('=')?;
        Some(((k.trim().to_string(), v.to_string()), 1))
    } else {
        None
    }
}

pub trait AgentSession {
    fn exec(&mut self, args: &[String]) -> std::result::Result<String, String>;
}

pub struct SubprocessAgentSession<'a> {
    pub root_dir: &'a Path,
    pub short_id: &'a str,
    pub session: &'a str,
    pub ws_url: &'a str,
}

impl AgentSession for SubprocessAgentSession<'_> {
    fn exec(&mut self, args: &[String]) -> std::result::Result<String, String> {
        let out = run_agent_browser_with_reconnect_in(
            self.root_dir,
            self.short_id,
            self.session,
            self.ws_url,
            args,
        )
        .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let out_s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            Err(if !err.is_empty() { err } else { out_s })
        }
    }
}

pub(crate) fn run_agent_browser_with_reconnect_in(
    root_dir: &Path,
    short_id: &str,
    session: &str,
    ws_url: &str,
    args: &[String],
) -> Result<std::process::Output> {
    validate_stealth_agent_args(args)?;
    let run_once = || {
        agent_browser_cmd_for_short_id_in(root_dir, short_id)
            .args(["--session", session, "--cdp", ws_url, "--input-mode", "human"])
            .args(args)
            .output()
            .context("Failed to execute agent-browser")
    };
    let mut out = run_once()?;
    if !out.status.success() && should_reconnect_agent_session(&out.stderr, &out.stdout) {
        let _ = ensure_agent_browser_connected_in(root_dir, short_id, ws_url);
        out = run_once()?;
    }
    Ok(out)
}

pub fn build_locator_candidate_commands(
    op: &str,
    locator: &str,
    value: Option<&str>,
    extra_args: &[String],
) -> Vec<Vec<String>> {
    let find_supported = extra_args.is_empty() && matches!(op, "click" | "fill" | "check" | "hover");

    if let Some(rest) = locator.strip_prefix("role:") {
        if !find_supported {
            return Vec::new();
        }
        let (role, name) = rest.split_once(':').unwrap_or((rest, ""));
        let mut candidates = Vec::new();
        if !name.is_empty() {
            let mut exact_cmd = vec![
                "find".to_string(),
                "role".to_string(),
                role.to_string(),
                op.to_string(),
                "--name".to_string(),
                name.to_string(),
                "--exact".to_string(),
            ];
            if let Some(v) = value {
                exact_cmd.push(v.to_string());
            }
            candidates.push(exact_cmd);

            let mut sub_cmd = vec![
                "find".to_string(),
                "role".to_string(),
                role.to_string(),
                op.to_string(),
                "--name".to_string(),
                name.to_string(),
            ];
            if let Some(v) = value {
                sub_cmd.push(v.to_string());
            }
            candidates.push(sub_cmd);
        } else {
            let mut role_only = vec![
                "find".to_string(),
                "role".to_string(),
                role.to_string(),
                op.to_string(),
            ];
            if let Some(v) = value {
                role_only.push(v.to_string());
            }
            candidates.push(role_only);
        }
        return candidates;
    }

    if let Some((kind, target_val)) = locator
        .strip_prefix("text:")
        .map(|t| ("text", t))
        .or_else(|| locator.strip_prefix("label:").map(|l| ("label", l)))
    {
        if !find_supported {
            return Vec::new();
        }
        let mut exact_cmd = vec![
            "find".to_string(),
            kind.to_string(),
            target_val.to_string(),
            op.to_string(),
            "--exact".to_string(),
        ];
        if let Some(v) = value {
            exact_cmd.push(v.to_string());
        }
        let mut sub_cmd = vec![
            "find".to_string(),
            kind.to_string(),
            target_val.to_string(),
            op.to_string(),
        ];
        if let Some(v) = value {
            sub_cmd.push(v.to_string());
        }
        return vec![exact_cmd, sub_cmd];
    }

    let mut cmd = vec![op.to_string(), locator.to_string()];
    if let Some(v) = value {
        cmd.push(v.to_string());
    }
    cmd.extend_from_slice(extra_args);
    vec![cmd]
}

pub fn match_semantic_locator_in_snapshot(
    loc: &str,
    snap_map: &std::collections::HashMap<String, SnapshotRefMeta>,
) -> Option<String> {
    let mut sorted: Vec<(&String, &SnapshotRefMeta)> = snap_map.iter().collect();
    sorted.sort_by_key(|(k, _)| k.trim_start_matches('e').parse::<u32>().unwrap_or(0));

    if let Some(rest) = loc.strip_prefix("role:") {
        let (role, name) = rest.split_once(':').unwrap_or((rest, ""));
        if let Some((k, _)) = sorted.iter().find(|(_, m)| {
            m.role.eq_ignore_ascii_case(role)
                && (name.is_empty() || m.name.eq_ignore_ascii_case(name))
        }) {
            return Some((*k).clone());
        }
        if !name.is_empty() {
            let needle = name.to_ascii_lowercase();
            if let Some((k, _)) = sorted.iter().find(|(_, m)| {
                m.role.eq_ignore_ascii_case(role) && m.name.to_ascii_lowercase().contains(&needle)
            }) {
                return Some((*k).clone());
            }
        }
        return None;
    }

    if let Some(target_val) = loc
        .strip_prefix("text:")
        .or_else(|| loc.strip_prefix("label:"))
    {
        if let Some((k, _)) = sorted
            .iter()
            .find(|(_, m)| m.name.eq_ignore_ascii_case(target_val))
        {
            return Some((*k).clone());
        }
        if !target_val.is_empty() {
            let needle = target_val.to_ascii_lowercase();
            if let Some((k, _)) = sorted
                .iter()
                .find(|(_, m)| m.name.to_ascii_lowercase().contains(&needle))
            {
                return Some((*k).clone());
            }
        }
    }
    None
}

pub fn execute_single_flow_step_with(
    runner: &mut dyn AgentSession,
    step: &FlowStep,
    vars: &std::collections::HashMap<String, String>,
) -> std::result::Result<(usize, String), String> {
    let sub_value = step.value.as_ref().map(|v| substitute_flow_vars(v, vars));
    let sub_extra: Vec<String> = step
        .extra_args
        .iter()
        .map(|a| substitute_flow_vars(a, vars))
        .collect();

    if step.locators.is_empty() {
        let mut cmd = vec![step.op.clone()];
        if let Some(v) = &sub_value {
            cmd.push(v.clone());
        }
        cmd.extend_from_slice(&sub_extra);
        return runner.exec(&cmd).map(|_| (0, step.op.clone()));
    }

    let mut last_err = String::new();
    for (loc_idx, raw_loc) in step.locators.iter().enumerate() {
        let loc = substitute_flow_vars(raw_loc, vars);
        let candidates =
            build_locator_candidate_commands(&step.op, &loc, sub_value.as_deref(), &sub_extra);

        if candidates.is_empty()
            && (loc.starts_with("role:") || loc.starts_with("text:") || loc.starts_with("label:"))
        {
            match runner.exec(&[
                "snapshot".to_string(),
                "-i".to_string(),
                "-c".to_string(),
                "--json".to_string(),
            ]) {
                Ok(snap_stdout) => {
                    let snap_map = parse_snapshot_refs(&snap_stdout);
                    if let Some(ref_key) = match_semantic_locator_in_snapshot(&loc, &snap_map) {
                        let mut cmd = vec![step.op.clone(), format!("@{ref_key}")];
                        if let Some(v) = &sub_value {
                            cmd.push(v.clone());
                        }
                        cmd.extend_from_slice(&sub_extra);
                        match runner.exec(&cmd) {
                            Ok(_) => return Ok((loc_idx, loc)),
                            Err(e) => last_err = e,
                        }
                    } else {
                        last_err = format!("Element not found for {loc}");
                    }
                }
                Err(e) => last_err = e,
            }
        }

        for cmd in candidates {
            match runner.exec(&cmd) {
                Ok(_) => return Ok((loc_idx, loc)),
                Err(e) => last_err = e,
            }
        }
    }
    Err(last_err)
}

fn normalize_single_cmd_tokens(raw: &[String]) -> Vec<String> {
    let mut seen_cmd = false;
    let mut normalized_target = false;
    raw.iter()
        .map(|s| {
            if !seen_cmd {
                if !s.starts_with('-') {
                    seen_cmd = true;
                }
                return s.clone();
            }
            if !normalized_target && !s.starts_with('-') {
                normalized_target = true;
                if s.strip_prefix('e')
                    .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
                {
                    return format!("@{s}");
                }
            }
            s.clone()
        })
        .collect()
}

pub fn normalize_heal_agent_args(raw: &[String]) -> Vec<String> {
    if strip_leading_agent_flags(raw)
        .first()
        .is_some_and(|c| c == "batch")
    {
        let mut seen_batch = false;
        raw.iter()
            .map(|s| {
                if !seen_batch {
                    if s == "batch" {
                        seen_batch = true;
                    }
                    return s.clone();
                }
                if s.starts_with('-') {
                    return s.clone();
                }
                let words = normalize_single_cmd_tokens(&split_shell_words(s));
                words
                    .into_iter()
                    .map(|w| {
                        if w.chars().any(char::is_whitespace) {
                            format!("\"{}\"", w.replace('"', "\\\""))
                        } else {
                            w
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    } else {
        normalize_single_cmd_tokens(raw)
    }
}

pub fn list_saved_flows_in(root_dir: &Path) -> Vec<AgentFlow> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(flows_dir_in(root_dir)) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if fname.starts_with('_') || !fname.ends_with(".json") {
                continue;
            }
            let stem = fname.trim_end_matches(".json");
            if let Ok(flow) = load_flow_from_path(&path, stem) {
                out.push(flow);
            }
        }
    }
    out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then_with(|| a.name.cmp(&b.name)));
    out
}

pub fn parse_flow_vars_text(raw: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in raw.split(['\n', '\r', ',']) {
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            if !k.is_empty() {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            )
        {
            out.push(((hi << 4) | lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_flow_vars_body(raw: &str) -> std::collections::HashMap<String, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{')
        && let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed)
        && let Some(obj) = val
            .get("vars")
            .and_then(|v| v.as_object())
            .or_else(|| val.as_object())
    {
        let mut map = std::collections::HashMap::new();
        for (k, v) in obj {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => continue,
                other => other.to_string(),
            };
            map.insert(k.clone(), s);
        }
        return map;
    }
    parse_flow_vars_text(raw)
}

pub fn mutate_flow_step_in(
    root_dir: &Path,
    flow_raw: &str,
    step_idx: usize,
    action: &str,
) -> Result<AgentFlow> {
    let clean_name = sanitize_flow_name(flow_raw)?;
    let path = flow_file_path_in(root_dir, &clean_name)?;
    let _guard = FLOW_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if !path.is_file() {
        bail!("Flow '{}' not found at {}", clean_name, path.display());
    }
    let mut flow = load_flow_from_path(&path, &clean_name)?;
    if step_idx >= flow.steps.len() {
        bail!(
            "step_index {step_idx} out of range (flow '{}' has {} steps)",
            clean_name,
            flow.steps.len()
        );
    }
    match action {
        "optional" => flow.steps[step_idx].optional = true,
        "required" => flow.steps[step_idx].optional = false,
        "toggle" => flow.steps[step_idx].optional = !flow.steps[step_idx].optional,
        "delete" | "rm" | "remove" => {
            flow.steps.remove(step_idx);
        }
        other => bail!(
            "Unknown step action '{other}' (expected optional, required, toggle, or delete)"
        ),
    }
    save_flow_to_path(&path, &mut flow)?;
    Ok(flow)
}

#[derive(Debug, Clone)]
pub struct FlowReplayReport {
    pub executed_steps: Vec<serde_json::Value>,
    pub failure: Option<serde_json::Value>,
}

pub fn replay_flow_steps_with_in(
    root_dir: &Path,
    flow_name: &str,
    profile: &Profile,
    extra_vars: &std::collections::HashMap<String, String>,
    from_step: usize,
    runner: &mut dyn AgentSession,
) -> Result<FlowReplayReport> {
    let clean_name = sanitize_flow_name(flow_name)?;
    let path = flow_file_path_in(root_dir, &clean_name)?;
    if !path.is_file() {
        bail!("Flow '{}' not found at {}", clean_name, path.display());
    }
    let flow = load_flow_from_path(&path, &clean_name)?;
    if flow.steps.is_empty() {
        bail!("Flow '{}' has 0 steps", clean_name);
    }
    if from_step > flow.steps.len() {
        bail!(
            "from_step {from_step} out of range (flow '{}' has {} steps)",
            clean_name,
            flow.steps.len()
        );
    }
    let short_id = profile.short_id();
    let mut vars = extra_vars.clone();
    vars.entry("profile.name".to_string())
        .or_insert_with(|| profile.name.clone());
    vars.entry("profile.short_id".to_string())
        .or_insert_with(|| short_id.clone());
    vars.entry("profile.notes".to_string())
        .or_insert_with(|| profile.notes.clone());

    let mut executed_steps = Vec::new();
    let mut failure = None;

    for step_idx in from_step..flow.steps.len() {
        let step = flow.steps[step_idx].clone();
        match execute_single_flow_step_with(runner, &step, &vars) {
            Ok((winning_loc_idx, matched_locator)) => {
                if winning_loc_idx > 0 {
                    promote_flow_step_locator(&path, &clean_name, step_idx, &matched_locator);
                }
                executed_steps.push(serde_json::json!({
                    "step": step_idx,
                    "op": step.op,
                    "matched_locator": matched_locator,
                    "status": "ok",
                }));
            }
            Err(err_msg) => {
                if step.optional {
                    executed_steps.push(serde_json::json!({
                        "step": step_idx,
                        "op": step.op,
                        "status": "skipped_optional",
                    }));
                    continue;
                }
                let snap_txt = runner
                    .exec(&["snapshot".to_string(), "-i".to_string(), "-c".to_string()])
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let parsed = if !snap_txt.is_empty() {
                    let p = parse_snapshot_refs(&snap_txt);
                    if !p.is_empty() {
                        save_snap_cache_in(root_dir, &short_id, &p);
                    }
                    p
                } else {
                    std::collections::HashMap::new()
                };
                let jev_find_payload = build_jev_find_payload(&step, &parsed);
                failure = Some(serde_json::json!({
                    "failed_step": step_idx,
                    "step": step,
                    "error": err_msg,
                    "snapshot": snap_txt,
                    "jev_find_payload": jev_find_payload,
                    "heal_cli": format!(
                        "bon-login flow heal {clean_name} {step_idx} {short_id} <agent-browser cmd...>"
                    ),
                    "resume_cli": format!(
                        "bon-login flow run {clean_name} {short_id} --from-step {}",
                        step_idx + 1
                    ),
                }));
                break;
            }
        }
    }

    Ok(FlowReplayReport {
        executed_steps,
        failure,
    })
}

pub fn replay_flow_steps_in(
    root_dir: &Path,
    flow_name: &str,
    profile: &Profile,
    ws_url: &str,
    extra_vars: &std::collections::HashMap<String, String>,
    from_step: usize,
) -> Result<FlowReplayReport> {
    let short_id = profile.short_id();
    let session = format!("bon_{short_id}");
    let mut adapter = SubprocessAgentSession {
        root_dir,
        short_id: &short_id,
        session: &session,
        ws_url,
    };
    replay_flow_steps_with_in(root_dir, flow_name, profile, extra_vars, from_step, &mut adapter)
}

pub fn run_flow_on_live_session_in(
    root_dir: &Path,
    flow_name: &str,
    profile: &Profile,
    ws_url: &str,
    extra_vars: &std::collections::HashMap<String, String>,
) -> Result<usize> {
    let report = replay_flow_steps_in(root_dir, flow_name, profile, ws_url, extra_vars, 0)?;
    if let Some(fail) = report.failure {
        let idx = fail.get("failed_step").and_then(|v| v.as_u64()).unwrap_or(0);
        let op = fail
            .get("step")
            .and_then(|s| s.get("op"))
            .and_then(|v| v.as_str())
            .unwrap_or("step");
        let err = fail
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("failed");
        bail!("Step #{} ({}) failed: {}", idx + 1, op, err);
    }
    Ok(report
        .executed_steps
        .iter()
        .filter(|s| s.get("status").and_then(|v| v.as_str()) == Some("ok"))
        .count())
}


pub fn save_profile_history_as_flow_in(
    root_dir: &Path,
    flow_raw: &str,
    profile: &Profile,
    var_pairs: &[(String, String)],
) -> Result<AgentFlow> {
    let flow_name = sanitize_flow_name(flow_raw)?;
    let short_id = profile.short_id();
    let hist_path = history_flow_path_in(root_dir, &short_id);
    let mut hist = load_flow_from_path(&hist_path, &flow_name)?;
    if hist.steps.is_empty() {
        bail!(
            "No recorded DOM steps in history for '{}' (bon_{short_id})",
            profile.name
        );
    }
    parameterize_flow_steps(&mut hist.steps, var_pairs);
    hist.name = flow_name.clone();
    let out_path = flow_file_path_in(root_dir, &flow_name)?;
    save_flow_to_path(&out_path, &mut hist)?;
    Ok(hist)
}


