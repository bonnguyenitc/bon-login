//! Passive pointer/scroll plans. Same `seed` + session replays; a new session does not.
//! No `thread_rng`. Callers send these through CDP `Input.*` only.

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[derive(Debug, Clone, PartialEq)]
pub enum HumanStep {
    Call {
        method: &'static str,
        params: serde_json::Value,
    },
    SleepMs(u64),
}

#[derive(Debug, Clone, Copy)]
pub enum DwellKind {
    /// Feed video, 8–95s.
    Feed,
    /// Article, 20–180s.
    Article,
    /// Profile page, 3–12s.
    Profile,
}

const ALLOWED: &[&str] = &[
    "Input.dispatchMouseEvent",
    "Page.getLayoutMetrics",
    "Page.bringToFront",
    "Page.navigate",
];

pub fn methods_are_passive(steps: &[HumanStep]) -> bool {
    steps.iter().all(|step| match step {
        HumanStep::SleepMs(_) => true,
        HumanStep::Call { method, .. } => ALLOWED.contains(method),
    })
}

pub fn warmup_page(
    seed: u32,
    session: u64,
    page: u64,
    vw: i32,
    vh: i32,
    dwell_secs: u64,
) -> Vec<HumanStep> {
    let dwell = dwell_secs.clamp(1, 30) * 1000;
    if vw < 2 || vh < 2 {
        return vec![HumanStep::SleepMs(dwell)];
    }
    let mut rng = rng_for(seed, session, page);
    let mut steps = Vec::new();
    let x0 = vw / 5;
    let y0 = vh / 3;
    let x1 = (vw * 2 / 3).clamp(0, vw - 1);
    let y1 = (vh / 2).clamp(0, vh - 1);
    steps.extend(mouse_path(&mut rng, x0, y0, x1, y1, vw, vh));
    steps.extend(scroll(&mut rng, 420, vw / 2, vh / 2));
    steps.push(HumanStep::SleepMs(dwell));
    steps.extend(scroll(&mut rng, -160, vw / 2, vh / 2));
    steps.extend(idle_drift(&mut rng, x1, y1, vw, vh));
    steps.push(HumanStep::Call {
        method: "Page.bringToFront",
        params: serde_json::json!({}),
    });
    steps
}

pub fn dwell_ms(seed: u32, session: u64, kind: DwellKind) -> u64 {
    let mut rng = rng_for(seed, session, kind as u64);
    let (lo, hi): (f64, f64) = match kind {
        DwellKind::Feed => (8.0, 95.0),
        DwellKind::Article => (20.0, 180.0),
        DwellKind::Profile => (3.0, 12.0),
    };
    let u1 = rng.random::<f64>().clamp(1e-9, 1.0 - 1e-9);
    let u2 = rng.random::<f64>();
    let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
    let mid = (lo * hi).sqrt();
    let seconds = (mid * (0.35 * z).exp()).clamp(lo, hi);
    (seconds * 1000.0) as u64
}

pub fn key_pause_ms(seed: u32, index: usize, ch: char) -> u64 {
    let mut rng = rng_for(seed, index as u64, ch as u64);
    if matches!(ch, '.' | ',' | '!' | '?' | ';' | ':' | '\n') {
        rng.random_range(250..=600)
    } else {
        rng.random_range(45..=180)
    }
}

pub fn click_at(seed: u32, session: u64, x: i32, y: i32, vw: i32, vh: i32) -> Vec<HumanStep> {
    if vw < 2 || vh < 2 {
        return Vec::new();
    }
    let x = x.clamp(0, vw - 1);
    let y = y.clamp(0, vh - 1);
    let mut rng = rng_for(seed, session, 9);
    let hold = rng.random_range(40..=120);
    vec![
        mouse_move(x, y),
        HumanStep::Call {
            method: "Input.dispatchMouseEvent",
            params: serde_json::json!({
                "type": "mousePressed",
                "x": x,
                "y": y,
                "button": "left",
                "buttons": 1,
                "clickCount": 1,
            }),
        },
        HumanStep::SleepMs(hold),
        HumanStep::Call {
            method: "Input.dispatchMouseEvent",
            params: serde_json::json!({
                "type": "mouseReleased",
                "x": x,
                "y": y,
                "button": "left",
                "buttons": 0,
                "clickCount": 1,
            }),
        },
    ]
}

fn mouse_path(
    rng: &mut StdRng,
    x0: i32,
    y0: i32,
    x1: i32,
    y1: i32,
    vw: i32,
    vh: i32,
) -> Vec<HumanStep> {
    let c1x = clamp_i(x0 + rng.random_range(-40..80), vw);
    let c1y = clamp_i(y0 + rng.random_range(-30..70), vh);
    let c2x = clamp_i(x1 + rng.random_range(-80..40), vw);
    let c2y = clamp_i(y1 + rng.random_range(-70..30), vh);
    let n = 10;
    let mut steps = Vec::with_capacity(n + 2);
    for i in 1..=n {
        let t = i as f64 / n as f64;
        let (x, y) = cubic(x0, y0, c1x, c1y, c2x, c2y, x1, y1, t);
        steps.push(mouse_move(clamp_i(x, vw), clamp_i(y, vh)));
        steps.push(HumanStep::SleepMs(rng.random_range(32..=70)));
    }
    let ox = clamp_i(x1 + rng.random_range(2..8), vw);
    let oy = clamp_i(y1 + rng.random_range(-4..5), vh);
    steps.push(mouse_move(ox, oy));
    steps.push(HumanStep::SleepMs(rng.random_range(32..=70)));
    steps.push(mouse_move(clamp_i(x1, vw), clamp_i(y1, vh)));
    steps
}

fn scroll(rng: &mut StdRng, px: i32, x: i32, y: i32) -> Vec<HumanStep> {
    let sign = if px >= 0 { 1 } else { -1 };
    let px = px.abs();
    if px == 0 {
        return Vec::new();
    }
    let n = rng.random_range(8..=20);
    let reverse_n = if rng.random_range(0..5) == 0 {
        rng.random_range(1..=2)
    } else {
        0
    };
    let reverse_total = if reverse_n == 0 {
        0
    } else {
        (px / 12).clamp(1, 40)
    };
    let forward = px + reverse_total;
    let mut weights = Vec::with_capacity(n);
    let mut w = 1.0f64;
    for _ in 0..n {
        weights.push(w);
        w *= rng.random_range(0.72..0.92);
    }
    let sum_w: f64 = weights.iter().sum();
    let mut deltas: Vec<i32> = weights
        .iter()
        .map(|weight| ((*weight / sum_w) * forward as f64).round() as i32)
        .collect();
    let drift = forward - deltas.iter().sum::<i32>();
    if let Some(last) = deltas.last_mut() {
        *last += drift;
    }
    if reverse_n > 0 {
        let each = (reverse_total / reverse_n).max(1);
        let mut left = reverse_total;
        for i in 0..reverse_n {
            let d = if i + 1 == reverse_n { left } else { each.min(left) };
            left -= d;
            if d == 0 {
                break;
            }
            let at = rng.random_range(0..=deltas.len());
            deltas.insert(at, -d);
        }
    }
    deltas
        .into_iter()
        .map(|d| {
            (
                HumanStep::Call {
                    method: "Input.dispatchMouseEvent",
                    params: serde_json::json!({
                        "type": "mouseWheel",
                        "x": x,
                        "y": y,
                        "deltaX": 0,
                        "deltaY": d * sign,
                    }),
                },
                HumanStep::SleepMs(rng.random_range(120..=600)),
            )
        })
        .flat_map(|(ev, sleep)| [ev, sleep])
        .collect()
}

fn idle_drift(rng: &mut StdRng, x: i32, y: i32, vw: i32, vh: i32) -> Vec<HumanStep> {
    let mut steps = Vec::new();
    let mut cx = x;
    let mut cy = y;
    for _ in 0..3 {
        cx = clamp_i(cx + rng.random_range(-12..13), vw);
        cy = clamp_i(cy + rng.random_range(-8..9), vh);
        steps.push(mouse_move(cx, cy));
        steps.push(HumanStep::SleepMs(rng.random_range(80..=200)));
    }
    steps
}

fn mouse_move(x: i32, y: i32) -> HumanStep {
    HumanStep::Call {
        method: "Input.dispatchMouseEvent",
        params: serde_json::json!({
            "type": "mouseMoved",
            "x": x,
            "y": y,
            "buttons": 0,
        }),
    }
}

fn cubic(x0: i32, y0: i32, c1x: i32, c1y: i32, c2x: i32, c2y: i32, x1: i32, y1: i32, t: f64) -> (i32, i32) {
    let u = 1.0 - t;
    let b = |a: i32, b: i32, c: i32, d: i32| {
        (u.powi(3) * a as f64
            + 3.0 * u.powi(2) * t * b as f64
            + 3.0 * u * t.powi(2) * c as f64
            + t.powi(3) * d as f64)
            .round() as i32
    };
    (b(x0, c1x, c2x, x1), b(y0, c1y, c2y, y1))
}

fn clamp_i(v: i32, size: i32) -> i32 {
    v.clamp(0, size.saturating_sub(1).max(0))
}

fn rng_for(seed: u32, session: u64, salt: u64) -> StdRng {
    StdRng::seed_from_u64(
        (seed as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(session.wrapping_mul(0xBF58_476D_1CE4_E5B9))
            .wrapping_add(salt.wrapping_mul(0x94D0_49BB_1331_11EB)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn points(steps: &[HumanStep]) -> Vec<(i32, i32)> {
        steps
            .iter()
            .filter_map(|s| match s {
                HumanStep::Call { params, .. }
                    if params.get("type").and_then(|v| v.as_str()) == Some("mouseMoved") =>
                {
                    Some((
                        params.get("x").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                        params.get("y").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
                    ))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn path_stays_inside_viewport_and_replays_only_same_session() {
        let a = warmup_page(42, 1, 0, 1280, 800, 5);
        let b = warmup_page(42, 1, 0, 1280, 800, 5);
        let c = warmup_page(42, 2, 0, 1280, 800, 5);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(methods_are_passive(&a));
        for (x, y) in points(&a) {
            assert!((0..1280).contains(&x), "{x}");
            assert!((0..800).contains(&y), "{y}");
        }
        assert!(warmup_page(42, 1, 0, 0, 0, 5).iter().all(|s| matches!(s, HumanStep::SleepMs(_))));
    }

    #[test]
    fn wheel_sum_matches_requested_pixels() {
        let steps = warmup_page(7, 3, 1, 1000, 700, 2);
        let mut wheels = Vec::new();
        for step in &steps {
            if let HumanStep::Call { params, .. } = step
                && params.get("type").and_then(|v| v.as_str()) == Some("mouseWheel")
            {
                wheels.push(params.get("deltaY").and_then(|v| v.as_i64()).unwrap_or(0));
            }
        }
        let down: i64 = wheels.iter().filter(|d| **d > 0).sum();
        let up: i64 = wheels.iter().filter(|d| **d < 0).sum();
        assert_eq!(down + up, 420 - 160);
        assert!(wheels.len() >= 8);
    }

    #[test]
    fn dwell_and_key_pauses_stay_in_range() {
        for kind in [DwellKind::Feed, DwellKind::Article, DwellKind::Profile] {
            let (lo, hi) = match kind {
                DwellKind::Feed => (8_000, 95_000),
                DwellKind::Article => (20_000, 180_000),
                DwellKind::Profile => (3_000, 12_000),
            };
            for session in 0..12 {
                let ms = dwell_ms(99, session, kind);
                assert!((lo..=hi).contains(&ms), "{ms} {kind:?}");
            }
        }
        assert!((45..=180).contains(&key_pause_ms(3, 0, 'a')));
        assert!((250..=600).contains(&key_pause_ms(3, 1, '.')));
        let click = click_at(3, 1, 10, 10, 200, 200);
        assert!(methods_are_passive(&click));
        assert!(!click.is_empty());
    }
}
