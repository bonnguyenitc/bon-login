//! Flow Builder: drag-and-drop editor for `flows/*.json` (same steps as `bon-login flow add`).

use gpui_kit::component::{
    button::{Button, ButtonVariants as _},
    input::{Input, InputState},
    *,
};
use gpui_kit::*;

use crate::flows::{CONTROL_OPS, DATA_OPS, FlowStep};
use crate::ui::theme::{BonTheme, SfSymbol};
use crate::ui::workspace_views::field_label;
use crate::ui::{ActivePopupModal, BonLoginApp};

/// Palette blocks as `flow add` lines; openers get a matching `end` when inserted.
const PALETTE: &[(&str, &str)] = &[
    ("Open URL", "open https://example.com"),
    ("Click", "click \"#selector\""),
    ("Fill", "fill \"#selector\" {{text}}"),
    ("Press key", "press Enter"),
    ("Wait", "wait 1000"),
    ("Get text", "--out text get text \"#selector\""),
    ("Eval JS", "--out result eval document.title"),
    ("HTTP request", "--out resp http https://api.example.com"),
    ("Read file", "--out content read_file data.txt"),
    ("Write file", "write_file out.txt {{content}} --append"),
    ("Regex", "--out match regex {{resp}} \"(\\\\d+)\""),
    ("JSON field", "--out value json {{resp}} data.id"),
    ("Shell cmd", "--out stdout cmd \"echo hello\""),
    ("If", "if {{value}} == 1"),
    ("Else", "else"),
    ("Loop N times", "--out i loop 3"),
    ("For each line", "--out line foreach {{content}}"),
    ("Break", "break"),
];

#[derive(Clone)]
pub struct FlowBuilderState {
    pub flow_name: String,
    pub steps: Vec<FlowStep>,
    pub selected: Option<usize>,
    pub args_input: Entity<InputState>,
    pub out_input: Entity<InputState>,
    /// Failed step index + error from the last run of this flow.
    pub failed: Option<(usize, String)>,
    /// Profile short id whose run is being watched for the live step highlight.
    pub run_short_id: Option<String>,
}

#[derive(Clone)]
enum FlowDrag {
    New(&'static str),
    Move(usize),
}

struct FlowDragPreview(SharedString);

impl Render for FlowDragPreview {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_3()
            .py_1()
            .rounded_md()
            .bg(BonTheme::bg_elevated())
            .border_1()
            .border_color(BonTheme::border_active())
            .text_xs()
            .font_semibold()
            .text_color(BonTheme::text_primary())
            .child(self.0.clone())
    }
}

fn op_color(op: &str) -> Hsla {
    if CONTROL_OPS.contains(&op) {
        BonTheme::warning()
    } else if DATA_OPS.contains(&op) {
        BonTheme::success()
    } else {
        BonTheme::accent()
    }
}

fn op_hint(op: &str) -> &'static str {
    match op {
        "open" => "<url>",
        "click" | "dblclick" | "hover" | "focus" | "check" | "uncheck" | "scrollintoview" => "<selector>",
        "fill" | "type" | "select" | "upload" => "<selector> <value>",
        "press" => "<key>, e.g. Enter",
        "wait" => "<ms> or <selector>",
        "get" => "text|value|url|title|count <selector>",
        "eval" => "<javascript>",
        "http" => "<url> [-X POST] [-H 'K: V'] [-d '<body>']",
        "read_file" => "<path>  (relative to files/)",
        "write_file" => "<path> <content> [--append]",
        "regex" => "<input> <pattern>  (group 1, else whole match)",
        "json" => "<input> <data.path>",
        "cmd" => "'<shell command>' [--timeout <s>]  ({{var}} is auto-quoted)",
        "if" => "<a> ==|!=|contains|!contains|matches|<|>|<=|>= <b>",
        "loop" => "<count>",
        "foreach" => "<text, one item per line>",
        "else" | "end" | "break" => "no arguments",
        _ => "agent-browser arguments",
    }
}

fn new_input(window: &mut Window, cx: &mut App, value: String) -> Entity<InputState> {
    cx.new(|cx| InputState::new(window, cx).default_value(value))
}

pub fn render_flow_builder(fb: FlowBuilderState, cx: &mut Context<BonLoginApp>) -> Div {
    let depths = crate::flows::step_depths(&fb.steps);
    let structure_err = crate::flows::match_flow_blocks(&fb.steps).err().map(|e| e.to_string());
    let running_step = fb
        .run_short_id
        .as_deref()
        .and_then(|sid| crate::flows::flow_progress(&fb.flow_name, sid));
    let status = if fb.run_short_id.is_some() {
        (
            format!("Running… step #{}", running_step.unwrap_or(0)),
            BonTheme::warning(),
        )
    } else if let Some(e) = &structure_err {
        (format!("{} {e}", SfSymbol::EXCLAMATIONMARK_TRIANGLE_FILL), BonTheme::danger())
    } else if let Some((i, e)) = &fb.failed {
        (format!("Last run failed at #{i}: {e}"), BonTheme::danger())
    } else {
        (format!("{} steps", fb.steps.len()), BonTheme::text_secondary())
    };

    let palette = v_flex()
        .id("fb-palette")
        .w(px(180.))
        .h_full()
        .gap_1()
        .overflow_y_scroll()
        .child(field_label("Blocks (drag or click)"))
        .children(PALETTE.iter().enumerate().map(|(pi, &(label, line))| {
            let op = crate::flows::parse_step_tokens(&crate::flows::split_step_line(line))
                .map(|(_, s)| s.op)
                .unwrap_or_default();
            div()
                .id(SharedString::from(format!("fb-pal-{pi}")))
                .w_full()
                .flex()
                .items_center()
                .gap_2()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(BonTheme::bg_panel())
                .border_1()
                .border_color(BonTheme::border())
                .cursor_grab()
                .text_xs()
                .text_color(BonTheme::text_primary())
                .hover(|s| s.bg(BonTheme::bg_hover()))
                .child(div().size(px(7.)).rounded_full().bg(op_color(&op)))
                .child(label)
                .on_click(cx.listener(move |app, _, window, cx| {
                    app.fb_drop(FlowDrag::New(line), usize::MAX, window, cx);
                }))
                .on_drag(FlowDrag::New(line), move |_, _, _, cx| {
                    cx.new(|_| FlowDragPreview(label.into()))
                })
        }));

    let rows = fb.steps.iter().enumerate().map(|(i, st)| {
        let is_sel = fb.selected == Some(i);
        let is_failed = fb.failed.as_ref().is_some_and(|(f, _)| *f == i);
        let is_running = running_step == Some(i);
        let out = st.out.as_deref().map(|o| format!("  → {{{{{o}}}}}")).unwrap_or_default();
        let args = crate::flows::step_args_line(st);
        let preview: SharedString = format!("{} {args}", st.op).into();
        div()
            .id(SharedString::from(format!("fb-step-{i}")))
            .w_full()
            .flex()
            .items_center()
            .gap_2()
            .pl(px(8. + 20. * depths[i] as f32))
            .pr_2()
            .py_1()
            .rounded_sm()
            .border_1()
            .bg(if is_running {
                BonTheme::warning_bg()
            } else if is_failed {
                BonTheme::danger_bg()
            } else if is_sel {
                BonTheme::accent_subtle()
            } else {
                BonTheme::bg_elevated()
            })
            .border_color(if is_sel { BonTheme::border_active() } else { BonTheme::border() })
            .cursor_grab()
            .child(
                div()
                    .w(px(26.))
                    .text_size(px(11.))
                    .text_color(BonTheme::text_secondary())
                    .child(format!("#{i}")),
            )
            .child(
                div()
                    .text_size(px(11.))
                    .font_semibold()
                    .text_color(op_color(&st.op))
                    .child(st.op.clone()),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .text_size(px(11.))
                    .text_color(BonTheme::text_primary())
                    .child(format!("{args}{out}")),
            )
            .children(st.optional.then(|| {
                div()
                    .text_size(px(10.))
                    .text_color(BonTheme::text_secondary())
                    .child("optional")
            }))
            .on_click(cx.listener(move |app, _, window, cx| app.fb_select(i, window, cx)))
            .on_drag(FlowDrag::Move(i), move |_, _, _, cx| {
                let p = preview.clone();
                cx.new(|_| FlowDragPreview(p))
            })
            .drag_over::<FlowDrag>(|s, _, _, _| s.border_t_2().border_color(BonTheme::accent()))
            .on_drop(cx.listener(move |app, d: &FlowDrag, window, cx| {
                app.fb_drop(d.clone(), i, window, cx);
            }))
    });

    let append_zone = div()
        .id("fb-append")
        .w_full()
        .min_h(px(44.))
        .flex()
        .items_center()
        .justify_center()
        .rounded_sm()
        .border_1()
        .border_color(BonTheme::border())
        .text_xs()
        .text_color(BonTheme::text_secondary())
        .child(if fb.steps.is_empty() {
            "Drag blocks here (or click a block) to start the flow"
        } else {
            "Drop here to append"
        })
        .drag_over::<FlowDrag>(|s, _, _, _| s.border_color(BonTheme::accent()).bg(BonTheme::accent_subtle()))
        .on_drop(cx.listener(|app, d: &FlowDrag, window, cx| {
            app.fb_drop(d.clone(), usize::MAX, window, cx);
        }));

    let inspector = match fb.selected.and_then(|i| fb.steps.get(i).map(|s| (i, s))) {
        None => div()
            .text_xs()
            .text_color(BonTheme::text_secondary())
            .child("Click a step to edit its arguments. Dragging an if/loop/foreach moves its whole block; deleting it keeps the body.")
            .into_any_element(),
        Some((i, st)) => {
            let is_opt = st.optional;
            v_flex()
                .w_full()
                .gap_2()
                .child(
                    h_flex()
                        .w_full()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_xs()
                                .font_semibold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("Step #{i} · {}   {}", st.op, op_hint(&st.op))),
                        )
                        .child(
                            h_flex()
                                .gap_1()
                                .child(
                                    Button::new("fb-opt")
                                        .ghost()
                                        .xsmall()
                                        .label(if is_opt { "Optional" } else { "Required" })
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.fb_toggle_optional(i, cx);
                                        })),
                                )
                                .child(
                                    Button::new("fb-del")
                                        .ghost()
                                        .xsmall()
                                        .label(format!("{} Delete", SfSymbol::TRASH))
                                        .on_click(cx.listener(move |app, _, _, cx| {
                                            app.fb_delete(i, cx);
                                        })),
                                ),
                        ),
                )
                .child(
                    h_flex()
                        .w_full()
                        .gap_2()
                        .items_end()
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_1()
                                .child(field_label("Arguments"))
                                .child(Input::new(&fb.args_input)),
                        )
                        .child(
                            v_flex()
                                .w(px(170.))
                                .gap_1()
                                .child(field_label("Save output to {{var}}"))
                                .child(Input::new(&fb.out_input)),
                        )
                        .child(
                            Button::new("fb-apply")
                                .with_variant(BonTheme::outline_blue(cx))
                                .small()
                                .label("Apply")
                                .on_click(cx.listener(move |app, _, window, cx| {
                                    app.fb_apply(window, cx);
                                })),
                        ),
                )
                .into_any_element()
        }
    };

    v_flex()
        .w(px(900.))
        .h(px(640.))
        .p_5()
        .gap_3()
        .rounded_lg()
        .bg(BonTheme::bg_elevated())
        .border_1()
        .border_color(BonTheme::border())
        .child(
            h_flex()
                .w_full()
                .justify_between()
                .items_center()
                .gap_3()
                .child(
                    v_flex()
                        .min_w_0()
                        .child(
                            div()
                                .text_base()
                                .font_bold()
                                .text_color(BonTheme::text_primary())
                                .child(format!("{}  Flow Builder — {}", SfSymbol::PENCIL, fb.flow_name)),
                        )
                        .child(div().truncate().text_xs().text_color(status.1).child(status.0)),
                )
                .child(
                    h_flex()
                        .gap_1p5()
                        .child(
                            Button::new("fb-run")
                                .with_variant(BonTheme::launch_cta(cx))
                                .small()
                                .label("▶ Run")
                                .on_click(cx.listener(|app, _, _, cx| app.fb_run(cx))),
                        )
                        .child(
                            Button::new("fb-back")
                                .ghost()
                                .small()
                                .label("Flows")
                                .on_click(cx.listener(|app, _, window, cx| app.fb_back(window, cx))),
                        )
                        .child(
                            Button::new("fb-close")
                                .ghost()
                                .small()
                                .label(SfSymbol::XMARK)
                                .on_click(cx.listener(|app, _, _, cx| app.close_popup_modal(cx))),
                        ),
                ),
        )
        .child(
            h_flex()
                .w_full()
                .flex_1()
                .min_h_0()
                .gap_3()
                .child(palette)
                .child(
                    v_flex()
                        .id("fb-steps")
                        .flex_1()
                        .h_full()
                        .gap_1()
                        .overflow_y_scroll()
                        .children(rows)
                        .child(append_zone),
                ),
        )
        .child(
            div()
                .w_full()
                .p_3()
                .rounded_md()
                .bg(BonTheme::bg_panel())
                .border_1()
                .border_color(BonTheme::border())
                .child(inspector),
        )
}

impl BonLoginApp {
    pub fn open_flow_builder(&mut self, flow_raw: &str, window: &mut Window, cx: &mut Context<Self>) {
        let name = match crate::flows::sanitize_flow_name(flow_raw) {
            Ok(n) => n,
            Err(e) => {
                self.banner_message = Some(format!("Invalid flow name: {e}"));
                cx.notify();
                return;
            }
        };
        let steps = self
            .saved_flows
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.steps.clone())
            .unwrap_or_default();
        self.popup_modal = Some(ActivePopupModal::FlowBuilder(FlowBuilderState {
            flow_name: name,
            steps,
            selected: None,
            args_input: new_input(window, cx, String::new()),
            out_input: new_input(window, cx, String::new()),
            failed: None,
            run_short_id: None,
        }));
        cx.notify();
    }

    /// Applies `edit` to the open builder and saves the flow; edits invalidate the last run's failure mark.
    fn fb_edit(&mut self, cx: &mut Context<Self>, edit: impl FnOnce(&mut FlowBuilderState)) {
        let Some(ActivePopupModal::FlowBuilder(fb)) = self.popup_modal.as_mut() else {
            return;
        };
        edit(fb);
        fb.failed = None;
        let saved = crate::flows::save_flow_steps_in(&self.workspace_root, &fb.flow_name, fb.steps.clone());
        match saved {
            Ok(_) => self.saved_flows = crate::flows::list_saved_flows_in(&self.workspace_root),
            Err(e) => self.banner_message = Some(format!("Save flow failed: {e:#}")),
        }
        cx.notify();
    }

    fn fb_drop(&mut self, drag: FlowDrag, to: usize, window: &mut Window, cx: &mut Context<Self>) {
        match drag {
            FlowDrag::New(line) => {
                let step = match crate::flows::parse_step_tokens(&crate::flows::split_step_line(line)) {
                    Ok((_, s)) => s,
                    Err(e) => {
                        self.banner_message = Some(format!("Invalid block: {e:#}"));
                        cx.notify();
                        return;
                    }
                };
                let mut at = 0;
                self.fb_edit(cx, |fb| {
                    at = to.min(fb.steps.len());
                    let opens_block = matches!(step.op.as_str(), "if" | "loop" | "foreach");
                    fb.steps.insert(at, step);
                    if opens_block {
                        let (_, end) = crate::flows::parse_step_tokens(&["end".to_string()]).unwrap();
                        fb.steps.insert(at + 1, end);
                    }
                });
                self.fb_select(at, window, cx);
            }
            FlowDrag::Move(from) => self.fb_edit(cx, |fb| {
                let to = to.min(fb.steps.len());
                crate::flows::move_flow_steps(&mut fb.steps, from, to);
                fb.selected = None;
            }),
        }
    }

    fn fb_select(&mut self, idx: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::FlowBuilder(fb)) = self.popup_modal.as_mut() else {
            return;
        };
        let Some(step) = fb.steps.get(idx) else {
            return;
        };
        let (args, out) = (crate::flows::step_args_line(step), step.out.clone().unwrap_or_default());
        fb.selected = Some(idx);
        fb.args_input = new_input(window, cx, args);
        fb.out_input = new_input(window, cx, out);
        cx.notify();
    }

    fn fb_apply(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::FlowBuilder(fb)) = &self.popup_modal else {
            return;
        };
        let Some((idx, old)) = fb.selected.and_then(|i| fb.steps.get(i).cloned().map(|s| (i, s))) else {
            return;
        };
        let out = fb.out_input.read(cx).value().trim().to_string();
        let mut tokens = Vec::new();
        if !out.is_empty() {
            tokens.extend(["--out".to_string(), out]);
        }
        tokens.push(old.op.clone());
        tokens.extend(crate::flows::split_step_line(&fb.args_input.read(cx).value()));
        let mut step = match crate::flows::parse_step_tokens(&tokens) {
            Ok((_, s)) => s,
            Err(e) => {
                self.banner_message = Some(format!("Step #{idx}: {e:#}"));
                cx.notify();
                return;
            }
        };
        step.optional = old.optional;
        // Same primary selector: keep the recorded fallback locators for self-healing.
        if step.locators.first() == old.locators.first() {
            step.locators = old.locators;
        }
        self.fb_edit(cx, |fb| fb.steps[idx] = step);
        self.fb_select(idx, window, cx);
    }

    fn fb_toggle_optional(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.fb_edit(cx, |fb| {
            if let Some(s) = fb.steps.get_mut(idx) {
                s.optional = !s.optional;
            }
        });
    }

    fn fb_delete(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.fb_edit(cx, |fb| {
            crate::flows::remove_flow_step(&mut fb.steps, idx);
            fb.selected = None;
        });
    }

    fn fb_back(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = match &self.popup_modal {
            Some(ActivePopupModal::FlowBuilder(fb)) => fb.flow_name.clone(),
            _ => return,
        };
        self.open_agent_flows_modal(None, window, cx);
        if let Some(ActivePopupModal::AgentFlows(m)) = self.popup_modal.as_mut() {
            m.expanded_flow_name = Some(name);
        }
    }

    fn fb_run(&mut self, cx: &mut Context<Self>) {
        let Some(ActivePopupModal::FlowBuilder(fb)) = &self.popup_modal else {
            return;
        };
        let name = fb.flow_name.clone();
        let Some(short_id) = self.run_saved_flow_ui(&name, cx) else {
            return;
        };
        if let Some(ActivePopupModal::FlowBuilder(fb)) = self.popup_modal.as_mut() {
            fb.failed = None;
            fb.run_short_id = Some(short_id);
        }
        // Repaint for the live step highlight until the run reports back.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_millis(250))
                    .await;
                let watching = this.update(cx, |app, cx| {
                    let live = matches!(
                        &app.popup_modal,
                        Some(ActivePopupModal::FlowBuilder(fb)) if fb.run_short_id.is_some()
                    );
                    cx.notify();
                    live
                });
                if !matches!(watching, Ok(true)) {
                    break;
                }
            }
        })
        .detach();
    }

    /// Called when a flow run finishes, to clear the live highlight and mark a failed step.
    pub(crate) fn fb_run_finished(&mut self, flow_name: &str, err: Option<&anyhow::Error>) {
        if let Some(ActivePopupModal::FlowBuilder(fb)) = self.popup_modal.as_mut()
            && fb.flow_name == flow_name
        {
            fb.run_short_id = None;
            fb.failed = err
                .and_then(|e| e.downcast_ref::<crate::flows::FlowStepFailed>())
                .map(|f| (f.step, f.error.clone()));
        }
    }
}
