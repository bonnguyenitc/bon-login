# 003 — Make toast banner interruptible and add physical entrance to popup modals

- **Status**: DONE
- **Commit**: 386e879
- **Severity**: MEDIUM
- **Category**: 3. Physicality & origin & 4. Interruptibility
- **Estimated scope**: 2 files (`src/ui/render_layout.rs`, `src/ui/popup_modals.rs`)

## Problem

1. **Toast banner restarts from zero on consecutive updates (`src/ui/render_layout.rs:1056-1058, 1112-1119`)**:
   `banner_id` is constructed as `SharedString::from(format!("toast-banner-{msg}"))`. When an in-progress toast (`"Checking proxy..."`) updates to its result (`"Proxy verified..."`) or a user triggers two actions in quick succession, the `ElementId` changes, resetting `AnimationState` to `delta = 0.0` (`opacity: 0.0`, `bottom: 12px`) and making the toast jump and blink:

```rust
// src/ui/render_layout.rs:1056, 1112-1119 — current
let banner_id = SharedString::from(format!("toast-banner-{msg}"));
h_flex()
    .id(banner_id.clone())
    // ...
    .with_animation(
        banner_id,
        Animation::new(Duration::from_millis(160))
            .with_easing(ease_out_quint()),
        |this, delta| {
            this.opacity(delta).bottom(px(12.0 + delta * 8.0))
        },
    )
```

2. **Popup modals enter with compounded $\text{delta}^2$ pure fade and no spatial lift (`src/ui/popup_modals.rs:2675-2708`)**:
   Both the full-window backdrop (`popup-backdrop-{anim_key}`) and its child `card` (`popup-modal-{anim_key}`) apply `BonTheme::ui_enter_anim()` (`|this, delta| this.opacity(delta)`). Because `card` is a child of the backdrop, their opacities multiply ($\text{delta}^2$), creating a sluggish initial ramp with zero physical separation between card and backdrop:

```rust
// src/ui/popup_modals.rs:2697-2707 — current
        .child(
            card.on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .with_animation(
                modal_anim_id,
                BonTheme::ui_enter_anim(),
                |this, delta| this.opacity(delta),
            ),
        )
        .with_animation(
            backdrop_anim_id,
            BonTheme::ui_enter_anim(),
            |this, delta| this.opacity(delta),
        )
```

## Target

1. Give the toast banner a stable `ElementId` (`"toast-banner-container"`) driven by `SpringAnimation::new(BonTheme::snappy_spring()).from(0.0f32).to(1.0f32)` (or `BonTheme::ui_enter_anim()` on the stable `"toast-banner-container"` ID) so that once the toast is mounted on screen, consecutive message updates swap the label/icon in-place without restarting the entrance from `bottom(px(12.))` and `opacity(0.0)`.
2. In `src/ui/popup_modals.rs:2675-2708`, animate the backdrop background alpha (`rgba(0x00000000)` $\rightarrow$ `rgba(0x00000080)`) via `phase.interpolate_clamped` instead of parent `.opacity(delta)` (eliminating the $\text{delta}^2$ compounded opacity on the child card), and give the modal `card` a physical `px(10.0)` upward lift (`mt(px((1.0 - delta) * 10.0)).opacity(delta)`) using `BonTheme::ui_enter_anim()`.

```rust
// src/ui/popup_modals.rs — target
    div()
        .absolute()
        .top_0()
        .left_0()
        .size_full()
        .flex()
        .items_center()
        .justify_center()
        .on_mouse_down(
            MouseButton::Left,
            cx.listener(|app, _, _, cx| {
                app.close_popup_modal(cx);
            }),
        )
        .child(
            card.on_mouse_down(MouseButton::Left, |_, _, cx| {
                cx.stop_propagation();
            })
            .with_animation(
                modal_anim_id,
                BonTheme::ui_enter_anim(),
                |this, delta| this.opacity(delta).mt(px((1.0 - delta) * 10.0)),
            ),
        )
        .with_animation(
            backdrop_anim_id,
            BonTheme::ui_enter_anim(),
            |this, delta| {
                this.bg(AnimationPhase(delta).interpolate_clamped(
                    Hsla::from(rgba(0x00000000)),
                    Hsla::from(rgba(0x00000080)),
                ))
            },
        )
        .into_any_element()
```

## Repo conventions to follow

- Use `BonTheme::ui_enter_anim()` (`140ms`, `ease_out_quint()`) and `SpringTarget::interpolate_clamped` (`src/ui/theme.rs:45-47, 244`).

## Steps

1. In `src/ui/render_layout.rs:1056-1120`, change `banner_id` from `format!("toast-banner-{msg}")` to a stable `"toast-banner-container"` ID and use `BonTheme::ui_enter_anim()` so rapid message updates while the banner is visible stay anchored at `bottom(px(20.))` and `opacity(1.0)`.
2. In `src/ui/popup_modals.rs:2678-2708`, interpolate the backdrop `.bg(...)` between `Hsla::from(rgba(0x00000000))` and `Hsla::from(rgba(0x00000080))` so parent opacity no longer multiplies with the child card, and add `.mt(px((1.0 - delta) * 10.0))` to the modal card entrance.

## Boundaries

- Do NOT change toast auto-dismiss timing (`3200ms`).
- Do NOT alter modal click-outside dismissal behavior.

## Verification

- **Mechanical**: `cargo test --quiet` passes.
- **Feel check**:
  - Click a profile `ID` to copy, then immediately click another profile `ID`: the toast updates its text in place without jumping down and fading from zero.
  - Open `Quick add` (`⌘⇧N`): the card rises crisply by `10px` with full `ease_out_quint` responsiveness instead of a sluggish $\text{delta}^2$ fade.
- **Done when**: Toast updates are interruptible in place and popup modals separate backdrop alpha from card opacity + vertical lift.
