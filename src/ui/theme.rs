use gpui_kit::component::{button::{ButtonCustomVariant, ButtonVariant}, *};
use gpui_kit::*;
use std::time::Duration;

/// macOS Sequoia / Sonoma Dark Mode Material & System Color Palette.
pub struct BonTheme;

impl BonTheme {
    /// macOS `systemBackground` Dark Mode (`#1C1C1E`)
    pub fn bg_canvas() -> Hsla {
        rgb(0x1c1c1e).into()
    }

    /// macOS Translucent Vibrancy Sidebar (`rgba(22, 22, 25, 0.84)`)
    pub fn bg_sidebar() -> Hsla {
        rgba(0x161619d6).into()
    }

    /// macOS `secondarySystemGroupedBackground` (`#242427`)
    pub fn bg_panel() -> Hsla {
        rgb(0x242427).into()
    }

    /// macOS `tertiarySystemBackground` / Elevated Control Surface (`#2C2C30`)
    pub fn bg_elevated() -> Hsla {
        rgb(0x2c2c30).into()
    }

    /// macOS Highlighted / Selected Row Surface (`rgba(10, 132, 255, 0.28)`)
    pub fn bg_selected() -> Hsla {
        rgba(0x0a84ff47).into()
    }

    /// macOS Subtle Row / Control Hover Surface (`rgba(255, 255, 255, 0.05)`)
    pub fn bg_hover() -> Hsla {
        rgba(0xffffff0d).into()
    }

    /// Critically-damped Apple spring (`damping = 1.0`, `response ≈ 0.3s`)
    pub const fn snappy_spring() -> SpringConfig {
        SpringConfig::new(420.0, 38.0, 1.0)
    }

    /// Crisp 140ms `ease_out_quint` entrance token for views, drawers, and modals
    pub fn ui_enter_anim() -> Animation {
        Animation::new(Duration::from_millis(140)).with_easing(ease_out_quint())
    }

    /// Phase-locked 30fps breathing pulse (`1200ms`, alpha `0.45..1.0`) for Starting/Checking badges
    pub fn status_pulse_anim() -> Animation {
        Animation::new(Duration::from_millis(1200))
            .repeat_synced()
            .with_max_fps(30.0)
            .with_easing(pulsating_between(0.45, 1.0))
    }

    /// macOS Recessed Segmented Control Track / Code Well (`#151517`)
    pub fn bg_well() -> Hsla {
        rgb(0x151517).into()
    }

    /// macOS Specular Hairline Divider (`rgba(255, 255, 255, 0.09)`)
    pub fn border() -> Hsla {
        rgba(0xffffff17).into()
    }

    /// macOS Control / Checkbox Bezel Border (`rgba(255, 255, 255, 0.22)`)
    pub fn border_control() -> Hsla {
        rgba(0xffffff38).into()
    }

    /// macOS Active Focus / Specular Highlight Border (`rgba(10, 132, 255, 0.65)`)
    pub fn border_active() -> Hsla {
        rgba(0x0a84ffa6).into()
    }

    /// macOS Primary Label (`#F5F5F7`)
    pub fn text_primary() -> Hsla {
        rgb(0xf5f5f7).into()
    }

    /// macOS Secondary Label (`#AEAEB2` — `systemGray2` Dark Mode)
    pub fn text_secondary() -> Hsla {
        rgb(0xaeaeb2).into()
    }

    /// macOS Tertiary / Section Caption Label (`#8E8E93` — `systemGray` Dark Mode, WCAG AA)
    pub fn text_muted() -> Hsla {
        rgb(0x8e8e93).into()
    }

    /// macOS Monospace Font Family for tabular IDs, IPs, ports, seeds, and TOTP codes
    pub const fn font_mono() -> &'static str {
        "SF Mono"
    }

    /// Apple System Blue (`#0A84FF`)
    pub fn accent() -> Hsla {
        rgb(0x0a84ff).into()
    }

    pub fn accent_subtle() -> Hsla {
        rgba(0x0a84ff24).into()
    }

    /// Apple System Green (`#30D158`)
    pub fn success() -> Hsla {
        rgb(0x30d158).into()
    }

    pub fn success_bg() -> Hsla {
        rgba(0x30d15822).into()
    }

    /// Apple System Cyan (`#64D2FF`)
    pub fn info() -> Hsla {
        rgb(0x64d2ff).into()
    }

    pub fn info_bg() -> Hsla {
        rgba(0x64d2ff22).into()
    }

    /// Apple System Orange (`#FF9F0A`)
    pub fn warning() -> Hsla {
        rgb(0xff9f0a).into()
    }

    pub fn warning_bg() -> Hsla {
        rgba(0xff9f0a22).into()
    }

    /// Apple System Red (`#FF453A`)
    pub fn danger() -> Hsla {
        rgb(0xff453a).into()
    }

    pub fn danger_bg() -> Hsla {
        rgba(0xff453a22).into()
    }

    /// macOS Prominent Push Button (`#0A84FF`)
    pub fn primary_cta(cx: &App) -> ButtonVariant {
        ButtonVariant::Custom(
            ButtonCustomVariant::new(cx)
                .color(rgb(0x0a84ff).into())
                .hover(rgb(0x2997ff).into())
                .active(rgb(0x0071e3).into())
                .foreground(rgb(0xffffff).into()),
        )
    }

    /// macOS System Green Button (`#30D158`)
    pub fn success_cta(cx: &App) -> ButtonVariant {
        ButtonVariant::Custom(
            ButtonCustomVariant::new(cx)
                .color(rgb(0x28cd41).into())
                .hover(rgb(0x30d158).into())
                .active(rgb(0x1eae36).into())
                .foreground(rgb(0xffffff).into()),
        )
    }

    /// Launch button on table rows
    pub fn launch_cta(cx: &App) -> ButtonVariant {
        Self::primary_cta(cx)
    }

    /// macOS Tinted Blue Action Button
    pub fn outline_blue(cx: &App) -> ButtonVariant {
        ButtonVariant::Custom(
            ButtonCustomVariant::new(cx)
                .color(rgba(0x0a84ff1f).into())
                .hover(rgba(0x0a84ff33).into())
                .active(rgba(0x0a84ff45).into())
                .foreground(rgb(0x409cff).into()),
        )
    }

    /// macOS Tinted Red Action Button
    pub fn outline_danger(cx: &App) -> ButtonVariant {
        ButtonVariant::Custom(
            ButtonCustomVariant::new(cx)
                .color(rgba(0xff453a1f).into())
                .hover(rgba(0xff453a33).into())
                .active(rgba(0xff453a45).into())
                .foreground(rgb(0xff6961).into()),
        )
    }

    /// macOS Standard Bezel Push Button (`#323236`)
    pub fn row_action(cx: &App) -> ButtonVariant {
        ButtonVariant::Custom(
            ButtonCustomVariant::new(cx)
                .color(rgb(0x323236).into())
                .hover(rgb(0x3d3d42).into())
                .active(rgb(0x28282b).into())
                .foreground(rgb(0xf5f5f7).into()),
        )
    }

    /// macOS Segmented / Pill Toggle Button
    pub fn toggle_pill(cx: &App, active: bool) -> ButtonVariant {
        if active {
            ButtonVariant::Custom(
                ButtonCustomVariant::new(cx)
                    .color(rgb(0x0a84ff).into())
                    .hover(rgb(0x2997ff).into())
                    .active(rgb(0x0071e3).into())
                    .foreground(rgb(0xffffff).into()),
            )
        } else {
            ButtonVariant::Custom(
                ButtonCustomVariant::new(cx)
                    .color(rgb(0x2c2c30).into())
                    .hover(rgb(0x38383d).into())
                    .active(rgb(0x242428).into())
                    .foreground(rgb(0x98989d).into()),
            )
        }
    }

    /// Shared 18×18 spring-animated checkbox used in Profiles and Proxy Manager tables.
    pub fn checkbox(
        id: impl Into<SharedString>,
        checked: bool,
        mark: &'static str,
        resting_bg: Hsla,
        on_toggle: impl Fn(&MouseDownEvent, &mut Window, &mut App) + 'static,
    ) -> impl IntoElement {
        div()
            .w(px(18.))
            .h(px(18.))
            .flex_shrink_0()
            .rounded(px(4.5))
            .cursor_pointer()
            .flex()
            .items_center()
            .justify_center()
            .bg(if checked { Self::accent() } else { resting_bg })
            .border_1()
            .border_color(if checked {
                Self::accent()
            } else {
                Self::border_control()
            })
            .text_xs()
            .font_bold()
            .text_color(rgb(0xffffff))
            .on_mouse_down(MouseButton::Left, on_toggle)
            .child(mark)
            .with_spring(
                id.into(),
                SpringAnimation::new(Self::snappy_spring()).to(checked),
                move |this, phase| {
                    this.bg(phase.interpolate_clamped(resting_bg, Self::accent()))
                        .border_color(
                            phase.interpolate_clamped(Self::border_control(), Self::accent()),
                        )
                        .hover(|s| s.border_color(Self::accent()))
                },
            )
    }
}

/// Apple SF Symbols (`SF Pro` Private Use Area glyphs on macOS).
pub struct SfSymbol;

impl SfSymbol {
    pub const PLUS: &'static str = "\u{10017c}";
    pub const MINUS: &'static str = "\u{10017d}";
    pub const CHECKMARK: &'static str = "\u{100185}";
    pub const XMARK: &'static str = "\u{100184}";
    pub const GLOBE: &'static str = "\u{1001aa}";
    pub const PUZZLEPIECE_EXTENSION_FILL: &'static str = "\u{10096e}";
    pub const BOLT_FILL: &'static str = "\u{1002e6}";
    pub const FOLDER_FILL: &'static str = "\u{100216}";
    pub const TRASH: &'static str = "\u{100211}";
    pub const PENCIL: &'static str = "\u{10020a}";
    pub const SLIDER_HORIZONTAL_3: &'static str = "\u{100306}";
    pub const GEARSHAPE_FILL: &'static str = "\u{1008cc}";
    pub const ARROW_CLOCKWISE: &'static str = "\u{100148}";
    pub const ARROW_TRIANGLE_2_CIRCLEPATH: &'static str = "\u{1002af}";
    pub const ARROW_UP: &'static str = "\u{100127}";
    pub const ARROW_DOWN: &'static str = "\u{100128}";
    pub const ARROW_UP_DOC: &'static str = "\u{10023b}";
    pub const ARROW_DOWN_DOC: &'static str = "\u{10023d}";
    pub const PLAY_FILL: &'static str = "\u{100284}";
    pub const STOP_FILL: &'static str = "\u{1006f7}";
    pub const ELLIPSIS: &'static str = "\u{100360}";
    pub const DOC_ON_DOC: &'static str = "\u{100241}";
    pub const PLUS_SQUARE_ON_SQUARE: &'static str = "\u{100add}";
    pub const CHEVRON_RIGHT: &'static str = "\u{10018a}";
    pub const ICLOUD_AND_ARROW_UP: &'static str = "\u{100315}";
    pub const LINK: &'static str = "\u{100263}";
    pub const TERMINAL: &'static str = "\u{100a7c}";
    pub const CHECKMARK_SHIELD: &'static str = "\u{10079b}";
    pub const CHECKMARK_CIRCLE_FILL: &'static str = "\u{100063}";
    pub const XMARK_CIRCLE_FILL: &'static str = "\u{100001}";
    pub const INFO_CIRCLE_FILL: &'static str = "\u{100175}";
    pub const EXCLAMATIONMARK_TRIANGLE_FILL: &'static str = "\u{1001ff}";
    pub const APPLE_LOGO: &'static str = "\u{1008fa}";
    pub const PC: &'static str = "\u{10097a}";
    pub const CALENDAR: &'static str = "\u{100249}";
    pub const CLOCK_ARROW_CIRCLEPATH: &'static str = "\u{1008d4}";
    pub const TAG_FILL: &'static str = "\u{1002e2}";
    pub const SIDEBAR_RIGHT: &'static str = "\u{1003db}";
    pub const LOCK_FILL: &'static str = "\u{1003a0}";
    pub const BOOKMARK_FILL: &'static str = "\u{10025f}";
}

#[cfg(test)]
mod tests {
    use super::{BonTheme, Duration};

    #[test]
    fn test_motion_tokens_invariants() {
        let spring = BonTheme::snappy_spring();
        let (omega, zeta) = spring.canonical();
        assert!(omega > 15.0 && omega < 30.0);
        assert!(zeta > 0.9 && zeta <= 1.0, "snappy_spring must be near-critically damped");

        let enter = BonTheme::ui_enter_anim();
        assert_eq!(enter.duration, Duration::from_millis(140));
        assert!(enter.oneshot);
        assert!(((enter.easing)(0.0) - 0.0).abs() < 1e-5);
        assert!(((enter.easing)(1.0) - 1.0).abs() < 1e-5);
        assert!((enter.easing)(0.25) > 0.70, "ease_out_quint starts fast");

        let pulse = BonTheme::status_pulse_anim();
        assert_eq!(pulse.duration, Duration::from_millis(1200));
        assert!(!pulse.oneshot);
        assert!(pulse.synced, "status_pulse_anim must be phase-locked via repeat_synced()");
        assert_eq!(pulse.max_fps, Some(30.0));
        let alpha_mid = (pulse.easing)(0.25);
        assert!((0.45..=1.0).contains(&alpha_mid));
    }
}
