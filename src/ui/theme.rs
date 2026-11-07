use gpui_kit::component::button::{ButtonCustomVariant, ButtonVariant};
use gpui_kit::{App, Hsla, SpringConfig, rgb, rgba};

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

    /// macOS Recessed Segmented Control Track / Code Well (`#151517`)
    pub fn bg_well() -> Hsla {
        rgb(0x151517).into()
    }

    /// macOS Specular Hairline Divider (`rgba(255, 255, 255, 0.08)`)
    pub fn border() -> Hsla {
        rgba(0xffffff14).into()
    }

    /// macOS Active Focus / Specular Highlight Border (`rgba(10, 132, 255, 0.65)`)
    pub fn border_active() -> Hsla {
        rgba(0x0a84ffa6).into()
    }

    /// macOS Primary Label (`#F5F5F7`)
    pub fn text_primary() -> Hsla {
        rgb(0xf5f5f7).into()
    }

    /// macOS Secondary Label (`#98989D`)
    pub fn text_secondary() -> Hsla {
        rgb(0x98989d).into()
    }

    /// macOS Tertiary / Section Caption Label (`#636366`)
    pub fn text_muted() -> Hsla {
        rgb(0x636366).into()
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
}

/// Apple SF Symbols (`SF Pro` Private Use Area glyphs on macOS).
pub struct SfSymbol;

impl SfSymbol {
    pub const PLUS: &'static str = "\u{10017c}";
    pub const MINUS: &'static str = "\u{10017d}";
    pub const CHECKMARK: &'static str = "\u{100185}";
    pub const XMARK: &'static str = "\u{100184}";
    pub const SQUARE_GRID_2X2: &'static str = "\u{1001f7}";
    pub const SQUARE_GRID_2X2_FILL: &'static str = "\u{100688}";
    pub const NETWORK: &'static str = "\u{100906}";
    pub const GLOBE: &'static str = "\u{1001aa}";
    pub const PUZZLEPIECE_EXTENSION: &'static str = "\u{10096d}";
    pub const PUZZLEPIECE_EXTENSION_FILL: &'static str = "\u{10096e}";
    pub const BOLT_FILL: &'static str = "\u{1002e6}";
    pub const FOLDER: &'static str = "\u{100215}";
    pub const FOLDER_FILL: &'static str = "\u{100216}";
    pub const TRASH: &'static str = "\u{100211}";
    pub const PENCIL: &'static str = "\u{10020a}";
    pub const SLIDER_HORIZONTAL_3: &'static str = "\u{100306}";
    pub const GEARSHAPE: &'static str = "\u{1008cb}";
    pub const GEARSHAPE_FILL: &'static str = "\u{1008cc}";
    pub const ARROW_CLOCKWISE: &'static str = "\u{100148}";
    pub const ARROW_TRIANGLE_2_CIRCLEPATH: &'static str = "\u{1002af}";
    pub const ARROW_DOWN: &'static str = "\u{100128}";
    pub const ARROW_UP_DOC: &'static str = "\u{10023b}";
    pub const ARROW_DOWN_DOC: &'static str = "\u{10023d}";
    pub const PLAY_FILL: &'static str = "\u{100284}";
    pub const STOP_FILL: &'static str = "\u{1006f7}";
    pub const ELLIPSIS: &'static str = "\u{100360}";
    pub const DOC_ON_DOC: &'static str = "\u{100241}";
    pub const PLUS_SQUARE_ON_SQUARE: &'static str = "\u{100add}";
    pub const MAGNIFYINGGLASS: &'static str = "\u{1002ab}";
    pub const CHEVRON_DOWN: &'static str = "\u{100187}";
    pub const CHEVRON_LEFT: &'static str = "\u{100189}";
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
    pub const DESKTOPCOMPUTER: &'static str = "\u{100657}";
    pub const PC: &'static str = "\u{10097a}";
    pub const CALENDAR: &'static str = "\u{100249}";
    pub const CLOCK_ARROW_CIRCLEPATH: &'static str = "\u{1008d4}";
    pub const TAG_FILL: &'static str = "\u{1002e2}";
    pub const SIDEBAR_RIGHT: &'static str = "\u{1003db}";
    pub const KEY_FILL: &'static str = "\u{1007d6}";
}
