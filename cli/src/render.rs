//! Shared presentation helpers: the render style, the plain-text labels both
//! renderers use, and the risk colour palette.
//!
//! The renderers in [`crate::report`] and [`crate::explain`] are pure functions
//! that take a [`RenderStyle`] and return a `String`. They never read the
//! environment or the terminal themselves -- that decision is made once, in
//! `main` (the composition root), and passed in. That is what keeps them
//! testable without capturing stdout.

use std::io::IsTerminal;

use hightower_core::process::{ProcessCategory, RiskLevel};

/// How output should be styled, decided once in `main`.
#[derive(Debug, Clone, Copy)]
pub struct RenderStyle {
    /// Emit ANSI colour and box-drawn borders when true; fall back to plain
    /// ASCII when false. Colour and the rich table travel together: both are on
    /// only for an interactive terminal.
    pub color: bool,
    /// The terminal width to fit into, or `None` when output is not a terminal.
    /// Only used by the rich path, to truncate the PATH column.
    pub max_width: Option<usize>,
}

impl RenderStyle {
    /// Plain, unlimited-width style. Only the tests construct it directly; the
    /// binary always goes through [`RenderStyle::detect`].
    #[cfg(test)]
    pub fn plain() -> Self {
        Self {
            color: false,
            max_width: None,
        }
    }

    /// Decides the style for the real process stdout.
    ///
    /// Colour is on only when stdout is a terminal, `NO_COLOR` is unset
    /// (<https://no-color.org>), and `--no-color` was not passed. Piping or
    /// redirecting therefore degrades to plain ASCII -- colour in a pipe is a bug.
    pub fn detect(no_color_flag: bool) -> Self {
        let is_terminal = std::io::stdout().is_terminal();
        let color = is_terminal && !no_color_flag && std::env::var_os("NO_COLOR").is_none();
        let max_width = if is_terminal {
            terminal_size::terminal_size().map(|(width, _height)| width.0 as usize)
        } else {
            None
        };
        Self { color, max_width }
    }
}

/// The plain-text label for a risk level, shown in both the table and `explain`.
pub fn risk_label(risk: RiskLevel) -> &'static str {
    match risk {
        RiskLevel::Trusted => "trusted",
        RiskLevel::Review => "review",
        RiskLevel::Suspicious => "suspicious",
    }
}

/// The plain-text label for a process category.
pub fn category_label(category: ProcessCategory) -> &'static str {
    match category {
        ProcessCategory::CoreWindows => "core-windows",
        ProcessCategory::Driver => "driver",
        ProcessCategory::ThirdPartyKnown => "third-party-known",
        ProcessCategory::Unknown => "unknown",
    }
}

/// The colour for a risk level: green (trusted), yellow (review), bold red
/// (suspicious). Used by the plain-text `explain` output via [`paint`].
pub fn risk_style(risk: RiskLevel) -> anstyle::Style {
    use anstyle::AnsiColor;
    let base = anstyle::Style::new();
    match risk {
        RiskLevel::Trusted => base.fg_color(Some(AnsiColor::Green.into())),
        RiskLevel::Review => base.fg_color(Some(AnsiColor::Yellow.into())),
        RiskLevel::Suspicious => base
            .fg_color(Some(AnsiColor::Red.into()))
            .effects(anstyle::Effects::BOLD),
    }
}

/// Wraps `text` in `style` when `enabled`, otherwise returns it unchanged. The
/// `enabled` flag comes from [`RenderStyle::color`], so a non-terminal never
/// gets escape sequences.
pub fn paint(text: &str, style: anstyle::Style, enabled: bool) -> String {
    if enabled {
        format!("{}{}{}", style.render(), text, style.render_reset())
    } else {
        text.to_string()
    }
}

/// Truncates `text` to at most `max` columns, keeping the start and the end with
/// an ellipsis between them -- so a truncated path keeps both its drive and its
/// file name, the two most identifying parts.
///
/// ponytail: counts `char`s, not display width. Fine for file-system paths
/// (effectively ASCII); switch to `unicode-width` if wide glyphs ever appear.
pub fn truncate_middle(text: &str, max: usize) -> String {
    let length = text.chars().count();
    if length <= max {
        return text.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let keep = max - 1; // leave one column for the ellipsis
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let head_text: String = text.chars().take(head).collect();
    let tail_text: String = text.chars().skip(length - tail).collect();
    format!("{head_text}…{tail_text}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_not_truncated() {
        assert_eq!(truncate_middle("C:\\a.exe", 40), "C:\\a.exe");
    }

    #[test]
    fn long_text_keeps_head_and_tail() {
        let path = r"C:\Program Files\Vendor\App\bin\service.exe";
        let out = truncate_middle(path, 20);
        assert_eq!(out.chars().count(), 20);
        assert!(out.contains('…'));
        assert!(out.starts_with("C:\\"));
        assert!(out.ends_with(".exe"));
    }

    #[test]
    fn paint_is_a_no_op_when_disabled() {
        let painted = paint("trusted", risk_style(RiskLevel::Trusted), false);
        assert_eq!(painted, "trusted");
        assert!(!painted.contains('\x1b'));
    }

    #[test]
    fn paint_adds_escapes_when_enabled() {
        let painted = paint("suspicious", risk_style(RiskLevel::Suspicious), true);
        assert!(painted.contains('\x1b'));
        assert!(painted.contains("suspicious"));
    }
}
