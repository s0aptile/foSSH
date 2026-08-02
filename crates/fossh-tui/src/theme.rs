//! Shared visual language for the whole TUI: warm amber/sage/terracotta
//! accents layered on top of the terminal's own default foreground and
//! background (never overridden for body text, so this stays readable on
//! both light and dark terminals), rounded borders, and consistent
//! padding so panels don't feel cramped. Accent colors carry meaning
//! (amber = pending/in-progress, sage = healthy/public/verified,
//! terracotta = reserved for actual errors, muted = secondary/help text)
//! rather than being decorative alone.

use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType, Borders, Padding};

pub const AMBER: Color = Color::Rgb(224, 175, 104);
pub const SAGE: Color = Color::Rgb(135, 169, 107);
pub const TERRACOTTA: Color = Color::Rgb(214, 118, 89);
pub const MUTED: Color = Color::Rgb(145, 135, 122);

/// A rounded, padded panel for the three main screens — `Min(0)`-sized
/// areas with room to spare, unlike the fixed-height tab/status bars.
pub fn panel(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MUTED))
        .title(format!(" {title} "))
        .title_style(Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
        .padding(Padding::uniform(1))
}

/// Same border treatment, no padding — for the fixed 3-row tab bar,
/// which has exactly one content row to spare and would clip under
/// `panel()`'s padding.
pub fn chrome(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MUTED))
        .title(format!(" {title} "))
        .title_style(Style::default().fg(AMBER).add_modifier(Modifier::BOLD))
}

pub fn accent() -> Style {
    Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
}

pub fn success() -> Style {
    Style::default().fg(SAGE)
}

pub fn pending() -> Style {
    Style::default().fg(AMBER)
}

pub fn error() -> Style {
    Style::default().fg(TERRACOTTA)
}

pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

/// The selected tab: a filled amber chip with dark text, like a pressed
/// button rather than a bare color swap — the "modern" half of "modern,
/// but with a taste of retro."
pub fn active_tab() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(AMBER)
        .add_modifier(Modifier::BOLD)
}
