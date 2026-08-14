//! Shared visual language for the whole TUI: a deep graphite background
//! with warm amber/sage/terracotta accents, rounded borders, and
//! consistent padding so panels don't feel cramped. Release 1 is dark
//! mode only (light mode is release-2 scope) — so, unlike an earlier
//! version of this module, the background is now forced explicitly
//! rather than left to the terminal's own default. Accent colors carry
//! meaning (amber = pending/in-progress, sage = healthy/public/verified,
//! terracotta = reserved for actual errors, muted = secondary/help text)
//! rather than being decorative alone.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType, Borders, Padding};

pub const GRAPHITE: Color = Color::Rgb(28, 28, 30);
pub const FOREGROUND: Color = Color::Rgb(216, 210, 200);
pub const AMBER: Color = Color::Rgb(224, 175, 104);
pub const SAGE: Color = Color::Rgb(135, 169, 107);
pub const TERRACOTTA: Color = Color::Rgb(214, 118, 89);
pub const MUTED: Color = Color::Rgb(145, 135, 122);

pub fn base_style() -> Style {
    Style::default().fg(FOREGROUND).bg(GRAPHITE)
}

/// Paints the whole frame graphite before anything else draws this
/// pass. Every widget rendered afterward only patches the style fields
/// it actually sets (ratatui's `Style::patch` leaves unset fields
/// alone), so an otherwise-unstyled `Span` still lands on graphite with
/// a readable foreground instead of whatever the terminal's own
/// default happens to be.
pub fn fill_background(frame: &mut Frame, area: Rect) {
    frame.render_widget(Block::default().style(base_style()), area);
}

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
