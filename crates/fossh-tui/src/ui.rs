use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::{App, Screen};
use crate::wizard::Step;

const FOSSH_GREEN: Color = Color::Green;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_tabs(frame, chunks[0], app.screen);

    match app.screen {
        Screen::Dashboard => draw_dashboard(frame, chunks[1]),
        Screen::Telemetry => draw_telemetry(frame, chunks[1], app),
        Screen::Wizard => draw_wizard(frame, chunks[1], app),
    }

    draw_status_line(frame, chunks[2]);
}

fn draw_tabs(frame: &mut Frame, area: Rect, current: Screen) {
    let make = |label: &str, screen: Screen| {
        let style = if screen == current {
            Style::default()
                .fg(FOSSH_GREEN)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default()
        };
        Span::styled(format!(" {label} "), style)
    };
    let line = Line::from(vec![
        make("1 Dashboard", Screen::Dashboard),
        Span::raw("  "),
        make("2 Telemetry", Screen::Telemetry),
        Span::raw("  "),
        make("3 Setup Wizard", Screen::Wizard),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" foSSH — local admin console ");
    frame.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_status_line(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(" q quit  ·  1/2/3 switch screen  ·  r refresh (Telemetry)")
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_dashboard(frame: &mut Frame, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "Watchdog",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(
            "  not running — chapter §3.3 (OCaml watchdog) is not yet built on this install.",
        ),
        Line::from("  See DURUM.md for what's implemented vs. pending in this chapter."),
        Line::from(""),
        Line::from(Span::styled(
            "Tamper detection",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  not available — depends on the watchdog above (chapter §3.6)."),
        Line::from(""),
        Line::from(Span::styled(
            "Active auth-gate sessions",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(
            "  none — the challenge-response auth gate (§2.1) also depends on the watchdog.",
        ),
        Line::from(""),
        Line::from(
            "Press 2 for a real telemetry summary from this install's database, or 3 to run the first-run setup wizard.",
        ),
    ];
    let block = Block::default().borders(Borders::ALL).title(" Status ");
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        area,
    );
}

fn draw_telemetry(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    match &app.sites {
        Err(e) => {
            lines.push(Line::from(Span::styled(
                format!("Could not read the database: {e}"),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(format!(
                "  (data dir: {})",
                app.data_dir.display()
            )));
        }
        Ok(sites) if sites.is_empty() => {
            lines.push(Line::from(
                "No sites yet — `fossh site create <slug>` to add one.",
            ));
        }
        Ok(sites) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "{:<24} {:<10} {:>12} {:>12}",
                    "SITE", "STATUS", "HITS TODAY", "UNIQUES"
                ),
                Style::default().add_modifier(Modifier::BOLD),
            )));
            for s in sites {
                let status = match (s.disabled, s.public) {
                    (true, _) => "disabled",
                    (false, true) => "public",
                    (false, false) => "private",
                };
                lines.push(Line::from(format!(
                    "{:<24} {:<10} {:>12} {:>12}",
                    s.slug, status, s.hits_today, s.uniques_today
                )));
            }
        }
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Telemetry summary (today, k-anonymized) ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_wizard(frame: &mut Frame, area: Rect, app: &App) {
    let w = &app.wizard;
    let mut lines = vec![
        Line::from(format!("Setup token path: {}", w.token_path.display())),
        Line::from(""),
    ];

    match &w.step {
        Step::NoTokenFound => {
            lines.push(Line::from("No setup token found."));
            lines.push(Line::from(""));
            lines.push(Line::from(
                "Press 'g' to generate one now (standalone/demo mode — in a real install the watchdog does this on first start; see chapter §3.3 in DURUM.md).",
            ));
        }
        Step::TokenJustGenerated { plaintext } => {
            lines.push(Line::from(Span::styled(
                "Token generated. This is shown exactly once:",
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                plaintext.clone(),
                Style::default()
                    .fg(FOSSH_GREEN)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(
                "Write it down. Press Enter to continue to verification.",
            ));
        }
        Step::AwaitingInput => {
            lines.push(Line::from("Enter the setup token to complete enrollment:"));
            lines.push(Line::from(""));
            lines.push(Line::from(format!("> {}", w.input)));
        }
        Step::Verified => {
            lines.push(Line::from(Span::styled(
                "Setup complete. The token file has been deleted and its hash invalidated — it cannot be reused.",
                Style::default().fg(FOSSH_GREEN),
            )));
        }
        Step::Failed(msg) => {
            lines.push(Line::from(Span::styled(
                format!("Failed: {msg}"),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from("Press Enter to try again."));
        }
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup Wizard ");
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}
