use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::{App, Screen};
use crate::theme;
use crate::wizard::Step;

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

    draw_status_line(frame, chunks[2], app);
}

fn draw_tabs(frame: &mut Frame, area: Rect, current: Screen) {
    let make = |label: &str, screen: Screen| {
        let style = if screen == current {
            theme::active_tab()
        } else {
            theme::muted()
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
    frame.render_widget(
        Paragraph::new(line).block(theme::chrome("foSSH ◆ local admin console")),
        area,
    );
}

/// Always reflects what the currently-active keys actually do — while
/// `Step::AwaitingInput` has raw-input priority (see `app.rs`), the
/// global q/1/2/3/r hints below are simply false (every one of those
/// characters is captured into the token buffer instead), which an
/// earlier, unconditional version of this line got wrong.
fn draw_status_line(frame: &mut Frame, area: Rect, app: &App) {
    let awaiting_input =
        app.screen == Screen::Wizard && matches!(app.wizard.step, Step::AwaitingInput);

    let line = if awaiting_input {
        Line::from(vec![
            Span::styled("Enter", theme::accent()),
            Span::raw(" submit   "),
            Span::styled("Backspace", theme::accent()),
            Span::raw(" delete   "),
            Span::styled("Esc", theme::accent()),
            Span::raw(" cancel, back to dashboard"),
        ])
    } else {
        let mut spans = vec![
            Span::styled("q", theme::accent()),
            Span::raw(" quit   "),
            Span::styled("1", theme::accent()),
            Span::raw("/"),
            Span::styled("2", theme::accent()),
            Span::raw("/"),
            Span::styled("3", theme::accent()),
            Span::raw(" switch screen"),
        ];
        match app.screen {
            Screen::Telemetry => {
                spans.push(Span::raw("   "));
                spans.push(Span::styled("r", theme::accent()));
                spans.push(Span::raw(" refresh"));
            }
            Screen::Wizard => match app.wizard.step {
                Step::NoTokenFound => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("g", theme::accent()));
                    spans.push(Span::raw(" generate token"));
                }
                Step::TokenJustGenerated { .. } | Step::Failed(_) => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("Enter", theme::accent()));
                    spans.push(Span::raw(" continue"));
                }
                Step::AwaitingInput | Step::Verified => {}
            },
            Screen::Dashboard => {}
        }
        Line::from(spans)
    };

    frame.render_widget(Paragraph::new(line).style(theme::muted()), area);
}

fn draw_dashboard(frame: &mut Frame, area: Rect) {
    let text = vec![
        Line::from(Span::styled("Watchdog", theme::accent())),
        Line::from(Span::styled(
            "  not running — chapter §3.3 (OCaml watchdog) is not yet built on this install.",
            theme::pending(),
        )),
        Line::from(Span::styled(
            "  See dev/DURUM.md for what's implemented vs. pending in this chapter.",
            theme::muted(),
        )),
        Line::from(""),
        Line::from(Span::styled("Tamper detection", theme::accent())),
        Line::from(Span::styled(
            "  not available — depends on the watchdog above (chapter §3.6).",
            theme::pending(),
        )),
        Line::from(""),
        Line::from(Span::styled("Active auth-gate sessions", theme::accent())),
        Line::from(Span::styled(
            "  none — the challenge-response auth gate (§2.1) also depends on the watchdog.",
            theme::pending(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Press 2 for a real telemetry summary from this install's database, or 3 to run the first-run setup wizard.",
            theme::muted(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(theme::panel("Status")),
        area,
    );
}

fn draw_telemetry(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    match &app.sites {
        Err(e) => {
            lines.push(Line::from(Span::styled(
                format!("Could not read the database: {e}"),
                theme::error(),
            )));
            lines.push(Line::from(Span::styled(
                format!("  (data dir: {})", app.data_dir.display()),
                theme::muted(),
            )));
        }
        Ok(sites) if sites.is_empty() => {
            lines.push(Line::from(Span::styled(
                "No sites yet — `fossh site create <slug>` to add one.",
                theme::muted(),
            )));
        }
        Ok(sites) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "{:<24} {:<10} {:>12} {:>12}",
                    "SITE", "STATUS", "HITS TODAY", "UNIQUES"
                ),
                theme::accent(),
            )));
            for s in sites {
                let (status, style) = match (s.disabled, s.public) {
                    (true, _) => ("disabled", theme::muted()),
                    (false, true) => ("public", theme::success()),
                    (false, false) => ("private", theme::pending()),
                };
                lines.push(Line::from(vec![
                    Span::raw(format!("{:<24} ", s.slug)),
                    Span::styled(format!("{status:<10} "), style),
                    Span::raw(format!("{:>12} {:>12}", s.hits_today, s.uniques_today)),
                ]));
            }
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(theme::panel("Telemetry summary (today, k-anonymized)")),
        area,
    );
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
            lines.push(Line::from(Span::styled(
                "Press 'g' to generate one now (standalone/demo mode — in a real install the watchdog does this on first start; see chapter §3.3 in dev/DURUM.md).",
                theme::muted(),
            )));
        }
        Step::TokenJustGenerated { plaintext } => {
            lines.push(Line::from(Span::styled(
                "Token generated. This is shown exactly once:",
                theme::accent(),
            )));
            lines.push(Line::from(""));
            // `.as_str()`, not a clone: `plaintext` is a `Zeroizing<String>`
            // specifically so the real setup-token plaintext has exactly
            // one live copy in this process — cloning it here for
            // rendering would mint a fresh, unprotected copy on every
            // single redraw (the event loop redraws roughly every
            // 100ms) for as long as this screen stays up.
            lines.push(Line::from(Span::styled(
                plaintext.as_str(),
                theme::pending().add_modifier(ratatui::style::Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Write it down. Press Enter to continue to verification.",
                theme::muted(),
            )));
        }
        Step::AwaitingInput => {
            lines.push(Line::from("Enter the setup token to complete enrollment:"));
            lines.push(Line::from(""));
            lines.push(Line::from(format!("> {}", w.input.as_str())));
        }
        Step::Verified => {
            lines.push(Line::from(Span::styled(
                "Setup complete. The token file has been deleted and its hash invalidated — it cannot be reused.",
                theme::success(),
            )));
        }
        Step::Failed(msg) => {
            lines.push(Line::from(Span::styled(
                format!("Failed: {msg}"),
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press Enter to try again.",
                theme::muted(),
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme::panel("Setup Wizard")),
        area,
    );
}
