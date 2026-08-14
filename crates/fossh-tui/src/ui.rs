use fossh_admin::command_client::{ChildState, TamperState};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::app::{App, Screen};
use crate::theme;
use crate::wizard::Step;

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    theme::fill_background(frame, area);
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
        Screen::Dashboard => draw_dashboard(frame, chunks[1], app),
        Screen::Telemetry => draw_telemetry(frame, chunks[1], app),
        Screen::Wizard => draw_wizard(frame, chunks[1], app),
        Screen::OperatorAuth => draw_operator_auth(frame, chunks[1], app),
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
        Span::raw("  "),
        make("4 Operator Auth", Screen::OperatorAuth),
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
        app.screen == Screen::Wizard && matches!(app.wizard.step, Step::PastingKey { .. });

    let line = if awaiting_input {
        Line::from(vec![
            Span::styled("Enter", theme::accent()),
            Span::raw(" submit key   "),
            Span::styled("Backspace", theme::accent()),
            Span::raw(" delete   "),
            Span::styled("Esc", theme::accent()),
            Span::raw(" cancel, back to key-source choice"),
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
            Span::raw("/"),
            Span::styled("4", theme::accent()),
            Span::raw(" switch screen"),
        ];
        match app.screen {
            Screen::Dashboard => {
                spans.push(Span::raw("   "));
                spans.push(Span::styled("r", theme::accent()));
                spans.push(Span::raw(" check watchdog"));
            }
            Screen::Telemetry => {
                spans.push(Span::raw("   "));
                spans.push(Span::styled("r", theme::accent()));
                spans.push(Span::raw(" refresh"));
            }
            Screen::Wizard => match app.wizard.step {
                Step::NoTokenFound => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("Enter", theme::accent()));
                    spans.push(Span::raw(" check again"));
                }
                Step::ReadyToSubmit { .. } => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("Enter", theme::accent()));
                    spans.push(Span::raw(" continue"));
                }
                Step::ChoosingKeySource { .. } => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("p", theme::accent()));
                    spans.push(Span::raw(" paste a key   "));
                    spans.push(Span::styled("g", theme::accent()));
                    spans.push(Span::raw(" generate a fresh key"));
                }
                Step::KeyGenerated { .. } => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("Enter", theme::accent()));
                    spans.push(Span::raw(" send the public key and enroll"));
                }
                Step::EnrollFailed { .. } => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("Enter", theme::accent()));
                    spans.push(Span::raw(" try a different key (same token)"));
                }
                Step::TokenDenied | Step::Failed(_) => {
                    spans.push(Span::raw("   "));
                    spans.push(Span::styled("Enter", theme::accent()));
                    spans.push(Span::raw(" re-check the token file"));
                }
                Step::PastingKey { .. } | Step::Enrolled { .. } => {}
            },
            Screen::OperatorAuth => {
                spans.push(Span::raw("   "));
                spans.push(Span::styled("a", theme::accent()));
                match app.operator_auth.step {
                    crate::operator_auth::Step::NotAttempted => {
                        spans.push(Span::raw(" authenticate"))
                    }
                    _ => spans.push(Span::raw(" try again")),
                }
            }
        }
        Line::from(spans)
    };

    frame.render_widget(Paragraph::new(line).style(theme::muted()), area);
}

fn draw_dashboard(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![Line::from(Span::styled(
        "Watchdog / tamper detection — live query over §3.4's QUIC/mTLS command channel",
        theme::accent(),
    ))];
    match &app.watchdog_status {
        Ok(status) => {
            let (child_text, child_style) = match status.child {
                ChildState::Running => ("running", theme::success()),
                ChildState::Stopped => ("not running", theme::error()),
            };
            lines.push(Line::from(vec![
                Span::raw("  supervised core process: "),
                Span::styled(child_text, child_style),
            ]));
            let (tamper_text, tamper_style) = match status.tamper {
                TamperState::Clean => (
                    "clean — manifest verifies against the running binary",
                    theme::success(),
                ),
                TamperState::Tampered => (
                    "TAMPER DETECTED — manifest/hash mismatch, see the watchdog's own log",
                    theme::error(),
                ),
                TamperState::Unknown => (
                    "inconclusive — the watchdog could not complete a fresh check (see its log)",
                    theme::pending(),
                ),
            };
            lines.push(Line::from(vec![
                Span::raw("  tamper check: "),
                Span::styled(tamper_text, tamper_style),
            ]));
        }
        Err(e) => {
            lines.push(Line::from(Span::styled(
                format!("  could not reach watchdog: {e}"),
                theme::error(),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Human-operator auth gate",
        theme::accent(),
    )));
    let (auth_text, auth_style) = match &app.operator_auth.step {
        crate::operator_auth::Step::NotAttempted => (
            "not attempted yet — screen 4, then 'a' to authenticate".to_string(),
            theme::muted(),
        ),
        crate::operator_auth::Step::Authenticated { .. } => (
            "authenticated — session token held on screen 4".to_string(),
            theme::success(),
        ),
        crate::operator_auth::Step::NotEnrolled => (
            "no operator key enrolled with the watchdog yet".to_string(),
            theme::pending(),
        ),
        crate::operator_auth::Step::Denied => (
            "last attempt was denied — see screen 4".to_string(),
            theme::error(),
        ),
        crate::operator_auth::Step::Failed(e) => {
            (format!("last attempt failed: {e}"), theme::error())
        }
    };
    lines.push(Line::from(vec![
        Span::raw("  "),
        Span::styled(auth_text, auth_style),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Press r to (re)check watchdog/tamper status, 2 for a real telemetry summary, 3 to run the first-run setup wizard, or 4 for the operator auth gate.",
        theme::muted(),
    )));

    frame.render_widget(
        Paragraph::new(lines)
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
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme::panel("Telemetry summary (today, k-anonymized)")),
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
            lines.push(Line::from(Span::styled(
                "No setup token file found there.",
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "The watchdog writes this file itself on first start (§2.6) — either it hasn't \
                 run yet, or setup already completed and burned it. Press Enter to check again.",
                theme::muted(),
            )));
        }
        Step::ReadyToSubmit { plaintext } => {
            lines.push(Line::from("Setup token found:"));
            lines.push(Line::from(""));
            // `.as_str()`, not a clone — see the same reasoning on
            // `Step::KeyGenerated`'s private-key line below: this is a
            // `Zeroizing<String>` specifically so the real plaintext
            // has exactly one live copy, and cloning it on every
            // redraw (roughly every 100ms while this screen is shown)
            // would defeat that.
            lines.push(Line::from(Span::styled(
                plaintext.as_str(),
                theme::pending().add_modifier(ratatui::style::Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press Enter to submit it to the watchdog and enroll an operator key.",
                theme::muted(),
            )));
        }
        Step::ChoosingKeySource { .. } => {
            lines.push(Line::from("Token accepted locally — not yet sent."));
            lines.push(Line::from(""));
            lines.push(Line::from(
                "Enroll the real operator public key: paste one you already have, or let \
                 foSSH generate a fresh keypair.",
            ));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "'p' to paste an armored public key   'g' to generate a fresh one",
                theme::muted(),
            )));
        }
        Step::PastingKey { input, .. } => {
            lines.push(Line::from(
                "Paste the armored public key block (bracketed paste preserves the newlines; \
                 Enter submits):",
            ));
            lines.push(Line::from(""));
            lines.push(Line::from(input.as_str()));
        }
        Step::KeyGenerated {
            fingerprint,
            private_key_armored,
            ..
        } => {
            lines.push(Line::from(Span::styled(
                format!("Generated a fresh key: {fingerprint}"),
                theme::accent(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "The private half is shown here exactly once — save it somewhere safe:",
                theme::accent(),
            )));
            lines.push(Line::from(""));
            // `.as_str()` for the same reason as `ReadyToSubmit`'s
            // token line above: a real secret key, `Zeroizing`-wrapped
            // on purpose.
            lines.push(Line::from(Span::styled(
                private_key_armored.as_str(),
                theme::pending(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "It also stays in your own GPG keyring, so it's ready for the operator-auth \
                 challenge-response screen (4) right after this. Press Enter to send the \
                 public half and enroll.",
                theme::muted(),
            )));
        }
        Step::Enrolled { fingerprint } => {
            lines.push(Line::from(Span::styled(
                format!("Enrolled: {fingerprint}"),
                theme::success(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "The token file has been deleted and its hash invalidated — it cannot be \
                 reused. Use screen 4 (Operator Auth) to authenticate with this key.",
                theme::success(),
            )));
        }
        Step::TokenDenied => {
            lines.push(Line::from(Span::styled(
                "The watchdog rejected the setup token.",
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Wrong or expired token, or setup already completed some other way. Press \
                 Enter to re-check the token file.",
                theme::muted(),
            )));
        }
        Step::EnrollFailed { reason_code, .. } => {
            lines.push(Line::from(Span::styled(
                format!("Enrollment failed: {reason_code}"),
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "The setup token was NOT consumed by this — press Enter to try a different key \
                 with the same token, no need to restart the wizard.",
                theme::muted(),
            )));
        }
        Step::Failed(msg) => {
            lines.push(Line::from(Span::styled(
                format!("Failed: {msg}"),
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press Enter to re-check the token file and try again.",
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

fn draw_operator_auth(frame: &mut Frame, area: Rect, app: &App) {
    use crate::operator_auth::Step as AuthStep;

    let mut lines = vec![
        Line::from(Span::styled(
            "§2.1 challenge-response auth gate: proves you hold the enrolled operator GPG key, in exchange for a session token.",
            theme::accent(),
        )),
        Line::from(Span::styled(
            format!(
                "Socket: {}",
                crate::operator_auth_client::socket_path().display()
            ),
            theme::muted(),
        )),
        Line::from(""),
    ];

    match &app.operator_auth.step {
        AuthStep::NotAttempted => {
            lines.push(Line::from("Not attempted yet."));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press 'a' to sign the watchdog's challenge with your local GPG key. If your key \
                 needs a passphrase, gpg's own pinentry will prompt for it.",
                theme::muted(),
            )));
        }
        AuthStep::Authenticated { token } => {
            lines.push(Line::from(Span::styled("Authenticated.", theme::success())));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::raw("Session token: "),
                Span::styled(
                    token.as_str(),
                    theme::pending().add_modifier(ratatui::style::Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "This token is not wired to issue an admin command from this screen yet — see dev/DURUM.md.",
                theme::muted(),
            )));
        }
        AuthStep::NotEnrolled => {
            lines.push(Line::from(Span::styled(
                "The watchdog has no enrolled operator key yet.",
                theme::error(),
            )));
            lines.push(Line::from(Span::styled(
                "Enroll a key first (§3.11) — this screen only handles proving an already-enrolled identity.",
                theme::muted(),
            )));
        }
        AuthStep::Denied => {
            lines.push(Line::from(Span::styled(
                "Denied. The watchdog rejected the signature — wrong key, wrong data, or the enrolled key was revoked or expired.",
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press 'a' to try again.",
                theme::muted(),
            )));
        }
        AuthStep::Failed(msg) => {
            lines.push(Line::from(Span::styled(
                format!("Failed: {msg}"),
                theme::error(),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press 'a' to try again.",
                theme::muted(),
            )));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme::panel("Operator Auth")),
        area,
    );
}
