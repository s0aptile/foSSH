# Project rules

Internal reference for how this project is named, written about, split into public/private, and positioned. Applies to code, docs, commit messages, and anything else produced for this repository.

## 1. Name

The product name is **foSSH** — lowercase `f`, uppercase `SSH`. Not "FoSSH", not "FOSSH", not "Fossh". Officially a backronym: **F**ree **O**pen **S**ource **S**oftware **H**itcounter — the same five letters read two ways at once, the casing doubling as a nod to the well-known `SSH` acronym even though this project has nothing to do with the Secure Shell protocol. "Hitcounter" is deliberate, not a hedge: it names the actual scope (self-hosted visit/event counting) rather than reaching for a grander label. Exceptions where casing is forced by the platform, not stylistic choice:

- Rust crate/package names: `fossh-core`, `fossh-cgi`, etc. (Cargo requires lowercase).
- The Composer package name `s0aptile/fossh-php` (Packagist requires lowercase, same reasoning as Cargo above).
- The PHP namespace `FoSSH\` (PSR-4 top-level namespaces are conventionally capitalized; this is the one deliberate exception, already shipped in `bindings/php`).
- C symbols (`fossh_ctx`, `fossh_init`, ...) — all lowercase, per the C ABI convention in `include/fossh.h`.

Everywhere else — prose, headings, READMEs, commit messages, the TUI, log output a human reads — it is **foSSH**. The real repository is `https://github.com/s0aptile/foSSH` (capital `SSH`, matching the product name) — not to be confused with the separate, lowercase `s0aptile/fossh-go` repository the Go binding lives in (`bindings/go/go.mod`), which is its own thing per Go's one-module-per-repository convention and was never part of this correction.

## 2. Writing tone

No AI-generated-sounding text. Concretely, that means:

- No marketing adjectives ("powerful", "seamless", "cutting-edge", "robust" used as a filler compliment rather than a claim being backed by something). If a capability is worth stating, state what it does, not how impressive it is.
- No exclamation points. No emoji unless a user explicitly asks for them in that specific context.
- No em-dash-heavy enthusiastic marketing cadence. Short declarative sentences over long qualified ones.
- Say what's true and tested plainly; say what's untested or deferred plainly too, in the same sentence style — don't hedge with false confidence in either direction.
- This applies to `README.md`, `tos.md`, the TUI's own copy, commit messages, and this file itself.

## 3. Public / private boundary

Two hard-separated zones. Treat the line between them like a border, not a suggestion:

**Public** — everything that ships in the git history, the release zip (`fossh-oa.zip`), and built binaries. Governed by the identity-scrubbing rules already locked in from the original spec's authorship addendum: pseudonymous authorship only (`$0aptile` / `github.com/s0aptile`), no real name, email, hostname, or home path anywhere in the repo, git history, or built artifacts. This is enforced mechanically (grep-based identity-hygiene gates, §19.4.12 of the original spec), not just by convention.

**Private** — anything specific to *this* real deployment: the actual machine's hostname, the real user's identity, any enrolled keypair or setup token generated on a real install, actual Cloudflare Tunnel IDs or domain names, `PUBLISH.md`. None of this belongs in the tracked tree at all, public or otherwise gated — it lives in `private-onlyauthor/` at the repo root, which is `.gitignore`d outright, or in `PUBLISH.md` (already gitignored). If a file would reveal which specific machine or person is running foSSH, it goes in `private-onlyauthor/`, full stop — there is no "public but redacted" middle tier for that category of fact.

The distinction is not "public repo vs. private repo" — it's one repo, with an enforced inner boundary. Nothing in `private-onlyauthor/` is ever included in the release zip, the git history, or a support request's paste-in.

## 4. Platform support

- **Fedora / Fedora Server is the first-class target.** `sudo dnf install fossh` is the intended end-user install path once RPM packaging (chapter §3.11) ships. Setup guidance defaults to `dnf`, not a generic "your package manager" hand-wave.
- Other Linux distributions, macOS, and FreeBSD are supported through the original CGI/embedded-FFI deployment shapes (build from source or use the static/dynamic artifacts per `docs/`), which remain valid and are not superseded by the Fedora-native chapter.
- **Windows is not supported yet.** It's in development. Don't document a Windows setup path as if it exists; say plainly that it doesn't yet, if asked.

## 5. Positioning

foSSH exists because the default answer to "how do I get basic site analytics" is a hosted service that sees every visitor's traffic in order to show you a dashboard about them — Google Analytics being the largest example, but the shape of the trade is the same across most hosted options: your visitors' data leaves your infrastructure and becomes someone else's product telemetry, in exchange for you not having to run anything yourself.

foSSH's answer is to not make that trade: self-hosted, no third party in the data path, k-anonymity and salted hashing instead of raw visitor identifiers, no cross-site tracking because there's no central service to correlate across sites in the first place. The cost is real too — you run it, you're responsible for it — which is exactly what the Fedora-native packaging, the watchdog, and the TUI setup wizard exist to make less painful, not to pretend away.

This isn't framed as "instead of Google" in the sense of requiring you to rip anything out. foSSH doesn't set cookies, doesn't touch any client-side global GA/GTM would also use, and doesn't load a client-side script at all in its server-relay integrations (see `docs/INTEGRATION-php.md` §3) — there's nothing to conflict with. Running foSSH for your own privacy-preserving numbers alongside Google Analytics or Tag Manager for ad attribution is a normal, supported combination, not a contradiction — they answer different questions.

## 6. New in this phase

- A local admin console for status, tamper-detection state, telemetry summary, and the first-run setup wizard — see chapter §3.9/§3.11. As of 0.2.0 this is `fossh-console`, a GTK4/libadwaita desktop application driving a headless `fossh-agent` helper over a pipe; it replaced the `ratatui` terminal console, which is retired with the rest of the 0.1.x line (ADR-0061).
- Fedora-native hardened deployment: an OCaml watchdog supervising the core process over a locally-pinned mTLS/QUIC channel, challenge-response auth (no static credentials anywhere), SELinux policy, and RPM packaging. See `dev/DURUM.md` for what's implemented versus still in progress.
- A local-nginx-plus-Cloudflare-Tunnel self-hosting guide lives at `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md` — the `preview/` location is the signal: a future deployment tier, not one that's been built and adversarially reviewed yet. Don't treat it as a supported path until `dev/DURUM.md` says otherwise.
