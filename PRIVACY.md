# Privacy

This page explains, in plain language, what foSSH collects on this site, how, and what that does and doesn't protect. A site owner running foSSH is welcome to copy this page (or a summary of it) into their own privacy policy — see the note for site owners at the end.

## What is collected

When you visit a page or trigger a tracked action, foSSH may record:

- the page path (e.g. `/blog/hello`), not the full URL with query parameters
- the referring site, if any
- your browser family, operating system family, and device type (desktop / mobile / tablet), as coarse categories — not your exact browser version, not a fingerprint
- your country, from your IP address — nothing more precise than that
- the time of the visit
- for named events (e.g. "signed up", "completed checkout"), the event name and, if the site owner configured it, a small number of pre-approved extra fields

## What is not collected, ever

- **Your IP address is never stored.** It's used for one calculation (below) in the instant a request is handled, and then discarded — not logged, not written to any file, not kept "just in case."
- **No cookies.** Nothing is set in your browser, and nothing is read from it either — no `localStorage`, no cache-based tricks.
- **No cross-site tracking.** foSSH has no central server that could correlate your visits across different websites. Each foSSH installation only ever knows about the site(s) it's configured for.
- **No fingerprinting.** No canvas fingerprinting, no font-enumeration, no screen-resolution entropy stacking, no TLS fingerprinting.
- **No free text.** You can't accidentally leak something you typed — foSSH only ever records event names and fields the site owner explicitly allowlisted in advance.
- **No session recording.** No heatmaps, no keystroke logs, no mouse-movement tracking.

## The rotating salt, explained without jargon

To count "how many different people visited," without storing who any of them are, foSSH mixes your IP address and browser category through a mathematical scrambling function (a "hash") before anything touches a database. The scrambling uses a random ingredient — a "salt" — that changes every single day and is never written down anywhere permanent.

**What this protects:** the scrambled result can't be reversed back into your real IP address. And because the salt changes daily, the same person visiting on Monday and on Tuesday produces two completely different, unlinkable scrambled values — so even the site owner can't tell "this is the same visitor as yesterday," only "today, N distinct visitors showed up."

**What this does not protect:** within a single day, if you visit the same site's pages twice, those two visits *do* scramble to the same value, so they can be counted as "the same visitor, twice" for that one day's numbers. The salt also lives only in memory or on a memory-backed filesystem (never written to a persistent disk) — see `THREAT_MODEL.md` for what that tradeoff means if someone has already compromised the server itself. And this is a statistics tool, not a legal shield: it reduces what's collected, it doesn't by itself make any particular use of it lawful — see the note for site owners below.

## Numbers, not individuals

foSSH also refuses to report any number small enough to identify an individual. If a particular page, country, or browser combination had fewer than a handful of visitors in a given period, foSSH folds that result into a generic "other" bucket instead of showing the small number on its own. This is called k-anonymity, and it is applied inside the part of the software that answers every query, so no report or export can go around it.

The threshold itself — how many visitors count as "a handful" — is a setting, and the site owner can change it. The default is five. Lowering it makes smaller groups visible; setting it to zero disables the fold entirely. foSSH's own self-check reports that as a critical problem when it finds it, but it is the site owner's machine and the site owner's decision, so this page cannot promise you what value they chose. If that matters to you, ask them.

## Respecting your signals

If your browser sends `Do Not Track` or the Global Privacy Control signal, foSSH treats that visit as opted out by default: nothing is recorded for it at all, not even in anonymized form.

## If this site sends data anywhere else

foSSH itself has nowhere to send anything: there is no central service, and the part of it that receives your visit cannot make an outbound connection at all.

However, a site owner can separately configure their installation to forward information to an external service they have chosen — a logging service, a dashboard, an alerting tool. That is their configuration and their decision, it is not something foSSH does on its own, and this page cannot tell you whether they have done it. A site owner who has should say so in their own privacy policy, and the note below asks them to.

## For site owners

Running foSSH does not, by itself, make your site compliant with GDPR, KVKK, ePrivacy, CCPA, or any other regime — it's a tool that collects less, not a substitute for knowing what applies to you. You are the sole data controller for whatever your deployment collects; foSSH's author is neither a controller nor a processor, because no data collected by your installation ever reaches them (see `tos.md`). If you paste this page into your own privacy policy, adjust it to match what you've actually configured — this page describes the software's defaults and guarantees, not your deployment. At minimum, check these four:

- which events and extra fields you've allowlisted;
- your retention period;
- your k-anonymity threshold, if you changed it from the default of five;
- **any external service you've configured foSSH to send data to.** If you have, this page as written is wrong for your site, because it tells your visitors nothing leaves your server. Say what you send, to whom, and why.
