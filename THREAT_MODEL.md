# Threat model

## Assets

What this document is trying to protect, in order of how badly a failure would hurt:

1. **Visitor identity and behavior** — the ability to tell who a specific real person is, or to reconstruct their individual browsing behavior on a site running foSSH, from anything foSSH stores or transmits.
2. **Write keys** — the per-site credential (`fossh_<slug>_<base32>`) that authenticates a request to record an event. Anyone holding one can submit (fabricated or real) telemetry for that site.
3. **The daily salt** — the ingredient that makes visitor hashing unlinkable day-to-day. Its exposure doesn't reveal anyone's identity by itself, but combined with a known IP/UA pair it lets an attacker recompute that one day's visitor hash.
4. **Aggregated statistics' integrity** — that a report ("347 hits, 12 unique visitors") reflects what actually happened, not something an attacker inflated, deflated, or poisoned.
5. **Availability of the ingest path** — a site's ability to keep recording legitimate events under load or minor attack, without that requiring foSSH to compromise any of the above to stay up.

## Adversaries

### The curious operator

The person running foSSH on their own site, wanting to know more about a specific visitor than the aggregated numbers allow.

**Defended against:** there is no raw IP, no raw user-agent string, and no per-visitor identifier anywhere in the data model — the operator has no query that produces "here's what visitor X did," because that row was never written. K-anonymity additionally folds any group below the threshold into an "(other)" bucket, so even a narrow, cleverly-constructed query can't isolate an individual by intersecting small groups.

**Not defended against:** an operator who controls the deployment can always modify the source, add their own logging, or run something else entirely alongside foSSH. Software cannot stop the person operating it from doing something different — foSSH's guarantee is about what *this* software does with the data that reaches it, not a constraint on the operator's infrastructure as a whole.

### Host compromise

An attacker who gains code execution or filesystem read access on the machine running foSSH.

**Defended against:** the spool (where events sit briefly before being folded into aggregates) is encrypted at rest under a per-install key — a stolen disk image or a read-only filesystem snapshot doesn't hand over raw event data in the clear. The rollup database itself holds only k-anonymity-folded aggregates and probabilistic sketches (HyperLogLog, histograms), not raw per-visitor rows, so there's nothing individually identifying to steal from it even unencrypted. Write keys are stored as `BLAKE3` hashes, not plaintext, and file permissions are enforced and checked (`fossh doctor`).

**Not defended against — stated plainly:** host compromise with an attacker who can also read process memory can, in principle, observe the current day's salt and any in-flight plaintext (an event being recorded right now, before it's written) — memory is not encrypted. An attacker with root can also just watch future traffic directly at the source, encryption of stored data notwithstanding. **This is why the salt lives on tmpfs (or in-process memory for the embedded/FFI shape), never on a persistent disk: the tradeoff is that a host compromise gets the salt back only for as long as the machine has been up since its last reboot, and only if they catch it while resident, rather than being able to read it back out of a disk image taken after the fact.** That's a real, deliberate tradeoff, not a gap nobody thought about — persistent storage would survive a reboot but would also survive being lifted straight off a backup or a decommissioned disk, which is the worse failure mode for a value whose entire job is to not outlive the day it was generated.

### Malicious embedder

The developer who integrates foSSH into a site or app and could misuse the parts of the API under their control.

**Defended against:** event names and property keys are allowlisted per site at setup time — an embedder can't invent a new free-text field and start collecting whatever they want through it; the CGI/FFI/binding layers all validate against the same allowlist. Properties are bounded in size and count (S4). There is no free-text field anywhere in the wire protocol.

**Not defended against:** an embedder who controls what gets passed as an *allowed* field's value can still put something sensitive in there if the site owner allowlisted a field broad enough to permit it (e.g. allowlisting a `notes` property and then putting an email address in it). foSSH enforces the *shape* of what's collected; it can't enforce that a site owner chose a safe shape. This is a configuration responsibility, documented as such rather than silently assumed away.

### Network observer

Someone positioned to observe traffic between a visitor's browser and the server, or between the server and wherever it's deployed.

**Defended against:** foSSH itself makes zero outbound network connections from its ingest path (P-invariant: zero egress) — there's no second hop to a foSSH-operated server for a network observer to target, because it doesn't exist. Signed-mode authentication (§8) includes a timestamp window and a replay-nonce cache, so a captured signed request can't be replayed later.

**Not defended against:** foSSH does not terminate TLS itself — that's the webserver's job in every deployment shape this project ships (CGI behind Apache/nginx, the embedded FFI call happening in-process). A deployment that serves the ingest endpoint over plain HTTP exposes exactly what plain HTTP always exposes (the path, the write key if sent as a bearer token, etc.) to anyone on the path. Use HTTPS; foSSH assumes you already are, the same way almost every piece of server software does.

### Subpoena / legal process

A request compelling the operator (not the author — see `tos.md`) to hand over whatever foSSH has stored.

**Defended against:** there's simply less to hand over. No raw IP, no raw UA, no per-visitor identifier, no free text. What exists is aggregated counts and probabilistic sketches for periods the operator's own retention policy hasn't already deleted.

**Not defended against:** aggregated counts are still real data about real traffic and are not immune to legal process just because they're aggregated — a subpoena can compel production of whatever does exist. foSSH minimizes what exists; it does not and cannot grant immunity from compelled disclosure of what's left.

## Explicitly not defended against (the §17 minimum of three, stated together)

1. **A compromised host reading live process memory** (the current day's salt, an event mid-flight before it's written) — see "Host compromise" above.
2. **An operator modifying or replacing foSSH itself** on their own infrastructure — see "The curious operator" above.
3. **Plaintext transport** if a deployment doesn't terminate TLS in front of foSSH — see "Network observer" above.
4. **A write-key holder submitting fabricated telemetry** — the write key is the trust boundary for "may this site record events at all," not a guarantee that every event recorded is truthful. This is inherent to any server-side/beacon-based analytics system, not specific to foSSH.

## Alpha caveats

This is Open Alpha (`0.1.0-alpha.1`). Read this section before deciding how much to trust this software with:

- **No third-party security audit has been performed.** Everything in this document reflects the author's own review and the automated checks described below, not an independent assessment.
- **No fuzzing has been run yet.** A `cargo-fuzz` harness against the CGI input parser is planned (chapter §3.7 in `DURUM.md`) but not built as of this release — the CGI/FastCGI input-parsing surface has not been fuzz-tested at all so far, only exercised by the project's own unit and integration tests.
- **What has been checked, mechanically, as of this release:** `cargo clippy -- -D warnings` clean; `cargo audit` and `cargo deny check` (advisories, license bans, sources) clean across both Cargo workspaces; Miri run clean against the two pointer-manipulating functions in the FFI boundary (`fossh-ffi`'s `miri_safe` module — Miri cannot interpret the compiled C code the bundled SQLite library brings in, so Miri's coverage stops at that boundary, not because the rest wasn't worth checking but because the tool structurally can't see through a `dlopen`-free but still-compiled-C dependency).
- **What has not been independently reviewed:** the SELinux policy module (compiles and packages cleanly; has not been load-tested against a real running process under enforcement — see `DURUM.md`), the cryptographic protocol design as a whole (built by one person following the specification's own invariants, not reviewed by a second cryptographer), and the OCaml watchdog / challenge-response auth gate / QUIC-mTLS IPC channel described in `DURUM.md`'s current chapter, which is not yet built at all.
- Per §19.3: alpha means the *interfaces* are unstable (wire format, config schema, SQLite schema, C ABI, CLI flags, binding APIs, spool frame format) — it does not mean the privacy and security invariants above are negotiable. An alpha build that leaked a raw IP would be a broken build, not an acceptable alpha limitation.
