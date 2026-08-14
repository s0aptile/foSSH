# Terms of Use and Disclaimer

**foSSH — Open Alpha**

Version 0.1.3_oa. Dated 2026-08-06. This document applies to this release only. It has no retroactive effect on any prior release, and a future release may ship a different version of this document that governs that release instead.

---

## 1. What foSSH is

foSSH is software, not a service. It has no network egress from its ingest path. The author never receives, stores, processes, or has access to any data collected by any deployment of foSSH. There is no server operated by the author, no account, no telemetry sent back to the author, and no update check. Everything below follows from that one fact.

## 2. No data reaches the author

Nobody who runs foSSH sends the author anything. This is verified mechanically, not just asserted: the project's continuous integration includes a test suite that runs with network access fully denied, and a grep-based check confirming the ingest and response code paths make no outbound connection of any kind.

## 3. Acceptance

By downloading, building, installing, linking, or running foSSH, you accept this document and the license.

## 4. The license controls; this document adds no restrictions

foSSH is licensed under the MIT License — see `LICENSE`. Nothing in this document restricts, conditions, or adds to the rights granted by that license. Where this document and the license appear to conflict, the license controls.

## 5. Open Alpha

This is an Open Alpha release. There is no stability guarantee for the wire format, configuration schema, database schema, C ABI, CLI flags, or binding APIs — any of these may change without notice between alpha releases. There is no guaranteed migration path between alpha releases; run `fossh export` before upgrading if you want your aggregated data available afterward regardless of schema changes. No fitness for production use is asserted.

## 6. No warranty

foSSH is provided "AS IS", without warranty of any kind, express or implied, restating in plain language the disclaimer already in `LICENSE` and narrowing nothing in it. There is no warranty of merchantability, fitness for a particular purpose, or non-infringement.

## 7. Limitation of liability

To the maximum extent permitted by applicable law, the author is not liable for any damages — direct, indirect, incidental, special, or consequential — arising from the use of foSSH, restating in plain language the same limitation already in `LICENSE`. No liability cap has been negotiated with you, because none exists to negotiate; this is a disclaimer, not a contract for services. No exception is made beyond what applicable law forbids disclaiming.

## 8. Assumption of risk

Use of foSSH is entirely at your own risk. You assume all risk of data loss, service interruption, incorrect measurement, misconfiguration, and legal or regulatory exposure arising from your deployment. By downloading, building, installing, linking, or running foSSH, you acknowledge this and waive, to the maximum extent permitted by applicable law, any claim against the author arising from such use.

## 9. Open source: modify freely, at your own risk

foSSH is open source under the MIT License, which already grants you the right to read, modify, extend, fork, or combine it with anything else you build — see `LICENSE`; this section adds no restriction beyond it. Advanced users are free to treat the codebase like a kit of parts: change it, bolt things onto it, strip things out of it, run a patched or forked version, whatever you want. None of that changes anything above. The same no-warranty (§6), limitation-of-liability (§7), and assumption-of-risk (§8) terms apply in full to a modified or forked deployment exactly as they do to an unmodified one — the author has no visibility into, and bears no responsibility for, what anyone builds on top of foSSH or how far it has diverged from the code as released.

## 10. You are the data controller

Whoever deploys foSSH is the sole data controller for the data their deployment collects. The author is neither a controller nor a processor, and no data-processing agreement exists or is needed, because no data collected by any deployment reaches the author. You are responsible for your own lawful basis for collection, your own notice to your users, your own retention policy, and your own handling of access requests, under whatever legal regime applies to you.

## 11. No compliance is warranted

Running foSSH does not make you compliant with GDPR, KVKK, ePrivacy, CCPA, or any other law or regulation. foSSH is a tool that collects less; compliance is a property of your deployment and your disclosures, not of this binary.

## 12. Intended use (non-binding)

The following is a statement of intent, not a license condition, not a field-of-use restriction, and not enforceable as a term of this document: foSSH is built to measure less, and is not intended for surveillance, deanonymization, or re-identification of individuals. This paragraph does not appear in, and does not modify, `LICENSE`.

## 13. Third-party components

foSSH bundles or depends on third-party software. See `NOTICE` for the complete list, each with its license, generated from the project's own dependency tooling.

## 14. Cryptography and export

foSSH contains cryptographic functionality (BLAKE3 hashing, HMAC-style request authentication, ChaCha20-Poly1305 authenticated encryption, SHA-256, constant-time comparison). You are responsible for compliance with the import, export, and use regulations of your own jurisdiction.

## 15. Name and trademark

Neither the name "foSSH" nor the handle "$0aptile" is a claimed or registered trademark, and none is granted by this document or the license — the MIT License itself is silent on trademarks, so this document states the position directly rather than restating one. Neither name nor handle may be used to endorse or promote a derived work without permission.

## 16. Security reports

Report vulnerabilities via GitHub private vulnerability reporting on this repository — see `SECURITY.md`. There is no bug bounty, no response-time SLA, and no guarantee of a fix.

## 17. No contract for services; no governing law or venue

This document is a disclaimer and notice, not a contract for the provision of any service. It does not name a governing law, a venue, or an arbitration procedure, and does not waive your right to a class action. The license — which needs no venue to disclaim a warranty — is the operative instrument here, not a services agreement.

## 18. Severability

If any clause of this document is found unenforceable, that clause is severed and the rest of the document remains in effect.

## 19. Changes

This document is versioned with releases. The version shipped with a given release governs that release; a later release may ship a different version, which then governs that later release, without retroactive effect on the one before it.

## 20. Contact

GitHub issues and GitHub private vulnerability reporting only. There is no other contact address for this project.
