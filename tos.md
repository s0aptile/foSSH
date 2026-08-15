# Terms of Use and Disclaimer

**foSSH — Open Alpha**

Version 0.0.2.1. Dated 2026-08-15. This document applies to this release only. It has no retroactive effect on any prior release, and a future release may ship a different version of this document that governs that release instead.

---

## 1. What foSSH is

foSSH is software, not a service. It has no network egress from its ingest path. The author never receives, stores, processes, or has access to any data collected by any deployment of foSSH. There is no server operated by the author, no account, no telemetry sent back to the author, and no update check. Everything below follows from that one fact.

## 2. No data reaches the author

Nobody who runs foSSH sends the author anything. This is structural rather than merely asserted: the code capable of making an outbound request is not present in the dependency tree of any ingest component, which you can verify yourself without trusting this sentence — `cargo tree -p fossh-cgi` and `cargo tree -p fossh-fcgi` — the two components that receive events — list neither `fossh-agent` (the helper the administration console speaks to, §19) nor `fossh-selfheal` (the optional local-model layer, §21). Those are the only two components in foSSH that can make an outbound request at all.

This statement is about the author. It is **not** a statement about anywhere your own deployment sends data at your own instruction. See §19.

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

Use of foSSH is entirely at your own risk. You assume all risk of data loss, downtime, incorrect measurement, misconfiguration, and legal or regulatory exposure arising from your deployment. By downloading, building, installing, linking, or running foSSH, you acknowledge this and waive, to the maximum extent permitted by applicable law, any claim against the author arising from such use.

## 9. Open source: modify freely, at your own risk

foSSH is open source under the MIT License, which already grants you the right to read, modify, extend, fork, or combine it with anything else you build — see `LICENSE`; this section adds no restriction beyond it. Advanced users are free to treat the codebase like a kit of parts: change it, bolt things onto it, strip things out of it, run a patched or forked version, whatever you want. None of that changes anything above. The same no-warranty (§6), limitation-of-liability (§7), and assumption-of-risk (§8) terms apply in full to a modified or forked deployment exactly as they do to an unmodified one — the author has no visibility into, and bears no responsibility for, what anyone builds on top of foSSH or how far it has diverged from the code as released.

## 10. You are the data controller

Whoever deploys foSSH is the sole data controller for the data their deployment collects. The author is neither a controller nor a processor, and no data-processing agreement exists or is needed, because no data collected by any deployment reaches the author. You are responsible for your own lawful basis for collection, your own notice to your users, your own retention policy, and your own handling of access requests, under whatever legal regime applies to you.

## 11. No compliance is warranted, and nothing here is legal advice

Running foSSH does not make you compliant with the KVKK, the Swiss revFADP, the GDPR, ePrivacy, the CCPA, or any other law, regulation, standard, or contractual obligation. foSSH is a tool that collects less; compliance is a property of your deployment, your configuration, your disclosures, and your jurisdiction, not a property of this software.

No statement anywhere in this project — this document, the README, `PRIVACY.md`, `THREAT_MODEL.md`, or any comment in the source — is legal advice, and none certifies compliance with anything. Design choices intended to reduce personal-data processing are described as honestly as the author can describe them. Whether they are sufficient for **your** deployment, sector, and jurisdiction is a determination only you and your own advisers can make. You are the data controller (§10), and that determination is yours alone.

## 12. Intended use (non-binding)

The following is a statement of intent, not a license condition, not a field-of-use restriction, and not enforceable as a term of this document: foSSH is built to measure less, and is not intended for surveillance, deanonymization, or re-identification of individuals. This paragraph does not appear in, and does not modify, `LICENSE`.

## 13. However you obtained it

These terms apply regardless of how you obtained foSSH: built from source, installed from an RPM, pulled from a package repository or Copr, unpacked from a release archive, or taken from a mirror or rebuild the author has no connection to. The author does not control, review, or vouch for the integrity of any distribution channel other than this project's own repository and release artifacts, and disclaims all liability for anything obtained elsewhere, including a package that has been modified, repackaged, or tampered with in transit.

## 14. Third-party components

foSSH bundles or depends on third-party software. See `NOTICE` for the complete list, each with its license, generated from the project's own dependency tooling.

## 15. Cryptography and export

foSSH contains cryptographic functionality (BLAKE3 hashing, HMAC-style request authentication, ChaCha20-Poly1305 authenticated encryption, SHA-256, constant-time comparison). You are responsible for compliance with the import, export, and use regulations of your own jurisdiction.

## 16. Name and trademark

Neither the name "foSSH" nor the handle "$0aptile" is a claimed or registered trademark, and none is granted by this document or the license — the MIT License itself is silent on trademarks, so this document states the position directly rather than restating one. Neither is registered as a trademark, and the author is not asserting a registered-trademark claim. The author does nonetheless ask that neither be used to endorse or promote a derived work without permission — a request grounded in whatever unregistered rights arise from use in the relevant jurisdiction, which is a weaker basis than a registration and is described here as exactly that.

## 17. Security reports

Report vulnerabilities via GitHub private vulnerability reporting on this repository — see `SECURITY.md`. There is no bug bounty, no response-time SLA, and no guarantee of a fix.

## 18. Governing law, venue, and the limits of what can be disclaimed

This document is a disclaimer and notice, not a contract for the provision of any service. No service is provided, no fee is charged, and no obligation is undertaken. The MIT License is the operative instrument; this document explains and supplements it without narrowing it.

**Governing law, and an honest note on its limits.** Where the author is free to choose, the author's choice is the substantive law of **Switzerland**, excluding its conflict-of-laws rules and excluding the United Nations Convention on Contracts for the International Sale of Goods, with the ordinary courts of Switzerland as the place of jurisdiction.

That freedom is not unlimited, and this document says so rather than asserting more than it can deliver. Because nothing here is a negotiated agreement, a court may decline to treat this section as a binding choice of forum or of law at all — and for non-contractual (tort-type) claims specifically, Art. 132 of the Swiss Private International Law Act permits the parties to choose the applicable law only by agreement reached **after** the damaging event, not in advance and not by unilateral notice. Turkish private international law is structured comparably. Where a choice made here is therefore ineffective, the applicable law and forum are whatever the ordinary conflict-of-laws rules of the deciding court produce, and nothing in this document pretends otherwise.

Stating this costs nothing and is consistent with the rest of this section: the disclaimers below do not depend on the choice of law above. They are unilateral exclusions of liability, which Swiss and Turkish law each regulate on their own terms whether or not a contract exists.

**Türkiye.** The author is subject to the law of the **Republic of Türkiye**, and nothing in the paragraph above displaces any mandatory provision of Turkish law that applies regardless of choice of law — including, without limitation, the Turkish Personal Data Protection Law No. 6698 (*Kişisel Verilerin Korunması Kanunu*, "KVKK") and any mandatory consumer-protection provision. Where Turkish law and the paragraph above cannot both be satisfied, the mandatory Turkish provision prevails to the minimum extent necessary and the remainder of this document is unaffected.

**Both regimes are acknowledged, not chosen between.** Where this document disclaims something, it does so to the maximum extent permitted under **both** Swiss and Turkish law, and it is to be read as effective under each independently. A limitation unenforceable under one is not thereby unenforceable under the other.

**What cannot be disclaimed, stated rather than hidden.** Neither jurisdiction permits an unlimited exclusion of liability, and this document does not pretend otherwise. Under Swiss law, Art. 100 of the Code of Obligations voids in advance any agreement excluding liability for unlawful intent (*Absicht*) or gross negligence (*grobe Fahrlässigkeit*). Under Turkish law, Art. 115 of the Turkish Code of Obligations No. 6098 voids in advance any agreement excluding liability for gross fault (*ağır kusur*). Accordingly, every disclaimer, limitation, exclusion and waiver in this document is to be read as **not** extending to unlawful intent or gross negligence/gross fault, and as fully effective in every other respect. This is a drafting choice, not a concession: a clause that overreached would risk being struck in its entirety, and a narrower clause that survives protects more than a broader one that does not.

**Data protection.** Where your deployment processes personal data, the applicable regime is determined by your own circumstances, not by the author's. Both the KVKK and the Swiss Federal Act on Data Protection (*revFADP* / *nDSG* / *nLPD*, in force 1 September 2023) are expressly acknowledged as regimes that may apply to a deployment. In every case you are the data controller and the author is neither controller nor processor — see §10 — because no data collected by your installation ever reaches the author. See §2.

**No waiver of class rights, no arbitration.** This document does not compel arbitration and does not waive any right you may have to bring or participate in a collective or class proceeding, where such a right exists under the law applicable to you.

## 19. External services you configure

foSSH can send requests to endpoints you supply, authenticated with credentials you supply. Every such request is initiated by you and by your configuration. The author has no relationship with, control over, knowledge of, or responsibility for any third party you choose to send data to, and does not endorse, vet, monitor, or warrant any of them.

You are solely responsible for: what you send, whether you were permitted to send it, what the recipient does with it, the terms you agreed to with that recipient, any charge they levy, and any legal or regulatory consequence of the transfer. This includes transfers across jurisdictions. The author is not a party to that relationship in any respect and disclaims all liability arising from it, to the maximum extent permitted by applicable law.

Provider definitions distributed with foSSH describe how to reach certain services. They are conveniences, not endorsements, not certifications of accuracy, and not warranties that the named service exists, functions, or is appropriate for your use. Provider definitions you obtain from anywhere other than this project are entirely unvetted by the author.

## 20. Credential storage

foSSH stores credentials you enter, encrypted at rest under a key held on the same machine. This is a defence against casual disclosure, not against an adversary with access to that machine. Anyone who can read that machine's storage as the relevant user can obtain those credentials, and no encryption applied by software running on that machine can prevent it. You are responsible for the security of the machine, for rotating any credential you believe exposed, and for the consequences of any exposure.

## 21. The optional local model

foSSH can optionally run a language model **on the same machine as the
install**, to add a plain-language explanation to a diagnostic the
deterministic rules have already produced. It is disabled unless the
machine meets a hardware floor and then passes a timed performance
check, and it can be removed without affecting anything foSSH
diagnoses or repairs.

**Its output is generated text, not advice.** It may be inaccurate,
incomplete, or misleading in ways that read as confident and correct.
Nothing it produces is a recommendation, an instruction, a
professional opinion, or a statement of fact by the author. Do not act
on it without independent verification. The author disclaims all
liability for any action taken or not taken on the basis of that
output, to the maximum extent permitted by applicable law.

**It cannot change what foSSH does.** By construction it may only
attach explanatory text to an existing diagnostic; it cannot create a
diagnostic, alter a severity, author a remedy, or cause anything to be
executed. If you require diagnostics you can rely on, use the
deterministic rules, which do not involve it at all and which are the
entire feature without it.

**Nothing is sent anywhere.** The model runs locally and is reached
only over this machine's loopback interface. No prompt, no diagnostic,
and no output leaves the machine, and none of it reaches the author,
who operates no service and receives nothing — see §2. Model weights
are obtained by you, from a third party, under whatever terms that
party sets; the author neither distributes them nor is a party to that
arrangement. You are responsible for complying with the licence or
usage terms attached to any weights you obtain, and for satisfying
yourself that they permit the use you put them to. The author makes no
representation about those terms and has not reviewed them.

**Not an automated decision about anyone.** Article 11(1)(g) of the
KVKK and Article 21 of the Swiss revFADP each concern a decision taken
solely by automated processing that produces a legal effect on, or
otherwise significantly affects, a natural person. Neither is engaged
here: these diagnostics concern the configuration of a deployment
rather than any person, and the model does not produce the diagnostic,
the severity, or the remedy in any case — it only annotates a
conclusion the deterministic rules already reached.

**Regulatory framing.** Where the EU AI Act (Regulation (EU)
2024/1689) applies to a deployment — including because a deployer is
established in the EU, or because output is used there — the feature
described in this section is, on its face, a limited-risk system
generating explanatory text for a professional operator, and not
something listed in Article 5 or Annex III. No representation is made
about how that Regulation applies to any particular deployment, and no
compliance with it is warranted, for the same reason no compliance
with the KVKK, the revFADP, the GDPR, ePrivacy or the CCPA is
warranted — see §11.

## 22. Where your data lives, and who is responsible for it

**Your data stays on your infrastructure.** Everything foSSH records —
events, aggregates, configuration, credentials you add, and anything
the optional local model is shown — is stored on machines you control
and is never transmitted to the author. There is no hosted component,
no account, no telemetry, and no update check.

That is a statement about the software's design, not a transfer of
duty. The division is deliberate:

**Yours.** Everything about the deployment. What you collect, whether
you were permitted to collect it, what you disclose to the people it
concerns, how long you keep it, who can reach the machine, how it is
backed up, whether it is encrypted at rest beyond what foSSH does
itself, which jurisdictions the machine and its visitors sit in, and
every legal or regulatory obligation arising from any of that. You are
the data controller — see §10. The author is neither controller nor
processor, and cannot be, because no data reaches them.

**The author's.** Stated first, because the label matters less than
where it sits: what follows is a statement of intent, not a warranty
and not a term of this document enforceable against the author — the
same standing §12's "intended use" has. It narrows nothing in §6 or
§7.

With that said, the author's side is effort rather than outcome: to
aim for software that is correct, to work at making it efficient, and
to be honest about what it does — through design choices that reduce
the amount of personal data processed in the first place, a threat
model that tries to state what is *not* defended against as plainly as
what is, and documentation that tries not to overstate a guarantee.
Nothing beyond that effort is undertaken, and no particular outcome is
promised.

Neither half substitutes for the other. Software that collects less
does not make a deployment lawful, and a lawful deployment does not
make software correct.

## 23. Integration verification

foSSH can drive a browser to a web address you supply in order to test whether an integration works. Doing so makes real network requests to that address from your machine, executes whatever that page contains, and — when the integration is working — records a genuine visit in your own data, which is precisely the proof being sought and cannot be avoided while still performing the test.

You are responsible for supplying an address you are authorised to request, and for any consequence of requesting it. Do not point it at anything you do not own or have permission to test.

## 24. Indemnification

If a third party brings a claim, demand, or proceeding against the author arising from your deployment of foSSH, your configuration of it, your choice or use of any third-party model weights, the data you chose to collect or forward, your use of the integration-verification feature against any address, or your breach of this document, you will indemnify and hold the author harmless against that claim and against the reasonable costs of defending it, to the maximum extent permitted by applicable law.

This does not extend to any claim arising from the author's own unlawful intent or gross negligence/gross fault, which §18 already excludes from every limitation in this document and which is excluded here too.

## 25. No support, no obligation to fix, no service level

Nothing obliges the author to respond to any report, fix any defect, publish any release, maintain compatibility, preserve any feature, or continue the project at all. There is no service level, no response time, no maintenance window, and no end-of-life commitment. Any assistance ever given is a gift and creates no expectation of further assistance and no course of dealing.

## 26. No security guarantee

foSSH has not been audited by any third party. Testing, fuzzing, and review reduce the likelihood of defects; they do not eliminate them and are not represented as doing so. No representation is made that foSSH is free of vulnerabilities, that any particular attack is prevented, or that any security property holds under conditions the threat model does not contemplate. `THREAT_MODEL.md` states what is and is not defended against, and it is deliberately explicit about the second.

## 27. Aggregate effect of this document

Every disclaimer, limitation, exclusion, and waiver in this document applies to the maximum extent permitted by applicable law, applies cumulatively and independently, and survives any termination of your use of foSSH. Where any one of them is held unenforceable, the remainder are unaffected and the unenforceable one is limited only to the minimum extent required, per §29..

## 28. This document, the licence and NOTICE are the whole of it

This document, `LICENSE`, and `NOTICE` are the complete statement of the author's position. No other statement anywhere — a repository comment, an issue reply, a message in a chat room, a conference remark, a post on any platform — adds a warranty, an obligation, a right, or a representation beyond what is written here, and none should be relied upon as doing so.

## 29. Severability

If any clause of this document is found unenforceable, that clause is severed and the rest of the document remains in effect.

## 30. Changes

This document is versioned with releases. The version shipped with a given release governs that release; a later release may ship a different version, which then governs that later release, without retroactive effect on the one before it.

## 31. Contact

GitHub issues and GitHub private vulnerability reporting only. There is no other contact address for this project.
