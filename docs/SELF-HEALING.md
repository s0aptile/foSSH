# Self-healing

foSSH checks its own state and reports what it finds, with a remedy for
each finding. There are two layers, and the relationship between them
is the important part.

## The rules, which are the whole feature

A fixed set of deterministic checks over real state: file permissions
on the data directory and the data key, whether k-anonymity is set to
something that actually anonymises, whether a one-time setup token is
still lying around, whether a configured GeoIP database exists, and
whether the watchdog is answering.

Each produces a finding with a severity and a remedy. Remedies come in
two kinds and the split is deliberate:

- **Automatic** — narrow by design, and restricted to changes that are
  idempotent, reversible and cannot lose data. In practice that means
  tightening file permissions. Nothing else.
- **Operator** — the exact command, printed for you to run. Anything
  that deletes, rewrites or relaxes a setting is always this, even
  where running it would have been easy.

This layer is in the base `fossh` package, always runs, and needs
nothing installed beyond foSSH itself.

```
sudo fossh doctor
```

## The optional model, and the fence around it

`fossh-selfheal` adds a local language model — `lfm2.5-thinking:1.2b`,
served by Ollama, on your own machine — that can write exactly one
thing: a plain-language explanation attached to a finding the rules
already produced.

It cannot create a finding, change a severity, alter a remedy, or cause
anything to be executed. That is enforced in code, not by prompting:
replies are matched to findings by an id that must already exist, and
only a single string is copied across.

The reason is specific. An operator installs foSSH for a set of
privacy guarantees. A component able to author remedies could argue
them out of one — "your k-anonymity threshold looks high, try lowering
it" is a fluent, confident, and completely wrong sentence that a small
model will produce readily. Keeping the model on the explaining side of
that line means its worst failure is unhelpful prose rather than a
changed setting.

Nothing about a visitor is ever sent to it. Prompts are built from
finding titles and details — strings foSSH itself wrote — and carry no
event, path, country, or aggregate.

## When it runs, and when it declines to

Two gates, both of which must pass.

**Hardware.** AVX2 is required and AVX-512 is preferred; a 1.2B model
quantised for CPU inference leans almost entirely on wide dot
products, and without AVX2 the fallback paths are slower by a large
multiple rather than a small one. Vulkan is a *fail-switch* — what a
machine without AVX2 falls back to, not an upgrade an AVX2 machine is
promoted into. Taking over a GPU for a background advisor on a server
that is doing something else is a bigger imposition than the feature
is worth.

The floor is **six physical cores and 8 GiB of RAM** — an AMD Ryzen 5
2600 (Zen+, 2018) or Intel Core i5-8400 (Coffee Lake, 2017) and
upward. Cores are counted physically, not logically: hyperthreads share
the vector units this work is bound by, so counting twelve threads on a
six-core chip and sizing a pool from it produces contention rather than
throughput.

One thing worth knowing if you are matching Intel parts by age: AVX-512
support is not monotonic. Skylake-X, Ice Lake and Rocket Lake have it;
Alder Lake and everything after ship with it fused off on consumer
chips. So a newer Intel CPU can land a tier below an older one, and
that is correct rather than a detection bug — the tier comes from
probing features, never from a model name.

**Measured performance.** Passing the hardware gate only earns the
right to be timed. A real generation is run and held to a throughput
floor; anything below it switches the layer off for that session. This
is what catches a VM whose CPUID advertises AVX-512 that the hypervisor
emulates slowly, which no amount of static detection can see.

Two cores are always held back and inference threads are capped at
four, so the advisor cannot saturate a machine whose actual job is
serving requests.

If either gate fails, self-healing runs its deterministic rules and
says so. That is not a degraded mode; it is the same feature.

## Installing it

The subpackage:

```
sudo dnf install fossh-selfheal
```

Ollama is **not** packaged for Fedora or EPEL and is deliberately not a
dependency — naming an unavailable package would make the subpackage
uninstallable. Install it yourself from
<https://ollama.com/download>, then pull the base model and build
foSSH's own:

```
ollama pull lfm2.5-thinking:1.2b
ollama create fossh-advisor:0.2.0 -f /usr/share/fossh/model/Modelfile
```

Without Ollama, the endpoint is simply unreachable and foSSH reports
that plainly while continuing to work.

### Why there is a second `ollama create` step

foSSH does not call the base model. It calls `fossh-advisor`, a derived
model built from it by the Modelfile this package installs, and the
difference is not cosmetic.

The rule that the model must never propose a fix is a security property
of this subsystem. Baked into the model as a `SYSTEM` message, it
survives a caller that forgets to send it; sent per request, it does
not. The same Modelfile carries a worked example of the shape a good
answer takes, a hard cap on reply length, sampling parameters chosen
for "restate a known fact accurately" rather than for open-ended chat,
a thread count matching the reservation described above, and a stop
sequence that drops the model's own reasoning trace before it can reach
an operator's screen.

It is versioned alongside foSSH for the same reason: an install running
0.2.0 against a tag built from an older Modelfile would differ in
behaviour with nothing to point at.

## How the endpoint is kept closed

Ollama binds loopback, which keeps the network out. It does not keep
*other local accounts* out: any unprivileged user on the machine can
connect to it and use the model freely, which on a shared host is a
real resource-exhaustion path.

So `fossh-selfheal` installs an Apache configuration
(`/etc/httpd/conf.d/fossh-model.conf`) that puts the endpoint behind a
per-install secret: 256 bits from `/dev/urandom`, generated once by the
package's own `%post`. It listens on `127.0.0.1` on its own port,
distinct from Ollama's, so the two cannot be confused in a `netstat`
listing or a firewall rule. It writes no access log, because request
bodies are prompts.

Two details of that secret file are load-bearing and neither is
obvious. It is owned `root:apache` at mode `0640`, with `fossh-svc`
added to the `apache` group — Apache runs as `apache` and foSSH's own
helper as `fossh-svc`, and a file readable by only one of them leaves
the endpoint either permanently unreachable or entirely unguarded.
Neither account can arrange that for itself, which is why the package
does it. And it is written with **no trailing newline**: Apache's
`file()` function returns the bytes verbatim, so a secret written with
`echo` would compare as `"abc\n"` against a header of `"abc"` and deny
every request forever while the configuration read as correct.

Separately, the model's configuration — which model, which endpoint,
how many threads — is written to an OpenPGP-clearsigned manifest signed
by a key generated at random on first run. That signature is verified
before the advisory layer is used at all, so an edited endpoint, a
swapped model, or a thread count raised until the box is saturated all
fail the check. Failing it disables the advisory layer and nothing
else.

Verification parses `gpg --status-fd` output rather than trusting the
exit code, because `gpg` exits 0 for a good signature from a revoked or
expired key.

## Turning it off

Uninstalling `fossh-selfheal` removes the model layer and changes
nothing about what foSSH diagnoses or repairs.

```
sudo dnf remove fossh-selfheal
```
