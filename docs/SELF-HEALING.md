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

`fossh-selfheal` adds a local language model — `lfm2.5-thinking`,
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

**Hardware.** The model runs entirely on the **CPU** — `num_gpu: 0` is
set on every request. It has to work on machines with no GPU, and
quietly claiming one on machines that have it would be taking a
resource the operator bought for something else.

The instruction set decides the tier: AVX is the floor, AVX2 is the
ordinary case, AVX-512 is used where present. The runtime selects the
matching backend itself.

| | Minimum |
|---|---|
| Processor | 4 physical cores with AVX2 — Intel Core i7-6700K (2015) or AMD Ryzen 5 1500X (2017), or later |
| Memory | 8 GiB |
| Storage | 32 GiB free; a mechanical disk is sufficient, solid state recommended for the install generally |

Cores are counted physically, not logically: hyperthreads share the
vector units this work is bound by. Two cores are always held back and
inference threads are capped at four — six threads measured no faster
than four (75.6 against 76.5 tokens/second), so the extra two would be
taken from the machine's real work for nothing.

One thing worth knowing if you are matching Intel parts by age:
AVX-512 support is not monotonic. Skylake-X, Ice Lake and Rocket Lake
have it; Alder Lake and later ship it fused off on consumer chips. So
a newer Intel CPU can land a tier below an older one, and that is
correct rather than a detection bug — the tier comes from probing
features, never from a model name.


**Measured performance.** Passing the hardware gate only earns the
right to be timed. A real generation is run and held to two limits,
and failing either switches the layer off for that session:

- **Time to first token: 1.7 seconds.** A background advisor that
  makes an operator wait has already cost more than it is worth.
- **Throughput: 38.5 tokens/second.**

Measured on a Ryzen 5 8400F, CPU only, four threads: **0.171 s** to
first token and **75.7 tokens/second** — roughly ten times the latency
margin and twice the throughput the gate requires.

That measurement is taken on the *warm* path, and the reason matters.
Cold, the first token takes 1.626 s — inside the 1.7 s ceiling by
seventy milliseconds, which is not a margin to build on. Warm it takes
0.097 s. So the model is kept resident and warmed once at startup,
because the warm path is the only one a real request ever takes.

Timing also catches what no feature bit can: a virtual machine whose
CPUID advertises AVX-512 that the hypervisor emulates slowly looks
perfect to static detection and fails here.


If either gate fails, self-healing runs its deterministic rules and
says so. That is not a degraded mode; it is the same feature.

## Installing it

The subpackage:

```
sudo dnf install fossh-selfheal
```

The subpackage's `%pre` creates a `fossh-selfheal` group, and the
scheduled tick (running as `fossh-svc`) reaches its runtime directory
as that directory's owner already — but a human running the console is
neither, and needs to join the group to hold the same exclusivity lock
the scheduled tick does:

```
sudo usermod -a -G fossh-selfheal $USER
```

Log out and back in for the new group membership to take effect —
`usermod` does not change a session already in progress. Skipping this
step does not break anything visibly: the console silently falls back
to a lock that excludes nothing the scheduled tick's own lock does,
and Hellen's Eye never actually runs.

Hellen's Eye is a second, separate model — `qwen3.5:4b`, run with
reasoning disabled per request, invoked only when you explicitly
submit a screenshot for it to read, never automatically. An earlier
base model for this role had a real, open defect (an adversarial image
could talk it into naming itself, and several others locked it into a
non-converging reasoning loop) that was fixed by switching models
rather than tuning around it — see `THREAT_MODEL.md`, "Explicitly not
defended against," item 7, for the full history and verification.

Ollama is **not** packaged for Fedora or EPEL and is deliberately not a
dependency — naming an unavailable package would make the subpackage
uninstallable. Install it yourself from
<https://ollama.com/download>, then pull the base model and build
foSSH's own:

```
ollama pull lfm2.5-thinking
ollama create fossh-advisor:0.0.2.2 -f /usr/share/fossh/model/Modelfile
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
answer takes, a token budget sized for this model's own reasoning
trace rather than just its reply, and sampling parameters chosen for
"restate a known fact accurately" rather than for open-ended chat.

The reasoning trace itself never reaches an operator's screen, but not
because generation is cut short at it — an earlier version tried that
with a stop sequence, which halts generation at the reasoning/reply
boundary and produces no reply at all, measured on every single test
call. Ollama's chat API separates `message.thinking` from
`message.content` on its own for a model with this capability; the
console only ever reads the latter.

It is versioned alongside foSSH for the same reason: an install running
0.0.2.1 against a tag built from an older Modelfile would differ in
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
