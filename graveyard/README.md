# Graveyard

Retired releases. Nothing here is supported, nothing here should be
installed, and nothing here is a reference for how foSSH works.

It exists because deleting a release outright is worse than burying it:
someone will eventually need to know what a retired version actually
did — to reproduce a bug report from it, to check whether a defect
predates a rewrite, or to confirm what a claim in an old document was
based on. A version that has simply vanished cannot answer any of
those.

## What is buried here

| Release | Buried | Tag | Why |
|---|---|---|---|
| `0.1.0_oa` – `0.1.2_oa` | source, via the tag below | — | Superseded by 0.1.3 before retirement; no separate artifact was kept. |
| `0.1.3_oa` | `0.1.3_oa/fossh-0.1.3_oa-source.tar.gz` | `v0.1.3_oa-retired` | The last of the 0.1.x line. See `../RETIREMENT.md`. |

The archive is a `git archive` of the retirement tag, so it is the
exact tree that release was built from — not a reconstruction. Its
SHA-256 is in `0.1.3_oa/SHA256SUMS`.

Built binaries and RPMs from the 0.1.x line are **not** kept. They
carried the build machine's username and hostname in their package
metadata (see `../RETIREMENT.md`), which is reason enough not to
preserve copies of them, and they can be rebuilt from the source
archive by anyone who genuinely needs one.

## Why 0.1.x is retired rather than merely superseded

The short version, in full in `../RETIREMENT.md`: the watchdog could
not start outside a systemd unit and reported something misleading when
it failed; three cross-language interop tests had been failing while
the project's own status file recorded them as passing; and the CI
configuration contained a syntax error meaning it had, on the evidence,
never once run.

None of that was found by a user. It was found by testing the tree
before 0.0.2.1, which is why the whole line was retired instead of
quietly superseded.

## Recovering a retired release

```
tar xzf graveyard/0.1.3_oa/fossh-0.1.3_oa-source.tar.gz
```

Or straight from git, which is the same tree:

```
git archive --prefix=fossh-0.1.3_oa/ v0.1.3_oa-retired | tar x
```

If you build it, be aware that the defects listed above are present. In
particular the watchdog will refuse to supervise anything unless it is
running as root, and will not tell you that is the reason.

## Adding to the graveyard

When a release is retired:

1. Tag its final commit `v<version>-retired`.
2. `git archive --format=tar.gz --prefix=fossh-<version>/ -o graveyard/<version>/fossh-<version>-source.tar.gz v<version>-retired`
3. `sha256sum` it into `graveyard/<version>/SHA256SUMS`.
4. Add a row to the table above and an entry to `../RETIREMENT.md`
   saying what was actually wrong, not just that it is old.

Step 4 is the one worth doing properly. A graveyard of version numbers
with no causes is a list; a graveyard that records what went wrong is
something the next release can learn from.
