# Deploying foSSH on Fedora Atomic / ostree-based systems

Fedora Silverblue, Kinoite, Fedora CoreOS, and other `rpm-ostree`-based
("Atomic") systems don't have a mutable base OS — there's no `dnf
install` against the running root filesystem, `/usr` is read-only after
boot, and packages get added by *layering* them onto the next boot's
ostree deployment instead. This guide is the `rpm-ostree` equivalent of
`docs/PACKAGING-copr.md`'s installation instructions, not a separate
deployment shape — it's the same `fossh` RPM built the same way on the
same Copr project, installed through ostree's own mechanism instead of
a plain `dnf install`.

**Status: written from reading `packaging/rpm/fossh.spec` and this
project's systemd units directly, not from a real `rpm-ostree install`
run against a live Silverblue/CoreOS box.** Everything below that's
general ostree behavior (package layering, reboot-to-apply, `/etc`
and `/var` being mutable and persistent) is well-established and not
specific to this package. The parts that are specific to `fossh` —
whether its `%post` scriptlet (which does more than the usual
`useradd`/`chown`, see "What actually happens during layering" below)
behaves identically inside `rpm-ostree`'s layering sandbox as it does
in a normal `dnf install` — are flagged explicitly as unverified where
they come up, not glossed over as confirmed.

## 0. Prerequisites

- A Fedora Atomic variant (Silverblue, Kinoite, Fedora CoreOS, or
  similar) with `rpm-ostree` — check `rpm-ostree --version`.
- The `s0aptile/fossh` Copr project actually has a successful build for
  the chroot matching your system before any of this is worth trying.
  As of this writing that's Fedora only (`fedora-44-x86_64`,
  `fedora-rawhide-x86_64`) — see `docs/PACKAGING-copr.md`'s "EPEL/RHEL-
  family build status" for why the EPEL/RHEL-family chroots don't have
  one yet. Fedora CoreOS and Fedora Silverblue/Kinoite both track
  Fedora releases, not EPEL, so this isn't a blocker for them
  specifically — it would matter for a hypothetical CentOS/RHEL-based
  Atomic variant, which isn't in scope here.

## 1. Add the Copr repo

There's no `dnf copr enable` on the host here — Atomic variants don't
ship a functional host-level `dnf` at all (`rpm-ostree` has its own
package-resolution backend; `dnf` still exists inside `toolbox`
containers, but that's a separate mutable environment with no bearing
on the host's own package set). `dnf copr enable` on a normal system
does nothing more exotic than fetching a `.repo` file from Copr and
dropping it into `/etc/yum.repos.d/` — do that step directly instead:

```
sudo curl -Lo /etc/yum.repos.d/_copr_s0aptile-fossh.repo \
  https://copr.fedorainfracloud.org/coprs/s0aptile/fossh/repo/fedora-$(rpm -E %fedora)/s0aptile-fossh-fedora-$(rpm -E %fedora).repo
```

(`rpm -E %fedora` resolves to your actual Fedora release number, e.g.
`44` — confirmed this expands correctly on ostree systems too, since
`rpm -E` only reads local macro state, not package-manager state.)
`/etc/yum.repos.d/` is ordinary `/etc` — mutable, and part of ostree's
persistent, 3-way-merged `/etc` that carries across deployments and
upgrades, the same as any other config file you drop there. This step
is genuinely no different on an Atomic system than dropping the same
file on Fedora Server; the difference starts at the next step.

## 2. Layer the package

```
sudo rpm-ostree install fossh
```

This resolves `fossh` (and its `Requires:` — `fcgiwrap`, `gnupg2`, the
`user()`/`group()` provides from `%pre`'s `useradd`, all the same
dependency graph `dnf install` would resolve) against the repo added in
step 1, downloads it, and layers it onto a **new** ostree deployment —
it does not touch the currently-booted one. `rpm-ostree status` shows
the new deployment queued, not yet active.

## 3. Reboot to apply

```
sudo systemctl reboot
```

This is ostree's own model, not something foSSH-specific or something
this packaging could avoid — a layered package never takes effect on
the already-booted deployment; you're switching to the new deployment
that has it, and that switch only happens at boot. `rpm-ostree
apply-live` exists for testing a layered change against the *current*
boot without rebooting, but it's explicitly described in `rpm-ostree`'s
own documentation as a debugging/iteration tool, not a persistent
substitute for a real reboot — don't rely on it for anything you expect
to survive the next reboot anyway; just reboot.

After rebooting, `rpm-ostree status` shows the new deployment as
booted, and `rpm -q fossh` works normally — from here, this is a
regular, fully-booted Linux system with a read-only `/usr` and every
other Fedora convention intact; nothing about steps 4+ below is
Atomic-specific.

## 4. First-run setup

Same as the Fedora-native path documented elsewhere in this project
(README's "Deployment shapes"):
`fossh-fcgiwrap.socket` and `fossh-watchdog.service` are enabled but
not started by the package install (`%post`'s `%systemd_post`, deferred
start by design — see `fossh.spec`'s own comment on why nothing
auto-starts until the setup wizard runs). Run `fossh-console` to walk
through first-run setup and enroll an operator key, or start the
relevant unit(s) manually per your deployment shape.

## What actually happens during layering — and what's unverified

`fossh.spec`'s `%post` does more than a typical package: alongside the
standard `useradd`/`chown`/`ldconfig`/`%selinux_modules_install`
sequence (all long-established, widely-used patterns on layered
`rpm-ostree` packages — Silverblue and Kinoite both ship SELinux
enforcing by default, and layered RPMs carrying their own policy
modules are a known-working, common case, not something unusual to
this package), it also runs the package's own just-installed
`fossh-watchdog` binary to generate a real GPG keypair and a tamper-
detection manifest (`generate-manifest`, writing under
`/var/lib/fossh-watchdog/`) as part of installation itself, via
`runuser -u fossh-watchdog -- ...`. That's a heavier scriptlet action
than most packages take — actually executing freshly-installed code to
do real cryptographic key generation — and it wasn't specifically
re-verified against a real `rpm-ostree install` in this investigation
pass, only reasoned about from `rpm-ostree`'s general, documented
layering behavior:

- `/var` is ostree's persistent, deployment-independent state — not
  versioned into the ostree commit the way `/usr` is, and not reset
  between deployments the way `/etc` is 3-way-merged. Package
  scriptlets writing real files under `/var/lib/...` during layering is
  a standard, supported pattern (this is exactly how most stateful
  layered packages work), so `%post`'s directory creation and `chown`
  calls for `/var/lib/fossh` and `/var/lib/fossh-watchdog` are on solid
  ground.
- The `generate-manifest` step specifically needs `/dev/urandom`
  (real entropy, for the GPG keypair) and a working `runuser` inside
  whatever sandbox `rpm-ostree` runs `%post` scriptlets in. Both are
  ordinary requirements plenty of other packages' scriptlets also have,
  but this wasn't tested end-to-end against a real Atomic box as part
  of this pass.
- If this step *does* fail or behave differently under `rpm-ostree`'s
  layering sandbox, the failure mode this project already designed for
  is graceful, not catastrophic: `fossh.spec`'s own comment on this
  line notes it's best-effort (`|| :`, a failure here doesn't fail the
  whole package install), and `fossh-watchdog.service`'s first real
  start already refuses to launch without a valid manifest, logging a
  clear reason rather than crash-looping (see that unit file's own
  header comment and `DECISIONS.md` ADR-0061). An operator who hits
  this can always re-run `fossh-watchdog generate-manifest ...`
  manually after boot, once the service and its state directory
  actually exist as booted, not layered, filesystem state — the
  documented fail-closed behavior covers this case even if the specific
  Atomic path hasn't had a live run against it yet.

**Recommended before calling this fully verified:** an actual
`rpm-ostree install fossh` + reboot + `systemctl status
fossh-watchdog.service` run against a real Silverblue or Fedora CoreOS
box, checking specifically whether `/var/lib/fossh-watchdog/manifest.asc`
and `gnupghome/` exist and are correctly owned right after that first
boot, before this doc's guidance above is treated as anything more than
well-reasoned-but-unverified.

## systemd units and SELinux after layering — confirmed by inspection, not by a live run

Every `packaging/systemd/*.service` unit in this project uses
`ProtectSystem=strict` (and friends — `ProtectHome`, the various
`Protect*`/`Restrict*` hardening directives) with an explicit
`ReadWritePaths=` carve-out for exactly the state directories each unit
needs (`/var/lib/fossh`, `/var/lib/fossh-watchdog`, `/run/fossh`,
`/etc/fossh`, depending on the unit — see each unit's own
`ReadWritePaths=` line). On an Atomic system, `/usr` is *already*
read-only after boot, system-wide, independent of anything a unit's own
`ProtectSystem=strict` does — the two don't conflict; `ProtectSystem=
strict` bind-mounts `/usr` read-only a second time inside the unit's
own private mount namespace, which is a no-op on top of something
already read-only, not a new restriction. Every path these units
actually write to (`/var/lib/...`, `/run/fossh`, `/etc/fossh`) is
mutable on ostree the same way it is on any other Fedora system — none
of this project's own units write to `/usr` at runtime; confirmed by
reading `fossh.spec`'s `%files` list and every `ExecStart=`/
`ReadWritePaths=` line directly, not assumed. `fossh.tmpfiles.conf`
(`/run/fossh`, `/run/fossh/salt`) is standard `systemd-tmpfiles`
machinery, identical on ostree — `/run` is `tmpfs` everywhere, wiped
every real reboot regardless of the underlying root filesystem being
ostree or not.

SELinux itself: Silverblue/Kinoite ship SELinux `targeted`/enforcing by
default, same policy store location (`/etc/selinux/`, mutable, part of
ostree's persistent state) as any other Fedora variant — a layered
package's `%post` running `%selinux_modules_install` loads its policy
module into that same store the same way. This project's own SELinux
module (`packaging/selinux/fossh.te`/`.fc`, covering `fossh-cgi` only —
see `fossh-fcgi.service`'s own header comment for the tracked gap that
isn't Atomic-specific) should behave identically once loaded, for the
same reason the systemd units do: nothing about SELinux policy loading
or enforcement is different between ostree's read-only `/usr` and any
other distro's writable one — policy modules live under `/etc`, not
`/usr`. Not independently re-verified against a real enforcing Atomic
system in this pass, same caveat as the section above.

## Uninstalling / rolling back

```
sudo rpm-ostree uninstall fossh
sudo systemctl reboot
```

Same reboot-to-apply model as installing. `rpm-ostree rollback` (to the
previous deployment entirely, not just this one package) is also always
available if something about a layered `fossh` needs backing out
faster than a targeted uninstall — standard ostree recovery, nothing
foSSH-specific about it.
