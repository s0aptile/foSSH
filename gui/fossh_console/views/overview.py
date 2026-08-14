"""The first thing the console shows: is this install healthy, and what
did it see today.

Everything on this page is a glance, not a report. Nothing here takes a
parameter, nothing here needs a decision, and the numbers are
deliberately today-only — the Telemetry page is where a real question
gets asked.
"""

from __future__ import annotations

from gi.repository import Adw, GLib, Gtk

from ..agent import AgentError
from ..iconography import symbolic_name
from ..widgets import StatTile, StatusRow, pad, section


class OverviewView(Gtk.Box):
    def __init__(self, agent) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self._agent = agent
        self._loaded_once = False

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(250)
        self._stack.set_vexpand(True)
        self.append(self._stack)

        self._stack.add_named(self._build_loading(), "loading")
        self._stack.add_named(self._build_content(), "content")
        self._stack.add_named(self._build_empty(), "empty")
        self._error_page = Adw.StatusPage(
            icon_name=symbolic_name("warning"),
            title="Could not read this install",
        )
        self._stack.add_named(self._error_page, "error")
        self._stack.set_visible_child_name("loading")

    # -- construction ------------------------------------------------

    def _build_loading(self) -> Gtk.Widget:
        # A centred spinner, not a skeleton: this load is normally
        # under a hundred milliseconds, and a skeleton that flashes is
        # worse than a spinner that barely appears.
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER)
        box.append(Adw.Spinner(width_request=32, height_request=32))
        return box

    def _build_empty(self) -> Gtk.Widget:
        page = Adw.StatusPage(
            icon_name=symbolic_name("empty"),
            title="No sites yet",
            description=(
                "A site is what foSSH counts against. Create one and it will get its own "
                "write key and its own numbers; one install can hold as many as you like."
            ),
        )
        hint = Gtk.Label(label="fossh site create my-site --allow pageview")
        hint.add_css_class("mono")
        hint.add_css_class("card-surface")
        hint.set_selectable(True)
        # Margins stand in for padding: a Gtk.Label has no padding
        # property, and wrapping it in a box for twelve pixels would be
        # a widget that exists for nothing.
        pad(hint, top=12, bottom=12, start=16, end=16)
        page.set_child(hint)
        return page

    def _build_content(self) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        pad(outer, top=24, bottom=32, start=24, end=24)

        clamp = Adw.Clamp(maximum_size=900, child=outer)
        scroller.set_child(clamp)

        # -- today's figures
        today = section("Today", "Since midnight, across every site on this install.")
        tiles = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12, homogeneous=True)
        self._hits = StatTile("Events", with_sparkline=True)
        self._uniques = StatTile("Visitors", with_sparkline=True)
        self._sites = StatTile("Sites")
        tiles.append(self._hits)
        tiles.append(self._uniques)
        tiles.append(self._sites)
        today.append(tiles)
        outer.append(today)

        # -- health
        health = section("Health")
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        # No margins here: `.card-surface` carries its own padding, and
        # adding margins as well would inset the card away from the
        # tiles above it.
        card.add_css_class("card-surface")

        self._watchdog_row = StatusRow("Watchdog")
        self._tamper_row = StatusRow("Tamper detection")
        card.append(self._watchdog_row)
        separator = Gtk.Box()
        separator.add_css_class("hairline")
        card.append(separator)
        card.append(self._tamper_row)

        self._health_note = Gtk.Label(xalign=0)
        self._health_note.add_css_class("caption")
        self._health_note.set_wrap(True)
        self._health_note.set_visible(False)
        card.append(self._health_note)

        health.append(card)
        outer.append(health)

        # -- per-site table
        sites_section = section("Sites")
        self._site_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self._site_list.add_css_class("boxed-list")
        sites_section.append(self._site_list)
        outer.append(sites_section)

        return scroller

    # -- data --------------------------------------------------------

    def refresh(self) -> None:
        if not self._loaded_once:
            self._stack.set_visible_child_name("loading")
        self._agent.call(
            "telemetry.summary",
            on_ok=self._on_summary,
            on_err=self._on_summary_error,
        )
        # Fired separately and never awaited: against an absent watchdog
        # this waits out a real multi-second QUIC timeout, and the rest
        # of the page has no reason to sit behind it.
        self._agent.call(
            "watchdog.status",
            on_ok=self._on_watchdog,
            on_err=self._on_watchdog_error,
        )

    def _on_summary(self, result: dict) -> None:
        sites = result.get("sites", [])
        self._loaded_once = True

        if not sites:
            self._stack.set_visible_child_name("empty")
            return

        total_hits = sum(s.get("hits_today", 0) for s in sites)
        total_uniques = sum(s.get("uniques_today", 0) for s in sites)

        self._hits.set_value(total_hits)
        self._uniques.set_value(total_uniques)
        self._sites.set_value(len(sites))

        # The sparkline shows this install's sites ranked by volume —
        # a real shape drawn from real values, not a fabricated time
        # series. Per-hour history would need a query per site and is
        # what the Telemetry page is for.
        self._hits.set_series(sorted((float(s.get("hits_today", 0)) for s in sites), reverse=True))
        self._uniques.set_series(
            sorted((float(s.get("uniques_today", 0)) for s in sites), reverse=True)
        )

        self._site_list.remove_all()
        for site in sorted(sites, key=lambda s: s.get("hits_today", 0), reverse=True):
            self._site_list.append(self._site_row(site))

        self._stack.set_visible_child_name("content")

    def _site_row(self, site: dict) -> Gtk.Widget:
        row = Adw.ActionRow(title=GLib.markup_escape_text(site.get("slug", "?")))

        states = []
        if site.get("disabled"):
            states.append("disabled")
        states.append("public" if site.get("public") else "private")
        allowed = site.get("allowlist") or []
        if allowed:
            states.append(", ".join(allowed[:4]) + ("…" if len(allowed) > 4 else ""))
        row.set_subtitle(GLib.markup_escape_text(" · ".join(states)))

        figures = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
        for value, caption in (
            (site.get("hits_today", 0), "events"),
            (site.get("uniques_today", 0), "visitors"),
        ):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            column.set_valign(Gtk.Align.CENTER)
            number = Gtk.Label(label=f"{value:,}", xalign=1)
            number.add_css_class("numeric")
            label = Gtk.Label(label=caption, xalign=1)
            label.add_css_class("caption")
            column.append(number)
            column.append(label)
            figures.append(column)
        row.add_suffix(figures)

        if site.get("disabled"):
            row.add_css_class("dim")
        return row

    def _on_summary_error(self, error: AgentError) -> None:
        self._error_page.set_title(
            "This install has no data directory yet"
            if error.is_unavailable
            else "Could not read this install"
        )
        self._error_page.set_description(error.message)
        self._stack.set_visible_child_name("error")

    def _on_watchdog(self, result: dict) -> None:
        child = result.get("child")
        tamper = result.get("tamper")

        if child == "running":
            self._watchdog_row.set_state("ok", "supervising")
        elif child == "stopped":
            self._watchdog_row.set_state("warn", "not supervising")
        else:
            self._watchdog_row.set_state("idle", "unknown")

        if tamper == "clean":
            self._tamper_row.set_state("ok", "clean")
        elif tamper == "tampered":
            self._tamper_row.set_state("bad", "tampered")
        else:
            self._tamper_row.set_state("idle", "not checked")
        self._health_note.set_visible(False)

    def _on_watchdog_error(self, error: AgentError) -> None:
        # Not an error state on screen. On EPEL and RHEL the watchdog
        # subpackage does not exist at all, and on a fresh install it
        # simply has not been started yet — both are ordinary, and
        # showing them in red would be false alarm.
        self._watchdog_row.set_state("idle", "unreachable")
        self._tamper_row.set_state("idle", "unavailable")
        self._health_note.set_text(error.message)
        self._health_note.set_visible(True)
