"""The first thing the console shows: is this install healthy, and what
did it see today.

Everything on this page is a glance, not a report. Nothing here takes a
parameter, nothing here needs a decision, and the numbers are
deliberately today-only — the Telemetry page is where a real question
gets asked.
"""

from __future__ import annotations

from gi.repository import Adw, GLib, Gtk

from ..advisor_bridge import AdvisorBridge
from ..agent import AgentError
from ..iconography import symbolic_name
from ..widgets import StatTile, StatusRow, pad, section

_SEVERITY_STATE = {"critical": "bad", "warning": "warn", "info": "idle"}

class OverviewView(Gtk.Box):
    def __init__(self, agent, advisor: AdvisorBridge) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.add_css_class("content-canvas")
        self._agent = agent
        self._advisor = advisor
        self._loaded_once = False
        self._finding_rows: dict[str, Adw.ExpanderRow] = {}
        self._advice_labels: dict[str, Gtk.Label] = {}
        self._explaining: set[str] = set()

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

    def _build_loading(self) -> Gtk.Widget:

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

        pad(hint, top=12, bottom=12, start=16, end=16)
        page.set_child(hint)
        return page

    def _build_content(self) -> Gtk.Widget:
        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        pad(outer, top=24, bottom=32, start=24, end=24)

        clamp = Adw.Clamp(maximum_size=900, child=outer)
        scroller.set_child(clamp)

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

        health = section("Health")
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)

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

        self._health_card = card
        health.append(card)
        outer.append(health)

        self._findings_section = section("Findings")
        self._findings_section.set_visible(False)
        self._findings_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self._findings_list.add_css_class("boxed-list")
        self._findings_section.append(self._findings_list)
        outer.append(self._findings_section)

        sites_section = section("Sites")
        self._site_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self._site_list.add_css_class("boxed-list")
        sites_section.append(self._site_list)
        outer.append(sites_section)

        return scroller

    def refresh(self) -> None:
        if not self._loaded_once:
            self._stack.set_visible_child_name("loading")
        self._agent.call(
            "telemetry.summary",
            on_ok=self._on_summary,
            on_err=self._on_summary_error,
        )

        self._agent.call(
            "watchdog.status",
            on_ok=self._on_watchdog,
            on_err=self._on_watchdog_error,
        )

        self._agent.call(
            "selfheal.check",
            on_ok=self._on_selfheal,
            on_err=self._on_selfheal_error,
        )

    def _on_selfheal(self, result: dict) -> None:
        findings = result.get("findings", [])
        self._findings_list.remove_all()
        self._finding_rows.clear()
        self._advice_labels.clear()
        self._findings_section.set_visible(bool(findings))

        for finding in findings:
            row = self._finding_row(finding)
            self._findings_list.append(row)
            self._finding_rows[finding["id"]] = row

            if finding.get("severity") != "info" and finding["id"] not in self._explaining:
                self._request_advice(finding)

    def _on_selfheal_error(self, error: AgentError) -> None:

        self._findings_section.set_visible(False)

    def _finding_row(self, finding: dict) -> Adw.ExpanderRow:
        row = Adw.ExpanderRow(
            title=GLib.markup_escape_text(finding["title"]),
            subtitle=finding.get("severity", "info"),
        )
        dot = Gtk.Box(valign=Gtk.Align.CENTER)
        dot.add_css_class("status-dot")
        dot.add_css_class(_SEVERITY_STATE.get(finding.get("severity"), "idle"))
        row.add_prefix(dot)

        detail = Gtk.Label(
            label=finding.get("detail", ""), xalign=0, wrap=True, selectable=True
        )
        pad(detail, top=8, bottom=8, start=16, end=16)
        row.add_row(detail)

        remedy = finding.get("remedy") or {}
        remedy_text = remedy.get("description") or ""
        command = remedy.get("command")
        if remedy_text:
            remedy_label = Gtk.Label(
                label=f"Remedy: {remedy_text}", xalign=0, wrap=True, selectable=True
            )
            remedy_label.add_css_class("caption")
            pad(remedy_label, bottom=8 if not command else 0, start=16, end=16)
            row.add_row(remedy_label)
        if command:
            command_label = Gtk.Label(label=command, xalign=0, selectable=True)
            command_label.add_css_class("mono")
            pad(command_label, bottom=8, start=16, end=16)
            row.add_row(command_label)

        advice = Gtk.Label(xalign=0, wrap=True, selectable=True)
        advice.add_css_class("caption")
        advice.set_visible(False)
        pad(advice, bottom=8, start=16, end=16)
        row.add_row(advice)
        self._advice_labels[finding["id"]] = advice

        return row

    def _request_advice(self, finding: dict) -> None:
        self._explaining.add(finding["id"])
        prompt = (
            f"Diagnostic: {finding['title']}\n"
            f"Severity: {finding.get('severity', 'info')}\n"
            f"Detail: {finding.get('detail', '')}"
        )

        def _ok(answer: str, finding_id: str = finding["id"]) -> None:
            self._explaining.discard(finding_id)
            label = self._advice_labels.get(finding_id)
            if label is None:
                return
            label.set_text(answer)
            label.set_visible(bool(answer.strip()))

        def _err(_exc: Exception, finding_id: str = finding["id"]) -> None:

            self._explaining.discard(finding_id)

        self._advisor.explain_async(prompt, on_ok=_ok, on_err=_err)

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

        self._set_alarmed(tamper == "tampered" or child == "stopped")

    def _set_alarmed(self, alarmed: bool) -> None:
        if alarmed:
            self._health_card.add_css_class("alarmed")
        else:
            self._health_card.remove_css_class("alarmed")

    def _on_watchdog_error(self, error: AgentError) -> None:

        self._set_alarmed(False)
        self._watchdog_row.set_state("idle", "unreachable")
        self._tamper_row.set_state("idle", "unavailable")
        self._health_note.set_text(error.message)
        self._health_note.set_visible(True)
