"""Ask a real question of one site's numbers.

This page's one unusual job is explaining k-anonymity honestly. On a
low-traffic site most breakdowns come back as a single `(other)` row,
and that is foSSH working exactly as designed — the store folds any
group under the threshold before it ever reaches a caller. An interface
that showed that as an empty chart would teach operators that the
product is broken; one that showed it as a warning would teach them
that privacy is a problem. So it is stated plainly, as information,
with the three real ways to get detail back.
"""

from __future__ import annotations

import time

from gi.repository import Adw, GLib, Gtk

from ..agent import AgentError
from ..iconography import symbolic_name
from ..motion import Duration

GROUP_FIELDS = [
    ("path", "Page"),
    ("kind", "Event kind"),
    ("name", "Event name"),
    ("country", "Country"),
    ("browser", "Browser"),
    ("os", "Operating system"),
    ("device", "Device"),
]

RANGES = [
    ("Today", 1),
    ("Last 7 days", 7),
    ("Last 30 days", 30),
    ("Last 90 days", 90),
]

class TelemetryView(Gtk.Box):
    def __init__(self, agent) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL)
        self.add_css_class("content-canvas")
        self._agent = agent
        self._sites: list[str] = []
        self._k = 5

        toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        toolbar.set_margin_top(16)
        toolbar.set_margin_bottom(16)
        toolbar.set_margin_start(24)
        toolbar.set_margin_end(24)

        self._site_dropdown = Gtk.DropDown.new_from_strings(["—"])
        self._site_dropdown.set_tooltip_text("Which site to report on")

        self._site_dropdown.connect("notify::selected", self._on_site_changed)

        self._range_dropdown = Gtk.DropDown.new_from_strings([label for label, _ in RANGES])
        self._range_dropdown.set_tooltip_text("How far back to look")
        self._range_dropdown.connect("notify::selected", lambda *_: self._run_query())

        self._group_dropdown = Gtk.DropDown.new_from_strings([label for _, label in GROUP_FIELDS])
        self._group_dropdown.set_tooltip_text("How to break the numbers down")
        self._group_dropdown.connect("notify::selected", lambda *_: self._run_query())

        for widget in (self._site_dropdown, self._range_dropdown, self._group_dropdown):
            toolbar.append(widget)

        spacer = Gtk.Box(hexpand=True)
        toolbar.append(spacer)

        check = Gtk.Button(label="Verify integration")
        check.set_tooltip_text(
            "Load one of your pages in a real browser and see whether foSSH receives the event"
        )
        check.connect("clicked", lambda *_: self._open_verify())
        toolbar.append(check)

        refresh = Gtk.Button(icon_name=symbolic_name("refresh"))
        refresh.set_tooltip_text("Refresh (Ctrl+R)")
        refresh.add_css_class("flat")
        refresh.connect("clicked", lambda *_: self.refresh())
        toolbar.append(refresh)

        self.append(toolbar)

        self._stack = Gtk.Stack()
        self._stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self._stack.set_transition_duration(Duration.STANDARD)
        self._stack.set_vexpand(True)
        self.append(self._stack)

        loading = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, valign=Gtk.Align.CENTER)
        loading.append(Adw.Spinner(width_request=32, height_request=32))
        self._stack.add_named(loading, "loading")

        self._results_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self._results_box.set_margin_start(24)
        self._results_box.set_margin_end(24)
        self._results_box.set_margin_bottom(32)
        scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER)
        scroller.set_child(Adw.Clamp(maximum_size=900, child=self._results_box))
        self._stack.add_named(scroller, "results")

        self._message_page = Adw.StatusPage()
        self._stack.add_named(self._message_page, "message")
        self._stack.set_visible_child_name("loading")

    def _open_verify(self) -> None:
        from .verify_dialog import VerifyDialog

        VerifyDialog().present(self)

    def refresh(self) -> None:
        self._agent.call(
            "telemetry.summary",
            on_ok=self._on_sites,
            on_err=self._on_error,
        )

    def _on_sites(self, result: dict) -> None:
        self._k = result.get("k_anonymity", 5)
        sites = [s.get("slug", "?") for s in result.get("sites", [])]
        if not sites:
            self._show_message(
                symbolic_name("empty"),
                "No sites yet",
                "Create a site first — there is nothing to report on until then.",
            )
            return

        if sites != self._sites:
            self._sites = sites
            model = Gtk.StringList.new(sites)

            self._site_dropdown.handler_block_by_func(self._on_site_changed)
            self._site_dropdown.set_model(model)
            self._site_dropdown.set_selected(0)
            self._site_dropdown.handler_unblock_by_func(self._on_site_changed)

        self._run_query()

    def _on_site_changed(self, *_args) -> None:
        self._run_query()

    def _selected_site(self) -> str | None:
        index = self._site_dropdown.get_selected()
        if index == Gtk.INVALID_LIST_POSITION or index >= len(self._sites):
            return None
        return self._sites[index]

    def _run_query(self) -> None:
        site = self._selected_site()
        if site is None:
            return
        days = RANGES[min(self._range_dropdown.get_selected(), len(RANGES) - 1)][1]
        field = GROUP_FIELDS[min(self._group_dropdown.get_selected(), len(GROUP_FIELDS) - 1)][0]

        now = int(time.time())
        start_of_today = now - (now % 86_400)
        frm = start_of_today - (days - 1) * 86_400

        self._stack.set_visible_child_name("loading")
        self._agent.call(
            "telemetry.query",
            {"site": site, "from": frm, "to": now, "group_by": [field]},
            on_ok=self._on_rows,
            on_err=self._on_error,
        )

    def _on_rows(self, result: dict) -> None:
        rows = result.get("rows", [])
        k = result.get("k_anonymity", self._k)

        child = self._results_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._results_box.remove(child)
            child = nxt

        if not rows:
            self._show_message(
                symbolic_name("no_results"),
                "Nothing in this range",
                "No events were recorded for this site over the period you picked. "
                "Try a wider range.",
            )
            return

        if result.get("entirely_folded"):
            self._results_box.append(self._folded_notice(k))

        total_hits = sum(r.get("hits", 0) for r in rows)
        self._results_box.append(self._table(rows, total_hits))
        self._stack.set_visible_child_name("results")

    def _folded_notice(self, k: int) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        box.add_css_class("privacy-note")
        box.set_margin_top(16)

        title = Gtk.Label(xalign=0)
        title.set_markup(
            f"<b>Every group here was folded into “(other)”.</b>"
        )
        title.set_wrap(True)

        body = Gtk.Label(xalign=0)
        body.set_text(
            f"That is foSSH working, not a fault: any group with fewer than {k} estimated "
            f"visitors is folded before it reaches this window, so no breakdown can single "
            f"anyone out. The totals themselves are unaffected. To get detail back, widen the "
            f"range so more traffic accumulates, group by something coarser — country folds "
            f"far less than page on the same traffic — or lower k_anonymity in fossh.toml, "
            f"which is a real privacy trade to make deliberately."
        )
        body.set_wrap(True)

        box.append(title)
        box.append(body)
        return box

    def _table(self, rows: list[dict], total_hits: int) -> Gtk.Widget:
        listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        listbox.add_css_class("boxed-list")

        for row in sorted(rows, key=lambda r: r.get("hits", 0), reverse=True):
            dims = row.get("dims", [])
            label = " · ".join(str(value) for _field, value in dims) if dims else "all"
            action_row = Adw.ActionRow(title=GLib.markup_escape_text(label))
            if label == "(other)":
                action_row.set_subtitle("groups below the k-anonymity threshold, combined")

            figures = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=24)
            figures.set_valign(Gtk.Align.CENTER)
            for value, caption in (
                (row.get("hits", 0), "events"),
                (row.get("uniques", 0), "visitors"),
            ):
                column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
                number = Gtk.Label(label=f"{value:,}", xalign=1)
                number.add_css_class("numeric")
                caption_label = Gtk.Label(label=caption, xalign=1)
                caption_label.add_css_class("caption")
                column.append(number)
                column.append(caption_label)
                figures.append(column)

            share = Gtk.ProgressBar()
            share.set_valign(Gtk.Align.CENTER)
            share.set_size_request(120, -1)
            largest = max((r.get("hits", 0) for r in rows), default=0) or 1
            share.set_fraction(min(1.0, row.get("hits", 0) / largest))
            figures.append(share)

            action_row.add_suffix(figures)
            listbox.append(action_row)

        wrapper = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        wrapper.set_margin_top(16)
        summary = Gtk.Label(xalign=0)
        summary.add_css_class("caption")
        summary.set_text(f"{total_hits:,} events across {len(rows)} group(s)")
        wrapper.append(listbox)
        wrapper.append(summary)
        return wrapper

    def _show_message(self, icon: str, title: str, description: str) -> None:
        self._message_page.set_icon_name(icon)
        self._message_page.set_title(title)
        self._message_page.set_description(description)
        self._stack.set_visible_child_name("message")

    def _on_error(self, error: AgentError) -> None:
        self._show_message(
            symbolic_name("warning"),
            "That query could not be run" if not error.is_unavailable else "Not available yet",
            error.message,
        )
