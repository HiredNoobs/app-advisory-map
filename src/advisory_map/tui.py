"""advisory-map vex tui: the findings with their assessments, and a form adding a verdict on one."""

from collections import Counter
from collections.abc import Callable, Iterable
from urllib.parse import quote

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.content import Content
from textual.screen import ModalScreen
from textual.suggester import Suggester
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
)

from advisory_map import cli
from advisory_map.findings import Finding
from advisory_map.vex.openvex import JUSTIFICATIONS, STATUSES, Store, product


def _value(field: Select[str] | Input) -> str:
    """What a field holds: nothing for a Select left blank."""
    return "" if field.value is Select.NULL else str(field.value).strip()


def _key(finding: Finding) -> tuple[str, str, str, str]:
    """What a finding is, however its severity or fix changes."""
    return finding.cve, finding.target_kind, finding.target, finding.package


# Most severe first, when the table's sorted by severity.
_SEVERITIES = ("critical", "high", "medium", "low")


def _order(column: int, cell: str) -> tuple[int, str]:
    """Where a cell sorts in its column: severities by rank, the rest as text."""
    if cli.COLUMNS[column] == "SEVERITY":
        return (_SEVERITIES.index(cell) if cell in _SEVERITIES else len(_SEVERITIES)), ""
    return 0, cell.casefold()


def _matches(cells: tuple[str, ...], terms: str) -> bool:
    """Whether a row has every term: a word in any of its cells, column:value in that column's."""
    for term in terms.casefold().split():
        name, colon, value = term.partition(":")
        if colon and name.upper() in cli.COLUMNS:
            if value not in cells[cli.COLUMNS.index(name.upper())].casefold():
                return False
        elif not any(term in cell.casefold() for cell in cells):
            return False
    return True


def _ranked(cells: Iterable[str], column: int | None = None) -> list[str]:
    """A column's values (or any column's), as they're offered: severities by rank, the rest the most
    common first."""
    counts = Counter(cells)
    if column is not None and cli.COLUMNS[column] == "SEVERITY":
        return sorted(counts, key=lambda cell: _order(column, cell))
    return sorted(counts, key=lambda cell: (-counts[cell], cell.casefold()))


def complete(terms: str, rows: Iterable[tuple[str, ...]]) -> str | None:
    """The filter with its last term completed: as a column's name, then as one of that column's values,
    or as any column's value. None when there's nothing to complete."""
    if not terms.strip() or terms[-1].isspace():
        return None
    term = terms.split()[-1]
    name, colon, typed = term.partition(":")
    if colon and name.upper() in cli.COLUMNS:
        column = cli.COLUMNS.index(name.upper())
        options = _ranked((row[column] for row in rows), column)
    else:
        typed = term
        names = [f"{header.casefold()}:" for header in cli.COLUMNS]
        options = names + _ranked(cell for row in rows for cell in row)
    for option in options:
        if len(option) > len(typed) and option.casefold().startswith(typed.casefold()):
            return terms + option[len(typed) :]
    return None


class _Completer(Suggester):
    """Suggests the filter completed, from the findings as they're read."""

    def __init__(self, rows: Callable[[], Iterable[tuple[str, ...]]]) -> None:
        # The findings change as they're read again: nothing's cached. Values are completed as typed.
        super().__init__(use_cache=False, case_sensitive=True)
        self.rows = rows

    async def get_suggestion(self, value: str) -> str | None:
        return complete(value, self.rows())


class _Filter(Input):
    """The filter, Tab taking its suggestion as the right arrow does."""

    BINDINGS = [Binding("tab", "cursor_right", "Complete", show=False)]


def advisory_url(finding: Finding) -> str:
    """Where to read the finding's advisory: Debian's tracker for a Debian package (its fixes, and its
    own TEMP- IDs), cve.org for any other CVE, osv.dev for the rest (GHSA-, PYSEC-, GO-...)."""
    name = quote(finding.cve, safe="")
    if finding.source == "debian":
        return f"https://security-tracker.debian.org/tracker/{name}"
    if finding.cve.startswith("CVE-"):
        return f"https://www.cve.org/CVERecord?id={name}"
    return f"https://osv.dev/vulnerability/{name}"


# The form's fields that only one status uses, and that status.
_USED_BY = {"justification": "not_affected", "impact": "not_affected", "action": "affected"}


class Assess(ModalScreen[bool]):
    """A verdict on one finding's CVE: dismissed with True once it's saved."""

    DEFAULT_CSS = """
    Assess { align: center middle; }
    Assess > VerticalScroll {
        width: 100; max-width: 100%; height: auto; max-height: 100%;
        border: thick $primary; padding: 0 1; background: $surface;
    }
    Assess #error { color: $error; }
    Assess Horizontal { height: auto; }
    """
    BINDINGS = [("escape", "cancel", "Cancel")]

    def __init__(self, store: Store, finding: Finding, author: str) -> None:
        super().__init__()
        self.store = store
        self.finding = finding
        self.author = author

    def compose(self) -> ComposeResult:
        item = self.finding
        # Content, Text and markup=False: labels are shown as they are, never read as markup.
        scopes = [
            (Content(f"This {item.target_kind}: {item.target}"), product(item.target_kind, item.target)),
            (Content(f"Every {item.target_kind}"), product(item.target_kind)),
            (Content("Everywhere"), product()),
        ]
        with VerticalScroll():
            yield Static(f"{item.cve} in {item.package} {item.installed_version}", markup=False)
            yield Label("Applies to")
            yield Select(scopes, id="scope", allow_blank=False, value=scopes[0][1])
            yield Select([(status, status) for status in STATUSES], id="status", prompt="Status")
            yield Select(
                [(justification, justification) for justification in JUSTIFICATIONS],
                id="justification",
                prompt="Justification",
            )
            yield Input(placeholder="Impact statement: why it's not affected", id="impact")
            yield Input(placeholder="Action statement: what to do about it", id="action")
            yield Input(value=self.author, placeholder="Author", id="author")
            yield Static(id="error", markup=False)
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self._show_fields()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "status":
            self._show_fields()

    def _show_fields(self) -> None:
        """Only the fields the status uses."""
        status = _value(self.query_one("#status", Select))
        for name, used_by in _USED_BY.items():
            self.query_one(f"#{name}").display = status == used_by

    @staticmethod
    def _given(field: Select[str] | Input) -> str:
        """What a field holds, if it's shown: one hidden since it was filled in isn't saved."""
        return _value(field) if field.display else ""

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save":
            self.dismiss(False)
            return
        author = _value(self.query_one("#author", Input))
        try:
            if not author:
                raise ValueError("Who's saying so: the author is needed.")
            self.store.add(
                author,
                self.finding.cve,
                _value(self.query_one("#scope", Select)),
                _value(self.query_one("#status", Select)),
                cli.now(),
                justification=self._given(self.query_one("#justification", Select)),
                impact_statement=self._given(self.query_one("#impact", Input)),
                action_statement=self._given(self.query_one("#action", Input)),
            )
        except ValueError as error:
            self.query_one("#error", Static).update(str(error))
            return
        self.dismiss(True)


class Tui(App[None]):
    TITLE = "advisory-map"
    BINDINGS = [
        ("a", "assess", "Assess"),
        # u toggles: the footer offers whichever it does next.
        ("u", "unassessed(True)", "Show unassessed"),
        ("u", "unassessed(False)", "Show all"),
        ("o", "copy_link", "Copy link"),
        ("slash", "find", "Filter"),
        ("escape", "clear_filter", "Clear filter"),
        # A column's number sorts by it, as its header does: one entry in the footer for them all.
        *(
            Binding(str(column + 1), f"sort({column})", "Sort", show=column == 0, key_display=f"1-{len(cli.COLUMNS)}")
            for column in range(len(cli.COLUMNS))
        ),
        ("r", "reload", "Reload"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, store: Store, url: str, author: str, reload_interval: float = 60) -> None:
        super().__init__()
        self.store = store
        self.url = url
        self.author = author
        # Seconds between reads of the findings: the app matches them again, and others add verdicts.
        self.reload_interval = reload_interval
        # Only the findings without a verdict that holds.
        self.to_assess_only = False
        # The column the table's sorted by, and whether it's reversed; None: as the app serves them, by
        # kind, target and CVE.
        self.sort: tuple[int, bool] | None = None
        # With their assessments, as the app serves them.
        self.findings: list[tuple[Finding, str]] = []
        # Why the findings couldn't be read last time, if they couldn't.
        self.error = ""
        # The findings in the table, row by row.
        self.shown: list[Finding] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield _Filter(
            placeholder="Filter: words in any column, or column:value (severity:critical); Tab completes",
            suggester=_Completer(lambda: [cli.row(*pair) for pair in self.findings]),
            id="filter",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(DataTable).add_columns(*self._headers())
        self.query_one("#filter").display = False
        self.action_reload()
        self.set_interval(self.reload_interval, self.action_reload)

    def action_reload(self) -> None:
        """The findings read again. Without the app, those last read stay, and the title says so."""
        try:
            self.findings = cli.findings(self.url)
            self.error = ""
        except OSError as error:
            self.error = str(error)
        self.show()

    def _selected(self) -> Finding | None:
        """The finding the cursor's on, if there's one."""
        row = self.query_one(DataTable).cursor_row
        return self.shown[row] if 0 <= row < len(self.shown) else None

    def _rows(self) -> list[tuple[Finding, tuple[str, ...]]]:
        """The findings to show, each with its cells: filtered, then sorted."""
        terms = self.query_one("#filter", Input).value
        rows = [
            (finding, cli.row(finding, assessment))
            for finding, assessment in self.findings
            if not self.to_assess_only or assessment in cli.TO_ASSESS
        ]
        rows = [(finding, cells) for finding, cells in rows if _matches(cells, terms)]
        if self.sort is not None:
            column, reverse = self.sort
            rows.sort(key=lambda row: _order(column, row[1][column]), reverse=reverse)
        return rows

    def show(self) -> None:
        """The findings again. The cursor stays on its finding, or on its row once the finding's gone."""
        table = self.query_one(DataTable)
        row = table.cursor_row
        selected = _key(finding) if (finding := self._selected()) else None
        table.clear()
        for column, header in zip(table.columns.values(), self._headers()):
            column.label = Text(header)
        self.shown = []
        for finding, cells in self._rows():
            table.add_row(*(Text(cell) for cell in cells))
            self.shown.append(finding)
        keys = [_key(finding) for finding in self.shown]
        table.move_cursor(row=keys.index(selected) if selected in keys else min(row, len(self.shown) - 1))
        self.sub_title = self._status()

    def _headers(self) -> list[str]:
        """The columns' headers, the one the table's sorted by with an arrow: ▲ its own order (A to Z,
        the most severe first), ▼ reversed. The others keep its room, so sorting never moves a column."""
        headers = [f"{name}  " for name in cli.COLUMNS]
        if self.sort is not None:
            column, reverse = self.sort
            headers[column] = f"{cli.COLUMNS[column]} {'▼' if reverse else '▲'}"
        return headers

    def _status(self) -> str:
        """How many findings are shown, and why they couldn't be read again."""
        shown, found = len(self.shown), len(self.findings)
        status = f"{found} findings" if shown == found else f"{shown} of {found} findings"
        return f"Couldn't read the findings: {self.error} · {status}" if self.error else status

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "unassessed":
            # Of the two bindings, only the one that changes it.
            return parameters != (self.to_assess_only,)
        if action == "clear_filter":
            return bool(self.query_one("#filter").display)
        return True

    def action_unassessed(self, to_assess_only: bool) -> None:
        self.to_assess_only = to_assess_only
        self.refresh_bindings()
        self.show()

    def action_copy_link(self) -> None:
        """The selected finding's advisory link, copied with OSC 52: the app runs in its container, with
        no browser to open, but the terminal it's shown in puts the link on its clipboard."""
        if finding := self._selected():
            url = advisory_url(finding)
            self.copy_to_clipboard(url)
            self.notify(url, title="Copied")

    def action_find(self) -> None:
        terms = self.query_one("#filter", Input)
        terms.display = True
        terms.focus()
        self.refresh_bindings()

    def action_clear_filter(self) -> None:
        terms = self.query_one("#filter", Input)
        terms.value = ""
        self._leave_filter()

    def _leave_filter(self) -> None:
        """Back to the table; the filter stays shown while it has terms."""
        terms = self.query_one("#filter", Input)
        terms.display = bool(terms.value)
        self.query_one(DataTable).focus()
        self.refresh_bindings()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.show()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter":
            self._leave_filter()

    def action_sort(self, column: int) -> None:
        """By the column; again, the other way; again, as the app serves them."""
        if self.sort == (column, False):
            self.sort = (column, True)
        elif self.sort == (column, True):
            self.sort = None
        else:
            self.sort = (column, False)
        self.show()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        self.action_sort(event.column_index)

    def action_assess(self) -> None:
        if finding := self._selected():
            self.push_screen(Assess(self.store, finding, self.author), self._assessed)

    def on_data_table_row_selected(self) -> None:
        self.action_assess()

    def _assessed(self, saved: bool | None) -> None:
        if saved:
            self.action_reload()
