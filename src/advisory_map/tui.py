"""advisory-map vex tui: the findings with their assessments, and a form adding a verdict on one."""

from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.content import Content
from textual.screen import ModalScreen
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
        ("u", "filter(True)", "Show unassessed"),
        ("u", "filter(False)", "Show all"),
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
        # With their assessments, as the app serves them.
        self.findings: list[tuple[Finding, str]] = []
        # The findings in the table, row by row.
        self.shown: list[Finding] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(DataTable).add_columns(*cli.COLUMNS)
        self.action_reload()
        self.set_interval(self.reload_interval, self.action_reload)

    def action_reload(self) -> None:
        """The findings read again. Without the app, those last read stay, and the title says so."""
        try:
            self.findings = cli.findings(self.url)
            self.sub_title = f"{len(self.findings)} findings"
        except OSError as error:
            self.sub_title = f"Couldn't read the findings: {error}"
        self.show()

    def show(self) -> None:
        """The findings again. The cursor stays on its finding, or on its row once the finding's gone."""
        table = self.query_one(DataTable)
        row = table.cursor_row
        selected = _key(self.shown[row]) if 0 <= row < len(self.shown) else None
        table.clear()
        self.shown = []
        for finding, assessment in self.findings:
            if not self.to_assess_only or assessment in cli.TO_ASSESS:
                table.add_row(*(Text(cell) for cell in cli.row(finding, assessment)))
                self.shown.append(finding)
        keys = [_key(finding) for finding in self.shown]
        table.move_cursor(row=keys.index(selected) if selected in keys else min(row, len(self.shown) - 1))

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        # Of the two filter bindings, only the one that changes it.
        return action != "filter" or parameters != (self.to_assess_only,)

    def action_filter(self, to_assess_only: bool) -> None:
        self.to_assess_only = to_assess_only
        self.refresh_bindings()
        self.show()

    def action_assess(self) -> None:
        if self.shown:
            finding = self.shown[self.query_one(DataTable).cursor_row]
            self.push_screen(Assess(self.store, finding, self.author), self._assessed)

    def on_data_table_row_selected(self) -> None:
        self.action_assess()

    def _assessed(self, saved: bool | None) -> None:
        if saved:
            self.action_reload()
