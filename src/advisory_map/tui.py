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


def _value(select: Select[str]) -> str:
    return "" if select.value is Select.NULL else str(select.value)


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
                prompt="Justification (not_affected)",
            )
            yield Input(placeholder="Impact statement: why it's not affected", id="impact")
            yield Input(placeholder="Action statement: what to do about it, when it's affected", id="action")
            yield Input(value=self.author, placeholder="Author", id="author")
            yield Static(id="error", markup=False)
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Cancel", id="cancel")

    def action_cancel(self) -> None:
        self.dismiss(False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "save":
            self.dismiss(False)
            return
        author = self.query_one("#author", Input).value.strip()
        try:
            if not author:
                raise ValueError("Who's saying so: the author is needed.")
            self.store.add(
                author,
                self.finding.cve,
                _value(self.query_one("#scope", Select)),
                _value(self.query_one("#status", Select)),
                cli.now(),
                justification=_value(self.query_one("#justification", Select)),
                impact_statement=self.query_one("#impact", Input).value.strip(),
                action_statement=self.query_one("#action", Input).value.strip(),
            )
        except ValueError as error:
            self.query_one("#error", Static).update(str(error))
            return
        self.dismiss(True)


class Tui(App[None]):
    TITLE = "advisory-map"
    BINDINGS = [
        ("a", "assess", "Assess"),
        ("u", "unassessed", "Unassessed only"),
        ("r", "reload", "Reload"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, store: Store, url: str, author: str) -> None:
        super().__init__()
        self.store = store
        self.url = url
        self.author = author
        self.only_unassessed = False
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

    def action_reload(self) -> None:
        try:
            self.findings = cli.findings(self.url)
            self.sub_title = f"{len(self.findings)} findings"
        except OSError as error:
            self.findings = []
            self.sub_title = f"Couldn't read the findings: {error}"
        self.show()

    def show(self) -> None:
        """The findings again; the cursor stays on its row."""
        table = self.query_one(DataTable)
        row = table.cursor_row
        table.clear()
        self.shown = []
        for finding, assessment in self.findings:
            if not self.only_unassessed or assessment in cli.TO_ASSESS:
                table.add_row(*(Text(cell) for cell in cli.row(finding, assessment)))
                self.shown.append(finding)
        table.move_cursor(row=min(row, len(self.shown) - 1))

    def action_unassessed(self) -> None:
        self.only_unassessed = not self.only_unassessed
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
