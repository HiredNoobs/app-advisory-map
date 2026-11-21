"""The verdicts page: a CVE's findings with their assessments, the statements about it, and a form adding
one. It's on a port of its own (WEB_PORT) because it writes: for an authenticating proxy alone to reach,
which says who's saving in the header WEB_AUTHOR_HEADER names (such as Remote-User or X-Forwarded-User).
Without one, the form asks who's saving."""

import logging
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from advisory_map.findings import advisory_url
from advisory_map.vex.assess import Assessed, assessed
from advisory_map.vex.openvex import (
    JUSTIFICATIONS,
    PRODUCT,
    STATUSES,
    Statement,
    Store,
    product,
)

if TYPE_CHECKING:
    from advisory_map.app import App

log = logging.getLogger(__name__)

PATH = "/assess"
# What names the findings a page is about: the CVE, then optionally which of its findings, by their field.
_SELECTORS = {"cve": "cve", "kind": "target_kind", "target": "target", "package": "package"}
# The form's fields that only one status uses, and that status.
_USED_BY = {"justification": "not_affected", "impact": "not_affected", "action": "affected"}
# A form is a few short fields: a body larger than this, or with more fields, isn't one.
_MAX_BODY = 64 * 1024
_MAX_FIELDS = 32
# Its own inline style, and the empty icon that keeps browsers from asking for /favicon.ico.
_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'"
)

_STYLE = """
:root { color-scheme: light dark; --fg: #1d1d1f; --bg: #fff; --muted: #6b6b70; --line: #d9d9de;
  --accent: #2563eb; --ok: #15803d; --bad: #b91c1c; }
@media (prefers-color-scheme: dark) { :root { --fg: #e8e8ea; --bg: #161618; --muted: #9a9aa2;
  --line: #34343a; --accent: #7aa2ff; --ok: #4ade80; --bad: #f87171; } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, sans-serif; }
main { max-width: 72rem; margin: 0 auto; padding: 1.5rem 1rem 3rem; }
h1 { margin: 0 0 1rem; font-size: 1.6rem; } h2 { margin: 2rem 0 .5rem; font-size: 1.15rem; }
a { color: var(--accent); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: .35rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
.notice { color: var(--ok); } .error { color: var(--bad); } .muted { color: var(--muted); }
form { display: grid; gap: .9rem; max-width: 40rem; }
label { display: grid; gap: .25rem; font-weight: 600; }
select, textarea, input { font: inherit; padding: .4rem .5rem; border: 1px solid var(--line); border-radius: 6px;
  background: var(--bg); color: var(--fg); }
textarea { min-height: 4.5rem; }
button { justify-self: start; font: inherit; font-weight: 600; padding: .45rem 1.2rem; border: 0;
  border-radius: 6px; background: var(--accent); color: var(--bg); cursor: pointer; }
form:not(:has(#status option[value="not_affected"]:checked)) .not-affected { display: none; }
form:not(:has(#status option[value="affected"]:checked)) .affected { display: none; }
"""


class _Html(str):
    """Markup, its text already escaped."""


def _html(value: str) -> str:
    return value if isinstance(value, _Html) else escape(value)


@dataclass(frozen=True)
class _Selection:
    """The findings a page is about, and what a verdict on them can say."""

    # The selectors given: the page's own link.
    selectors: Mapping[str, str]
    findings: list[Assessed]
    # About the CVE, newest first.
    statements: list[Statement]
    # (label, product): the installations a verdict on these findings can cover.
    scopes: list[tuple[str, str]]

    @property
    def cve(self) -> str:
        return self.selectors["cve"]

    def prefill(self) -> dict[str, str]:
        """The form, from the verdict the findings share, if they share one: a new one starts from it."""
        decided = {item.statement for item in self.findings}
        statement = decided.pop() if len(decided) == 1 else None
        if statement is None:
            return {}
        offered = [scope for _, scope in self.scopes]
        return {
            "scope": next((scope for scope in statement.products if scope in offered), ""),
            "status": statement.status,
            "justification": statement.justification,
            "impact": statement.impact_statement,
            "action": statement.action_statement,
        }


def _select(app: "App", store: Store, fields: Mapping[str, str]) -> _Selection:
    """The CVE's findings that match the other selectors, assessed as /metrics assesses them."""
    selectors = {name: fields[name] for name in _SELECTORS if fields.get(name)}
    statements = store.statements()
    items, _ = assessed(app.findings, statements, app.fingerprints.data if app.fingerprints else {}, app.kev.data or {})
    chosen = [
        item
        for item in items
        if all(getattr(item.finding, _SELECTORS[name]) == value for name, value in selectors.items())
    ]
    targets = sorted({(item.finding.target_kind, item.finding.target) for item in chosen})
    scopes = []
    if len(targets) == 1:
        [(kind, target)] = targets
        scopes.append((f"This {kind}: {target}", product(kind, target)))
    scopes += [(f"Every {kind}", product(kind)) for kind in sorted({kind for kind, _ in targets})]
    scopes.append(("Everywhere", product()))
    about = [statement for statement in statements if selectors["cve"] in statement.names]
    return _Selection(selectors, chosen, sorted(about, key=lambda s: s.timestamp, reverse=True), scopes)


def _describe(scope: str) -> str:
    """An installation product, in words."""
    if scope == PRODUCT:
        return "Everywhere"
    if not scope.startswith(f"{PRODUCT}/"):
        return scope
    kind, _, target = scope.removeprefix(f"{PRODUCT}/").partition("/")
    return f"{unquote(kind)}: {unquote(target)}" if target else f"Every {unquote(kind)}"


def _options(choices: Sequence[tuple[str, str]], selected: str) -> str:
    return "".join(
        f'<option value="{escape(value)}"{" selected" if value == selected else ""}>{escape(label)}</option>'
        for label, value in choices
    )


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    head = "".join(f"<th>{escape(header)}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{_html(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _document(title: str, content: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="data:,">'
        f"<title>{escape(title)} · advisory-map</title><style>{_STYLE}</style></head>"
        f"<body><main>{content}</main></body></html>"
    )


def _message(title: str, text: str) -> str:
    return _document(title, f"<h1>{escape(title)}</h1><p>{escape(text)}</p>")


def _finding_row(item: Assessed) -> list[str]:
    finding = item.finding
    advisory = _Html(f'<a href="{escape(advisory_url(finding))}" rel="noreferrer">{escape(finding.source)}</a>')
    return [
        finding.target_kind,
        finding.target,
        finding.package,
        finding.installed_version,
        finding.fixed_version,
        finding.severity,
        item.assessment,
        item.justification,
        advisory,
    ]


def _statement_row(statement: Statement) -> list[str]:
    return [
        statement.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
        statement.author,
        ", ".join(_describe(scope) for scope in statement.products),
        statement.status,
        statement.justification,
        statement.impact_statement,
        statement.action_statement,
    ]


def _page(selection: _Selection, values: Mapping[str, str], user: str | None, notice: str = "", error: str = "") -> str:
    """The CVE's page, its form holding values. user is who's saving, as the proxy says (None without one:
    the form asks)."""
    findings = _table(
        ("Kind", "Target", "Package", "Version", "Fixed", "Severity", "Assessment", "Justification", "Advisory"),
        [_finding_row(item) for item in selection.findings],
    )
    statements = (
        _table(
            ("When", "Who", "Applies to", "Status", "Justification", "Impact", "Action"),
            [_statement_row(statement) for statement in selection.statements],
        )
        if selection.statements
        else '<p class="muted">None yet.</p>'
    )
    hidden = "".join(
        f'<input type="hidden" name="{name}" value="{escape(value)}">' for name, value in selection.selectors.items()
    )
    if user is None:
        author = f'<label>Author<input name="author" value="{escape(values.get("author", ""))}" required></label>'
    else:
        author = f'<p class="muted">Saving as {escape(user)}.</p>' if user else ""
    statuses = [("Choose a status", ""), *((status, status) for status in STATUSES)]
    justifications = [("Choose a justification", ""), *((name, name) for name in JUSTIFICATIONS)]
    content = f"""
<h1>{escape(selection.cve)}</h1>
{f'<p class="notice">{escape(notice)}</p>' if notice else ""}
{f'<p class="error">{escape(error)}</p>' if error else ""}
<h2>Findings</h2>
{findings}
<h2>New verdict</h2>
<form method="post" action="{PATH}">
{hidden}
<label>Applies to<select name="scope" id="scope">{_options(selection.scopes, values.get("scope", ""))}</select></label>
<label>Status<select name="status" id="status">{_options(statuses, values.get("status", ""))}</select></label>
<label class="not-affected">Justification
<select name="justification" id="justification">{_options(justifications, values.get("justification", ""))}</select>
</label>
<label class="not-affected">Impact statement
<textarea name="impact">{escape(values.get("impact", ""))}</textarea></label>
<label class="affected">Action statement
<textarea name="action">{escape(values.get("action", ""))}</textarea></label>
{author}
<button type="submit">Save</button>
</form>
<h2>Statements about {escape(selection.cve)}</h2>
{statements}
"""
    return _document(selection.cve, content)


def _fields(text: str) -> dict[str, str]:
    """A query's or form's fields, the first value of each: ValueError with too many."""
    return {
        name: values[0] for name, values in parse_qs(text, keep_blank_values=True, max_num_fields=_MAX_FIELDS).items()
    }


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, app: "App", store: Store, author_header: str | None) -> None:
        super().__init__(("", port), _Handler)
        self.app = app
        self.store = store
        self.author_header = author_header
        # Handlers run in threads: saves are one at a time, each document read and written whole.
        self.saving = threading.Lock()

    def server_bind(self) -> None:
        # HTTPServer's looks its address up in DNS for a name only CGI uses: seconds where there's no
        # answer.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = "advisory-map", self.server_address[1]

    def handle_error(self, request: object, client_address: object) -> None:
        log.exception("verdicts page: request from %s failed", client_address)


class _Handler(BaseHTTPRequestHandler):
    """Each method sends one response: a refusal, or what was asked for."""

    server: _Server
    server_version = "advisory-map"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        log.debug("verdicts page: " + format, *args)

    def _send(self, status: int, body: str, headers: Mapping[str, str] | None = None) -> None:
        data = body.encode()
        self.send_response(status)
        for name, value in {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(data)),
            "Content-Security-Policy": _CSP,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            **(headers or {}),
        }.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _user(self) -> str | None:
        """Who's saving, as the proxy says: empty if it doesn't, None without one (the form asks)."""
        if self.server.author_header is None:
            return None
        return (self.headers.get(self.server.author_header) or "").strip()

    def _same_origin(self) -> bool:
        """Whether a form was sent from this page, not another site's: as the browser says (Fetch
        Metadata), else by its Origin. A client that sends neither isn't a browser on another site."""
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None:
            return site in ("same-origin", "none")
        origin = self.headers.get("Origin")
        return origin is None or urlsplit(origin).netloc == self.headers.get("Host")

    def _form(self) -> dict[str, str] | None:
        """The form sent, or None once it's refused."""
        length = self.headers.get("Content-Length") or "0"
        # Without a length to read, or with too much, the connection's left unread: it's closed.
        if not (length.isascii() and length.isdigit()):
            self.close_connection = True
            self._send(400, _message("Not saved", "That isn't the page's form."), {"Connection": "close"})
            return None
        if int(length) > _MAX_BODY:
            self.close_connection = True
            self._send(413, _message("Not saved", "That's too much for a verdict."), {"Connection": "close"})
            return None
        try:
            return _fields(self.rfile.read(int(length)).decode())
        except ValueError:
            self._send(400, _message("Not saved", "That isn't the page's form."))
            return None

    def _selection(self, fields: Mapping[str, str]) -> _Selection | None:
        """The findings the fields select, or None once they're refused."""
        if not fields.get("cve"):
            self._send(400, _message("Which CVE?", f"The page is for a CVE's findings: {PATH}?cve=CVE-..."))
            return None
        selection = _select(self.server.app, self.server.store, fields)
        if not selection.findings:
            self._send(404, _message(selection.cve, "No finding of it matches: it may be fixed, or gone."))
            return None
        return selection

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if url.path != PATH:
            self._send(404, _message("Not found", f"The verdicts page is {PATH}?cve=CVE-..."))
            return
        try:
            query = _fields(url.query)
        except ValueError:
            self._send(400, _message("Which CVE?", f"The page is for a CVE's findings: {PATH}?cve=CVE-..."))
            return
        if selection := self._selection(query):
            notice = "Saved: it applies to these findings from now on." if "saved" in query else ""
            self._send(200, _page(selection, selection.prefill(), self._user(), notice=notice))

    def do_POST(self) -> None:
        if urlsplit(self.path).path != PATH:
            self._send(404, _message("Not found", f"The verdicts page is {PATH}?cve=CVE-..."))
        elif not self._same_origin():
            self._send(403, _message("Not saved", "The form was sent from another site."))
        elif self._user() == "":
            self._send(403, _message("Not saved", "Who's saving? The proxy in front of the page didn't say."))
        elif (form := self._form()) is not None and (selection := self._selection(form)):
            self._save(selection, form)

    def _save(self, selection: _Selection, form: Mapping[str, str]) -> None:
        """The verdict in the form, added: the page again, or the form with why it wasn't."""
        status = form.get("status", "")
        # Only what the status uses: a field hidden once it was filled in isn't saved.
        given = {name: form.get(name, "").strip() if status == used_by else "" for name, used_by in _USED_BY.items()}
        user = self._user()
        try:
            author = user or form.get("author", "").strip()
            if not author:
                raise ValueError("Who's saying so: the author is needed.")
            if form.get("scope") not in [scope for _, scope in selection.scopes]:
                raise ValueError("Choose what it applies to from those offered.")
            with self.server.saving:
                self.server.store.add(
                    author,
                    selection.cve,
                    form["scope"],
                    status,
                    datetime.now(UTC),
                    justification=given["justification"],
                    impact_statement=given["impact"],
                    action_statement=given["action"],
                )
        except ValueError as error:
            self._send(400, _page(selection, form, user, error=str(error)))
            return
        location = f"{PATH}?" + urlencode({**selection.selectors, "saved": "1"})
        self._send(303, _message("Saved", "Saved."), {"Location": location})


def serve(app: "App", port: int, author_header: str | None) -> ThreadingHTTPServer:
    """The page, served in a thread of its own until the process ends (or the server's shut down)."""
    if app.vex is None:
        raise ValueError("the verdicts page needs VEX_DIR")
    server = _Server(port, app, app.vex, author_header)
    threading.Thread(target=server.serve_forever, name="verdicts-page", daemon=True).start()
    log.info("verdicts page on port %d", server.server_address[1])
    return server
