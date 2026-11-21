import http.client
from collections.abc import Callable, Iterator, Mapping
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

import pytest
from conftest import FINDINGS, fake_app

from advisory_map import cli, web
from advisory_map.vex.openvex import Store, product

PAGE = "/assess?" + urlencode({"cve": "CVE-2026-0001", "kind": "container", "target": "web/frontend"})
VERDICT = {
    "cve": "CVE-2026-0001",
    "kind": "container",
    "target": "web/frontend",
    "scope": product("container", "web/frontend"),
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impact": "The OIDC login is not configured",
}


class Response:
    def __init__(self, response: http.client.HTTPResponse) -> None:
        self.status = response.status
        self.headers = response.headers
        self.body = response.read().decode()


class Page:
    """The verdicts page, served on a port of its own."""

    def __init__(self, server: ThreadingHTTPServer) -> None:
        self.server = server
        self.port = server.server_address[1]

    def request(self, method: str, path: str, body: bytes = b"", headers: Mapping[str, str] | None = None) -> Response:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body, dict(headers or {}))
            return Response(connection.getresponse())
        finally:
            connection.close()

    def get(self, path: str) -> Response:
        return self.request("GET", path)

    def post(self, form: Mapping[str, str], headers: Mapping[str, str] | None = None) -> Response:
        headers = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
        return self.request("POST", "/assess", urlencode(form).encode(), headers)


type Serve = Callable[..., Page]


@pytest.fixture
def serve(vex_dir: Path) -> Iterator[Serve]:
    """serve(*findings, author_header="Remote-User"): the page for an app with these findings."""
    servers: list[ThreadingHTTPServer] = []

    def page(*findings: tuple[str, ...], author_header: str | None = "Remote-User") -> Page:
        servers.append(web.serve(fake_app(vex_dir, *findings), 0, author_header))  # type: ignore[arg-type]
        return Page(servers[-1])

    yield page
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def page(serve: Serve) -> Page:
    return serve(*FINDINGS)


class Form(HTMLParser):
    """What a page's form holds: each field's value (a select's selected option's), and what each select
    offers."""

    def __init__(self, body: str) -> None:
        super().__init__()
        self.values: dict[str, str] = {}
        self.options: dict[str, list[str]] = {}
        self._select: str | None = None
        self._textarea: str | None = None
        self.feed(body)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        name, value = attributes.get("name") or "", attributes.get("value") or ""
        if tag == "select":
            self._select = name
            self.values[name], self.options[name] = "", []
        elif tag == "option" and self._select:
            self.options[self._select].append(value)
            if "selected" in attributes:
                self.values[self._select] = value
        elif tag == "textarea":
            self._textarea = name
            self.values[name] = ""
        elif tag == "input" and name:
            self.values[name] = value

    def handle_endtag(self, tag: str) -> None:
        if tag == "select":
            self._select = None
        elif tag == "textarea":
            self._textarea = None

    def handle_data(self, data: str) -> None:
        if self._textarea:
            self.values[self._textarea] += data


def test_a_findings_verdict(page: Page) -> None:
    response = page.get(PAGE)
    assert response.status == 200
    assert "web/frontend" in response.body and "unassessed" in response.body
    assert "https://www.cve.org/CVERecord?id=CVE-2026-0001" in response.body
    form = Form(response.body)
    assert form.options["scope"] == [product("container", "web/frontend"), product("container"), product()]
    assert form.values["status"] == ""
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_saving_a_verdict(page: Page, vex_dir: Path) -> None:
    origin = f"http://127.0.0.1:{page.port}"
    # What another status uses isn't saved.
    verdict = {**VERDICT, "action": "Upgrade"}
    response = page.post(verdict, {"Remote-User": "alice", "Origin": origin, "Sec-Fetch-Site": "same-origin"})
    assert response.status == 303 and response.headers["Location"] == f"{PAGE}&saved=1"
    [statement] = Store(vex_dir).statements()
    assert statement.author == "alice" and statement.products == (product("container", "web/frontend"),)
    assert (statement.status, statement.justification) == ("not_affected", "vulnerable_code_not_in_execute_path")
    assert (statement.impact_statement, statement.action_statement) == ("The OIDC login is not configured", "")
    # Shown with its verdict, which the form starts from: a change is a statement of its own.
    shown = page.get(response.headers["Location"])
    assert "Saved" in shown.body and "not_affected" in shown.body and "alice" in shown.body
    fields = ("scope", "status", "justification", "impact")
    assert {name: Form(shown.body).values[name] for name in fields} == {name: VERDICT[name] for name in fields}


def test_an_invalid_verdict_isnt_saved(page: Page, vex_dir: Path) -> None:
    response = page.post({**VERDICT, "justification": "", "impact": ""}, {"Remote-User": "alice"})
    assert response.status == 400
    assert "not_affected needs a justification or an impact_statement" in response.body
    assert Form(response.body).values["status"] == "not_affected"
    assert Store(vex_dir).statements() == []


@pytest.mark.parametrize(
    "headers",
    [
        # Who's saving: only the proxy in front of it says.
        {},
        # From another site.
        {"Remote-User": "alice", "Sec-Fetch-Site": "cross-site"},
        {"Remote-User": "alice", "Sec-Fetch-Site": "same-site"},
        {"Remote-User": "alice", "Origin": "https://elsewhere.example"},
    ],
)
def test_who_can_save(page: Page, vex_dir: Path, headers: dict[str, str]) -> None:
    assert page.post({**VERDICT, "author": "mallory"}, headers).status == 403
    assert Store(vex_dir).statements() == []


def test_without_a_proxy_the_form_asks_who(serve: Serve, vex_dir: Path) -> None:
    page = serve(*FINDINGS, author_header=None)
    assert "author" in Form(page.get(PAGE).body).values
    assert page.post(VERDICT).status == 400
    assert page.post({**VERDICT, "author": "bob"}).status == 303
    assert [statement.author for statement in Store(vex_dir).statements()] == ["bob"]


def test_only_the_findings_scopes(page: Page, vex_dir: Path) -> None:
    response = page.post({**VERDICT, "scope": product("debian-package")}, {"Remote-User": "alice"})
    assert response.status == 400
    assert Store(vex_dir).statements() == []


def test_a_cve_on_many_targets(serve: Serve) -> None:
    page = serve(
        ("CVE-2026-0002", "debian-package", "host-1", "openssl"),
        ("CVE-2026-0002", "debian-package", "host-2", "openssl"),
    )
    # As Grafana's CVEs by package links it: a package's findings on every host.
    response = page.get("/assess?" + urlencode({"cve": "CVE-2026-0002", "package": "openssl"}))
    assert "host-1" in response.body and "host-2" in response.body
    assert Form(response.body).options["scope"] == [product("debian-package"), product()]


def test_text_isnt_markup(serve: Serve, vex_dir: Path) -> None:
    target = "web/<script>alert(1)</script>"
    Store(vex_dir).add(
        "alice", "CVE-2026-0001", product("container", target), "not_affected", cli.now(), impact_statement="<b>no</b>"
    )
    page = serve(("CVE-2026-0001", "container", target, "pkg"))
    body = page.get("/assess?" + urlencode({"cve": "CVE-2026-0001", "target": target})).body
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "<b>no</b>" not in body and "&lt;b&gt;no&lt;/b&gt;" in body


@pytest.mark.parametrize(
    "method, path, body, headers, status",
    [
        pytest.param("GET", "/assess", b"", {}, 400, id="no CVE"),
        pytest.param("GET", "/assess?cve=CVE-2026-9999", b"", {}, 404, id="no finding"),
        pytest.param("GET", "/elsewhere", b"", {}, 404, id="elsewhere"),
        pytest.param("GET", "/assess?" + "&".join(f"f{n}=x" for n in range(40)), b"", {}, 400, id="not its query"),
        pytest.param("POST", "/assess", b"\xff", {}, 400, id="not its form"),
        pytest.param("POST", "/assess", b"cve=CVE-2026-0001", {"Content-Length": "-1"}, 400, id="no length"),
        pytest.param("POST", "/assess", b"x" * 100_000, {}, 413, id="too large"),
    ],
)
def test_requests_it_refuses(
    page: Page, method: str, path: str, body: bytes, headers: dict[str, str], status: int
) -> None:
    headers = {"Remote-User": "alice", "Content-Type": "application/x-www-form-urlencoded", **headers}
    assert page.request(method, path, body, headers).status == status
