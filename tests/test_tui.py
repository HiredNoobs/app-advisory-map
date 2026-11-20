import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import FINDINGS, METRICS_URL, FakeHttp, serve
from textual.widget import Widget
from textual.widgets import DataTable, Input, Select, Static

from advisory_map import cli
from advisory_map.advisories.kev import Exploited
from advisory_map.findings import Finding
from advisory_map.tui import Assess, Tui, advisory_url, complete
from advisory_map.vex.openvex import Store, product

pytestmark = pytest.mark.usefixtures("vex_dir")

# Columns and lines: the dialog fits, it scrolls in a smaller terminal.
SIZE = (120, 40)


def rendered(*widgets: Widget) -> str:
    """The text the widgets draw."""
    return "\n".join(widget.render_line(y).text for widget in widgets for y in range(widget.size.height))


def assessments(tui: Tui) -> list[tuple[str, str]]:
    table = tui.query_one(DataTable)
    return [(str(row[0]), str(row[1])) for row in (table.get_row_at(index) for index in range(table.row_count))]


def test_assess_a_finding(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            assert assessments(tui) == [("unassessed", "CVE-2026-0001"), ("unassessed", "CVE-2026-0002")]
            await pilot.press("enter")
            assert isinstance(tui.screen, Assess)
            assert tui.screen.query_one("#scope", Select).value == product("container", "web/frontend")
            assert tui.screen.query_one("#author", Input).value == "alice"
            tui.screen.query_one("#status", Select).value = "not_affected"
            # The form shows the fields the status uses.
            await pilot.pause()
            tui.screen.query_one("#impact", Input).value = "The OIDC login is not configured"
            await pilot.click("#save")
            await pilot.pause()
            assert not isinstance(tui.screen, Assess)
            assert assessments(tui) == [("not_affected", "CVE-2026-0001"), ("unassessed", "CVE-2026-0002")]
            await pilot.press("u")
            assert assessments(tui) == [("unassessed", "CVE-2026-0002")]
            await pilot.press("u")
            assert len(assessments(tui)) == 2

    asyncio.run(scenario())
    [statement] = json.loads((vex_dir / "alice.json").read_text())["statements"]
    assert statement["status"] == "not_affected"
    assert statement["impact_statement"] == "The OIDC login is not configured"


def test_the_filter_says_what_it_does(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")

        def offered() -> set[str]:
            return {active.binding.description for active in tui.active_bindings.values() if active.enabled}

        async with tui.run_test(size=SIZE) as pilot:
            assert "Show unassessed" in offered() and "Show all" not in offered()
            await pilot.press("u")
            assert "Show all" in offered() and "Show unassessed" not in offered()
            await pilot.press("u")
            assert "Show unassessed" in offered()

    asyncio.run(scenario())


def cves(tui: Tui) -> list[str]:
    """The CVEs in the table, row by row."""
    return [cve for _, cve in assessments(tui)]


def cursor(tui: Tui) -> str:
    """The CVE of the finding under the cursor."""
    table = tui.query_one(DataTable)
    return str(table.get_row_at(table.cursor_row)[1])


def test_a_reload_keeps_the_cursor_on_its_finding(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("down")
            assert cursor(tui) == "CVE-2026-0002"
            # A new finding, in the row above it.
            serve(fake_http, vex_dir, ("CVE-2026-0003", "container", "web/backend", "pkg"), *FINDINGS)
            await pilot.press("r")
            assert cursor(tui) == "CVE-2026-0002"

    asyncio.run(scenario())


def test_it_reloads_on_its_own(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice", reload_interval=0.1)
        async with tui.run_test(size=SIZE) as pilot:
            assert len(assessments(tui)) == 2
            serve(fake_http, vex_dir, *FINDINGS, ("CVE-2026-0003", "talos", "node-1", "kubelet"))
            await pilot.pause(0.5)
            assert len(assessments(tui)) == 3

    asyncio.run(scenario())


def test_the_form_asks_for_what_the_status_needs(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("a")

            async def asked(status: str) -> set[str]:
                tui.screen.query_one("#status", Select).value = status
                await pilot.pause()
                return {
                    name for name in ("justification", "impact", "action") if tui.screen.query_one(f"#{name}").display
                }

            assert await asked("not_affected") == {"justification", "impact"}
            tui.screen.query_one("#impact", Input).value = "Not reachable"
            assert await asked("fixed") == set()
            assert await asked("under_investigation") == set()
            assert await asked("affected") == {"action"}
            tui.screen.query_one("#action", Input).value = "Upgrade"
            await pilot.click("#save")
            await pilot.pause()
            assert not isinstance(tui.screen, Assess)

    asyncio.run(scenario())
    # What a hidden field held isn't saved.
    [statement] = json.loads((vex_dir / "alice.json").read_text())["statements"]
    assert (statement["status"], statement["action_statement"]) == ("affected", "Upgrade")
    assert "impact_statement" not in statement


def test_an_invalid_verdict_isnt_saved(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("a")
            tui.screen.query_one("#status", Select).value = "fixed"
            await pilot.click("#save")
            await pilot.pause()
            assert isinstance(tui.screen, Assess)
            assert "author" in str(tui.screen.query_one("#error", Static).content)
            await pilot.press("escape")
            assert not isinstance(tui.screen, Assess)

    asyncio.run(scenario())
    assert not vex_dir.exists()


def test_a_verdict_on_every_installation_of_a_kind(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("down", "a")
            tui.screen.query_one("#scope", Select).value = product("debian-package")
            tui.screen.query_one("#status", Select).value = "fixed"
            await pilot.click("#save")
            await pilot.pause()
            assert not isinstance(tui.screen, Assess)

    asyncio.run(scenario())
    [statement] = json.loads((vex_dir / "alice.json").read_text())["statements"]
    assert statement["products"] == [{"@id": "advisory-map:installation/debian-package"}]


def test_expired_verdicts_need_assessing(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS, kev={"CVE-2026-0002": Exploited("2026-11-30", False)})
    Store(vex_dir).add(
        "alice", "CVE-2026-0002", product(), "not_affected", datetime(2026, 11, 20, tzinfo=UTC), impact_statement="No"
    )

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("u")
            assert assessments(tui) == [("unassessed", "CVE-2026-0001"), ("expired", "CVE-2026-0002")]

    asyncio.run(scenario())


def test_labels_arent_markup(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, ("CVE-2026-0001", "container", "web/[b]app[/b]", "pkg"))

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            assert "web/[b]app[/b]" in rendered(tui.query_one(DataTable))
            await pilot.press("a")
            await pilot.pause()
            scope = tui.screen.query_one("#scope", Select)
            assert "This container: web/[b]app[/b]" in rendered(*scope.query(Static))

    asyncio.run(scenario())


def test_without_the_app(fake_http: FakeHttp, vex_dir: Path) -> None:
    fake_http.routes[METRICS_URL] = OSError("connection refused")

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.pause()
            assert assessments(tui) == []
            assert "connection refused" in str(tui.sub_title)

    asyncio.run(scenario())


def test_a_failed_reload_keeps_the_findings(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("down")
            fake_http.routes[METRICS_URL] = OSError("connection refused")
            await pilot.press("r")
            assert len(assessments(tui)) == 2 and cursor(tui) == "CVE-2026-0002"
            assert "connection refused" in str(tui.sub_title)

    asyncio.run(scenario())


def test_o_copies_the_advisorys_link(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("down", "o")
            assert tui.clipboard == "https://www.cve.org/CVERecord?id=CVE-2026-0002"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "source, cve, url",
    [
        ("osv", "CVE-2026-0001", "https://www.cve.org/CVERecord?id=CVE-2026-0001"),
        ("osv", "GHSA-abcd-efgh-ijkl", "https://osv.dev/vulnerability/GHSA-abcd-efgh-ijkl"),
        ("debian", "TEMP-0000000-ABCDEF", "https://security-tracker.debian.org/tracker/TEMP-0000000-ABCDEF"),
    ],
)
def test_advisory_url(source: str, cve: str, url: str) -> None:
    finding = Finding(cve, "high", source, source, "container", "web/frontend", "web", "pkg", "1.0", "", "open")
    assert advisory_url(finding) == url


def test_filter(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS, ("CVE-2026-0003", "container", "web/backend", "pkg", "critical"))

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            # Words match any column.
            await pilot.press("slash", *"web/")
            assert cves(tui) == ["CVE-2026-0003", "CVE-2026-0001"]
            await pilot.press("space", *"critical")
            assert cves(tui) == ["CVE-2026-0003"]
            # Enter keeps it, back in the table.
            await pilot.press("enter")
            assert tui.focused is tui.query_one(DataTable) and cves(tui) == ["CVE-2026-0003"]
            # Escape clears it.
            await pilot.press("slash", "escape")
            assert len(cves(tui)) == 3
            # column:value matches that column only.
            await pilot.press("slash", *"kind:debian", "enter")
            assert cves(tui) == ["CVE-2026-0002"]
            assert "1 of 3" in str(tui.sub_title)

    asyncio.run(scenario())


def test_the_filter_completes(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, vex_dir, *FINDINGS, ("CVE-2026-0003", "container", "web/backend", "pkg", "critical"))

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            terms = tui.query_one("#filter", Input)
            # A column's name, then its values, the most severe first; Tab or the right arrow takes it.
            await pilot.press("slash", *"sev")
            await pilot.pause()
            await pilot.press("tab")
            assert terms.value == "severity:"
            await pilot.pause()
            await pilot.press("right")
            assert terms.value == "severity:critical" and cves(tui) == ["CVE-2026-0003"]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "terms, completed",
    [
        # As typed, then the rest.
        ("Sev", "Severity:"),
        # The most common first.
        ("kind:container target:", "kind:container target:web/frontend"),
        # Without a column, any column's values.
        ("web/b", "web/backend"),
        ("severity:high ", None),
        ("nothing", None),
    ],
)
def test_complete(terms: str, completed: str | None) -> None:
    rows = [
        ("unassessed", "CVE-1", "high", "container", "web/frontend", "a", "1.0"),
        ("unassessed", "CVE-2", "high", "container", "web/frontend", "b", "1.0"),
        ("unassessed", "CVE-3", "low", "container", "web/backend", "c", "1.0"),
    ]
    assert complete(terms, rows) == completed


def test_sort(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(
        fake_http,
        vex_dir,
        ("CVE-1", "container", "a", "pkg", "low"),
        ("CVE-2", "container", "b", "pkg", "critical"),
        ("CVE-3", "container", "c", "pkg", "high"),
    )

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            table = tui.query_one(DataTable)

            def header() -> str:
                return rendered(table).splitlines()[0]

            def arrows() -> int:
                return header().count("▲") + header().count("▼")

            unsorted = header()
            assert cves(tui) == ["CVE-1", "CVE-2", "CVE-3"] and arrows() == 0
            # The footer has one entry for them all.
            shown = [active.binding for active in tui.active_bindings.values() if active.binding.show]
            assert [binding.key_display for binding in shown if binding.description == "Sort"] == ["1-8"]
            # A header, or its number, sorts by its column: the most severe first; again, the other way;
            # again, as it was. Its arrow says which, in room every header keeps for it.
            severity = header().index("SEVERITY")
            await pilot.click(DataTable, offset=(severity + 1, 0))
            assert cves(tui) == ["CVE-2", "CVE-3", "CVE-1"] and "SEVERITY ▲" in header()
            assert [header().index(name) for name in cli.COLUMNS] == [unsorted.index(name) for name in cli.COLUMNS]
            await pilot.press("3")
            assert cves(tui) == ["CVE-1", "CVE-3", "CVE-2"] and "SEVERITY ▼" in header()
            await pilot.click(DataTable, offset=(severity + 1, 0))
            assert cves(tui) == ["CVE-1", "CVE-2", "CVE-3"] and header() == unsorted
            # Another column's takes over: only it has an arrow.
            await pilot.press("3", "5")
            assert cves(tui) == ["CVE-1", "CVE-2", "CVE-3"] and "TARGET ▲" in header() and arrows() == 1
            await pilot.press("5")
            assert cves(tui) == ["CVE-3", "CVE-2", "CVE-1"] and "TARGET ▼" in header()
            # The cursor follows its finding however it's sorted.
            assert cursor(tui) == "CVE-1"
            await pilot.press("up", "up", "5")
            assert cursor(tui) == "CVE-3" and cves(tui)[-1] == "CVE-3" and header() == unsorted

    asyncio.run(scenario())


def test_cli_runs_it(monkeypatch: pytest.MonkeyPatch, vex_dir: Path) -> None:
    runs: list[Tui] = []
    monkeypatch.setattr(Tui, "run", lambda self: runs.append(self))
    monkeypatch.setenv("VEX_AUTHOR", "alice")
    assert cli.main(["tui"]) == 0
    [tui] = runs
    assert (tui.store.path, tui.url, tui.author) == (vex_dir, METRICS_URL, "alice")
