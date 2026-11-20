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
from advisory_map.tui import Assess, Tui
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


def test_cli_runs_it(monkeypatch: pytest.MonkeyPatch, vex_dir: Path) -> None:
    runs: list[Tui] = []
    monkeypatch.setattr(Tui, "run", lambda self: runs.append(self))
    monkeypatch.setenv("VEX_AUTHOR", "alice")
    assert cli.main(["tui"]) == 0
    [tui] = runs
    assert (tui.store.path, tui.url, tui.author) == (vex_dir, METRICS_URL, "alice")
