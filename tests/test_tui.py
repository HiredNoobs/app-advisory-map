import asyncio
import html
import json
import re
from pathlib import Path

import pytest
from conftest import FINDINGS, METRICS_URL, FakeHttp, serve
from textual.widgets import DataTable, Input, Select, Static

from advisory_map import cli
from advisory_map.tui import Assess, Tui
from advisory_map.vex.openvex import Store, product

pytestmark = pytest.mark.usefixtures("vex_dir")

# Columns and lines: the dialog fits, it scrolls in a smaller terminal.
SIZE = (120, 40)


def screen(tui: Tui) -> str:
    """The text on the screen."""
    texts = re.findall(r">([^<]*)</text>", tui.export_screenshot())
    return "\n".join(html.unescape(text).replace("\xa0", " ") for text in texts)


def assessments(tui: Tui) -> list[tuple[str, str]]:
    table = tui.query_one(DataTable)
    return [(str(row[0]), str(row[1])) for row in (table.get_row_at(index) for index in range(table.row_count))]


def test_assess_a_finding(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            assert assessments(tui) == [("unassessed", "CVE-2026-0001"), ("unassessed", "CVE-2026-0002")]
            await pilot.press("enter")
            assert isinstance(tui.screen, Assess)
            assert tui.screen.query_one("#scope", Select).value == product("container", "web/frontend")
            assert tui.screen.query_one("#author", Input).value == "alice"
            tui.screen.query_one("#status", Select).value = "not_affected"
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


def test_an_invalid_verdict_isnt_saved(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, *FINDINGS)

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "")
        async with tui.run_test(size=SIZE) as pilot:
            await pilot.press("down", "a")
            assert isinstance(tui.screen, Assess)
            tui.screen.query_one("#scope", Select).value = product("debian-package")
            tui.screen.query_one("#status", Select).value = "fixed"
            await pilot.click("#save")
            await pilot.pause()
            assert "author" in str(tui.screen.query_one("#error", Static).content)
            tui.screen.query_one("#author", Input).value = "alice"
            # A button ignores a press within 0.2s of the last.
            await pilot.pause(0.3)
            await pilot.click("#save")
            await pilot.pause()
            assert not isinstance(tui.screen, Assess)
            await pilot.press("a", "escape")
            assert not isinstance(tui.screen, Assess)

    asyncio.run(scenario())
    [statement] = json.loads((vex_dir / "alice.json").read_text())["statements"]
    assert statement["products"] == [{"@id": "advisory-map:installation/debian-package"}]


def test_labels_arent_markup(fake_http: FakeHttp, vex_dir: Path) -> None:
    serve(fake_http, ("CVE-2026-0001", "container", "web/[b]app[/b]", "pkg"))

    async def scenario() -> None:
        tui = Tui(Store(vex_dir), METRICS_URL, "alice")
        async with tui.run_test(size=SIZE) as pilot:
            assert "web/[b]app[/b]" in screen(tui)
            await pilot.press("a")
            await pilot.pause()
            assert "This container: web/[b]app[/b]" in screen(tui)

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


def test_cli_runs_it(monkeypatch: pytest.MonkeyPatch, vex_dir: Path) -> None:
    runs: list[Tui] = []
    monkeypatch.setattr(Tui, "run", lambda self: runs.append(self))
    monkeypatch.setenv("VEX_AUTHOR", "alice")
    assert cli.main(["tui"]) == 0
    [tui] = runs
    assert (tui.store.path, tui.url, tui.author) == (vex_dir, METRICS_URL, "alice")
