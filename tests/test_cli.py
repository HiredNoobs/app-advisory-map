import json
from pathlib import Path

import pytest
from conftest import FINDINGS, METRICS_URL, FakeHttp, response, serve

from advisory_map import __main__, cli
from advisory_map.vex.openvex import Store, product

pytestmark = pytest.mark.usefixtures("vex_dir")


def test_list(fake_http: FakeHttp, vex_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    serve(fake_http, *FINDINGS)
    Store(vex_dir).add(
        "alice",
        "CVE-2026-0002",
        product("debian-package"),
        "not_affected",
        cli.now(),
        justification="component_not_present",
    )
    assert cli.main(["list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["ASSESSMENT", "CVE", "SEVERITY", "KIND", "TARGET", "PACKAGE", "VERSION"]
    assert [line.split()[:2] for line in lines[1:]] == [
        ["unassessed", "CVE-2026-0001"],
        ["not_affected", "CVE-2026-0002"],
    ]
    assert cli.main(["list", "--unassessed"]) == 0
    assert [line.split()[1] for line in capsys.readouterr().out.splitlines()[1:]] == ["CVE-2026-0001"]
    assert cli.main(["list", "--cve", "CVE-2026-0002"]) == 0
    assert [line.split()[1] for line in capsys.readouterr().out.splitlines()[1:]] == ["CVE-2026-0002"]


def test_list_from_another_port(fake_http: FakeHttp, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LISTEN_PORT", "9000")
    fake_http.routes["http://127.0.0.1:9000/metrics"] = response(b"")
    assert cli.main(["list"]) == 0
    assert fake_http.requests[0][0] == "http://127.0.0.1:9000/metrics"


def test_list_without_the_app(fake_http: FakeHttp, capsys: pytest.CaptureFixture[str]) -> None:
    fake_http.routes[METRICS_URL] = OSError("connection refused")
    assert cli.main(["list"]) == 1
    assert "connection refused" in capsys.readouterr().err


def test_add(fake_http: FakeHttp, vex_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    serve(fake_http, *FINDINGS)
    code = cli.main(
        [
            "add",
            "CVE-2026-0001",
            "--kind",
            "container",
            "--target",
            "web/frontend",
            "--status",
            "not_affected",
            "--justification",
            "vulnerable_code_not_in_execute_path",
            "--impact",
            "The OIDC login is not configured",
            "--author",
            "alice",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "alice.json" in out
    assert "applies to 1 finding" in out
    [statement] = json.loads((vex_dir / "alice.json").read_text())["statements"]
    assert statement["products"] == [{"@id": "advisory-map:installation/container/web/frontend"}]
    assert statement["impact_statement"] == "The OIDC login is not configured"


def test_add_everywhere_with_the_author_from_the_environment(
    fake_http: FakeHttp, vex_dir: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("VEX_AUTHOR", "alice")
    fake_http.routes[METRICS_URL] = OSError("connection refused")
    assert cli.main(["add", "CVE-2026-0009", "--status", "under_investigation"]) == 0
    out = capsys.readouterr().out
    assert "connection refused" in out
    [statement] = json.loads((vex_dir / "alice.json").read_text())["statements"]
    assert statement["products"] == [{"@id": "advisory-map:installation"}]


def test_add_checks_its_own_statement(fake_http: FakeHttp, vex_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    serve(fake_http, *FINDINGS)
    # Another author's document, read after alice's.
    Store(vex_dir).add("bob", "CVE-2026-0009", product(), "fixed", cli.now())
    assert cli.main(["add", "CVE-2026-0001", "--status", "fixed", "--author", "alice"]) == 0
    assert "applies to 1 finding" in capsys.readouterr().out


def test_add_matching_nothing(fake_http: FakeHttp, capsys: pytest.CaptureFixture[str]) -> None:
    serve(fake_http, *FINDINGS)
    assert cli.main(["add", "CVE-2026-0001", "--kind", "talos", "--status", "fixed", "--author", "alice"]) == 0
    assert "applies to no finding" in capsys.readouterr().out


@pytest.mark.parametrize(
    "args, message",
    [
        (["add", "CVE-1", "--status", "fixed"], "--author"),
        (["add", "CVE-1", "--status", "not_affected", "--author", "alice"], "justification or an impact_statement"),
        (["add", "CVE-1", "--target", "host-1", "--status", "fixed", "--author", "alice"], "--kind"),
    ],
)
def test_add_errors(args: list[str], message: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(args) == 1
    assert message in capsys.readouterr().err


def test_vex_dir_is_required(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.delenv("VEX_DIR")
    assert cli.main(["add", "CVE-1", "--status", "fixed", "--author", "alice"]) == 1
    assert "VEX_DIR" in capsys.readouterr().err


def test_main_runs_the_cli_for_vex(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(cli, "main", lambda args: calls.append(args) or 3)
    with pytest.raises(SystemExit) as exit_:
        __main__.main(["vex", "list"])
    assert (exit_.value.code, calls) == (3, [["list"]])
