import io
import json
import subprocess
import zipfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from advisory_map.advisories.cvelist import record_path
from advisory_map.common import http


@pytest.fixture(autouse=True)
def hermetic_git(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """git as it runs in the image: no user or system config (signing, hooks, aliases). An empty home, as
    git before 2.32 ignores GIT_CONFIG_GLOBAL."""
    home = tmp_path_factory.mktemp("home")
    for variable in ("HOME", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(home))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def record(
    cve: str,
    versions: list[dict[str, Any]] | None = None,
    vendor: str = "HashiCorp",
    product: str = "Vault",
    cna_cvss: dict[str, Any] | None = None,
    adp_cvss: dict[str, Any] | None = None,
    state: str = "PUBLISHED",
) -> dict[str, Any]:
    """A CVE JSON 5 record: its CNA's affected product, and CVSS metrics from the CNA and/or an ADP."""
    cna: dict[str, Any] = {
        "providerMetadata": {"dateUpdated": "2026-01-01T00:00:00.000Z"},
        "affected": [{"vendor": vendor, "product": product, "versions": versions or []}],
    }
    if cna_cvss:
        cna["metrics"] = [cna_cvss]
    containers: dict[str, Any] = {"cna": cna}
    if adp_cvss:
        containers["adp"] = [{"providerMetadata": {"dateUpdated": "2026-06-01T00:00:00.000Z"}, "metrics": [adp_cvss]}]
    return {"cveMetadata": {"cveId": cve, "state": state}, "containers": containers}


class Origin:
    """A stand-in for cvelistV5: a git repository of CVE records on main."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True)
        self._git("init", "--quiet", "--initial-branch=main")

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.path), "-c", "user.name=test", "-c", "user.email=test@example.invalid", *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    @property
    def url(self) -> str:
        # A file:// URL, not a path: git ignores --depth for local paths.
        return self.path.as_uri()

    def commit(self, *records: dict[str, Any], remove: Iterable[str] = ()) -> str:
        for item in records:
            path = self.path / record_path(item["cveMetadata"]["cveId"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(item))
        for cve in remove:
            (self.path / record_path(cve)).unlink()
        self._git("add", "--all")
        self._git("commit", "--quiet", "--allow-empty", "--message", "records")
        return self._git("rev-parse", "HEAD").strip()


@pytest.fixture
def origin(tmp_path: Path) -> Origin:
    return Origin(tmp_path / "origin")


TRACKER = {
    "openssl": {
        # Fixed in trixie by a security update, never affected bookworm.
        "CVE-2026-0001": {
            "releases": {
                "trixie": {"status": "resolved", "fixed_version": "3.5.4-1~deb13u2", "urgency": "high"},
                "bookworm": {"status": "resolved", "fixed_version": "0", "urgency": "not yet assigned"},
            }
        },
        # Not fixed, Debian won't issue an advisory.
        "CVE-2026-0002": {
            "releases": {
                "trixie": {"status": "open", "urgency": "low", "nodsa": "Minor issue", "nodsa_reason": ""},
            }
        },
    },
    "curl": {
        "CVE-2026-0003": {
            "releases": {
                "trixie": {"status": "open", "urgency": "medium*", "nodsa": "", "nodsa_reason": "postponed"},
            }
        },
        "CVE-2026-0004": {"releases": {"trixie": {"status": "undetermined", "urgency": "not yet assigned"}}},
        # Fixed in a version older than the one installed.
        "CVE-2025-0005": {
            "releases": {"trixie": {"status": "resolved", "fixed_version": "8.10.0-1", "urgency": "low"}}
        },
    },
}

KEV = {
    "vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-10-30", "knownRansomwareCampaignUse": "Known"}]
}


def osv_archive(*records: dict[str, Any]) -> bytes:
    """An OSV ecosystem's all.zip."""
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        for item in records:
            archive.writestr(f"{item['id']}.json", json.dumps(item))
    return data.getvalue()


def response(body: Any, status: int = 200, **headers: str) -> http.Response:
    """body as JSON, or as it is if bytes."""
    message = Message()
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    if status == 304:
        return http.Response(status, message)
    return http.Response(status, message, body if isinstance(body, bytes) else json.dumps(body).encode())


class FakeHttp:
    """http.get by URL prefix: a response (or a callable making one from the URL), or an exception to raise.
    Records each request's headers."""

    def __init__(self) -> None:
        self.routes: dict[str, http.Response | Exception | Callable[[str], http.Response]] = {}
        self.requests: list[tuple[str, Mapping[str, str]]] = []

    def get(
        self, url: str, headers: Mapping[str, str] | None = None, context: object = None, dest: Path | None = None
    ) -> http.Response:
        self.requests.append((url, dict(headers or {})))
        route = next(route for prefix, route in self.routes.items() if url.startswith(prefix))
        if isinstance(route, Exception):
            raise route
        response = route(url) if callable(route) else route
        if dest is None or response.status == 304:
            return response
        dest.write_bytes(response.body)
        return http.Response(response.status, response.headers)

    @contextmanager
    def lines(self, url: str) -> Iterator[Iterator[bytes]]:
        yield iter(self.get(url).body.splitlines(keepends=True))


@pytest.fixture
def fake_http(monkeypatch: pytest.MonkeyPatch) -> FakeHttp:
    fake = FakeHttp()
    monkeypatch.setattr(http, "get", fake.get)
    monkeypatch.setattr(http, "lines", fake.lines)
    return fake
