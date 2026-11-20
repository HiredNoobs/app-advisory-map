from datetime import UTC, datetime

from advisory_map.findings import Finding
from advisory_map.vex.assess import assess, assessment
from advisory_map.vex.openvex import Statement, product


def finding(cve: str = "CVE-1", kind: str = "container", target: str = "ns/app") -> Finding:
    return Finding(cve, "high", "osv", "osv", kind, target, "ns", "pkg", "1.0.0", "", "open")


def verdict(
    status: str = "not_affected",
    products: tuple[str, ...] = (product(),),
    cve: str = "CVE-1",
    day: int = 1,
    aliases: tuple[str, ...] = (),
) -> Statement:
    justification = "component_not_present" if status == "not_affected" else ""
    return Statement(cve, aliases, products, status, justification, "", "", datetime(2026, 11, day, tzinfo=UTC), "a")


def test_no_statements() -> None:
    decided, unmatched = assess([finding()], [])
    assert decided == [None]
    assert unmatched == []
    assert assessment(None) == ("unassessed", "")


def test_products_cover_the_installations_under_them() -> None:
    findings = [finding(target="ns/app"), finding(target="ns/other"), finding(kind="talos", target="node-1")]
    statements = [verdict(products=(product("container", "ns/app"),))]
    assert assess(findings, statements)[0] == [statements[0], None, None]
    statements = [verdict(products=(product("container", "ns"),))]
    assert assess(findings, statements)[0] == [statements[0], statements[0], None]
    statements = [verdict(products=(product("container"),))]
    assert assess(findings, statements)[0] == [statements[0], statements[0], None]
    statements = [verdict(products=(product(),))]
    assert assess(findings, statements)[0] == [statements[0]] * 3


def test_a_product_covers_whole_segments_only() -> None:
    statements = [verdict(products=(product("container", "ns/app"),))]
    assert assess([finding(target="ns/application")], statements)[0] == [None]


def test_other_products_and_vulnerabilities_dont_match() -> None:
    statements = [verdict(products=("pkg:golang/example.com/app",)), verdict(cve="CVE-2")]
    decided, unmatched = assess([finding()], statements)
    assert decided == [None]
    assert unmatched == statements


def test_an_alias_matches() -> None:
    statements = [verdict(cve="GHSA-1", aliases=("CVE-1",))]
    assert assess([finding()], statements)[0] == statements


def test_the_latest_statement_decides() -> None:
    older = verdict("under_investigation", (product("container", "ns/app"),), day=1)
    newer = verdict("affected", (product(),), day=2)
    assert assess([finding()], [newer, older])[0] == [newer]
    # Statements made at the same time: the last one read.
    again = verdict("fixed", (product(),), day=2)
    assert assess([finding()], [newer, again])[0] == [again]


def test_superseded_statements_still_match() -> None:
    older, newer = verdict(day=1), verdict("affected", day=2)
    assert assess([finding()], [older, newer]) == ([newer], [])


def test_assessment() -> None:
    assert assessment(verdict()) == ("not_affected", "component_not_present")
    assert assessment(verdict("affected")) == ("affected", "")
