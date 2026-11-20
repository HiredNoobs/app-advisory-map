"""advisory-map vex: verdicts on the findings, run in the app's container (kubectl or docker exec). The
findings and their assessments come from the app's /metrics, which reads the OpenVEX documents in
VEX_DIR again whenever one changes; verdicts are added to them, and those that apply to no finding
archived."""

import argparse
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from prometheus_client.parser import text_string_to_metric_families

from advisory_map.common import http
from advisory_map.findings import Finding
from advisory_map.vex.assess import assess
from advisory_map.vex.openvex import ARCHIVE, JUSTIFICATIONS, STATUSES, Store, product

COLUMNS = ("ASSESSMENT", "CVE", "SEVERITY", "KIND", "TARGET", "PACKAGE", "VERSION", "FIXED")
# Assessments with no verdict that holds.
TO_ASSESS = ("unassessed", "expired")


def now() -> datetime:
    return datetime.now(UTC)


def metrics_url() -> str:
    """The app's /metrics, from inside its container."""
    return f"http://127.0.0.1:{os.environ.get('LISTEN_PORT', '8080')}/metrics"


def served(url: str) -> tuple[list[tuple[Finding, str]], float | None]:
    """The findings the app serves with their assessments, by kind, target and CVE, and when it matched
    them (None: not yet)."""
    found: list[tuple[Finding, str]] = []
    matched = None
    for family in text_string_to_metric_families(http.get(url).body.decode()):
        if family.name == "advisory_map_vulnerability_info":
            found.extend(
                (Finding.from_labels(sample.labels), sample.labels.get("assessment", "")) for sample in family.samples
            )
        elif family.name == "advisory_map_match_last_success_timestamp_seconds":
            matched = family.samples[0].value
    return sorted(found, key=lambda pair: (pair[0].target_kind, pair[0].target, pair[0].cve)), matched


def findings(url: str) -> list[tuple[Finding, str]]:
    return served(url)[0]


def store(args: argparse.Namespace) -> Store:
    path = args.vex_dir or os.environ.get("VEX_DIR")
    if not path:
        raise ValueError("no VEX directory: set VEX_DIR or pass --vex-dir")
    return Store(Path(path))


def _table(rows: Sequence[Sequence[str]]) -> str:
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    return "\n".join("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows)


def row(finding: Finding, assessment: str) -> tuple[str, ...]:
    """A finding's COLUMNS."""
    return (
        assessment,
        finding.cve,
        finding.severity,
        finding.target_kind,
        finding.target,
        finding.package,
        finding.installed_version,
        finding.fixed_version,
    )


def list_findings(args: argparse.Namespace) -> None:
    rows = [
        row(item, assessment)
        for item, assessment in findings(args.url)
        if (not args.unassessed or assessment in TO_ASSESS) and args.cve in (None, item.cve)
    ]
    print(_table([COLUMNS, *rows]))


def add(args: argparse.Namespace) -> None:
    author = args.author or os.environ.get("VEX_AUTHOR")
    if not author:
        raise ValueError("no author: pass --author or set VEX_AUTHOR")
    if args.target is not None and args.kind is None:
        raise ValueError("--target needs --kind")
    product_id = product(args.kind, args.target)
    vex = store(args)
    statement = vex.add(
        author,
        args.cve,
        product_id,
        args.status,
        now(),
        justification=args.justification or "",
        impact_statement=args.impact or "",
        action_statement=args.action or "",
    )
    print(f"{args.cve} {args.status} for {product_id}: added to {vex.document(author)}")
    try:
        found = findings(args.url)
    except OSError as error:
        print(f"Couldn't read the findings to check it ({error}); it's saved all the same.")
        return
    applying = sum(decided is not None for decided in assess([item for item, _ in found], [statement])[0])
    print(
        f"It applies to {applying} finding{'' if applying == 1 else 's'}." if applying else "It applies to no finding."
    )


def prune(args: argparse.Namespace) -> None:
    found, matched = served(args.url)
    if matched is None:
        raise ValueError("the app hasn't matched the findings yet: every statement would look unmatched")
    vex = store(args)
    _, unmatched = assess([item for item, _ in found], vex.statements())
    statements = vex.archive(unmatched, now()) if args.apply else vex.archivable(unmatched)
    rows = [
        (
            statement.author,
            statement.vulnerability,
            statement.status,
            " ".join(statement.products),
            str(statement.timestamp.date()),
        )
        for statement in statements
    ]
    print(_table([("AUTHOR", "CVE", "STATUS", "PRODUCTS", "MADE"), *rows]))
    when = datetime.fromtimestamp(matched, UTC).isoformat(timespec="seconds")
    done = f"moved to {vex.path / ARCHIVE}" if args.apply else "--apply moves them to the archive"
    print(f"These apply to none of the {len(found)} findings the app matched at {when}: {done}.")


def tui(args: argparse.Namespace) -> None:
    # Only here: the rest of the CLI, and the app, run without loading Textual.
    from advisory_map.tui import Tui

    Tui(store(args), args.url, args.author or os.environ.get("VEX_AUTHOR", "")).run()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="advisory-map vex", description="Verdicts on advisory-map's findings.")
    root.add_argument("--vex-dir", help="the OpenVEX documents (default: VEX_DIR)")
    root.add_argument("--url", default=metrics_url(), help="the app's /metrics (default: %(default)s)")
    commands = root.add_subparsers(dest="command", required=True)

    listing = commands.add_parser("list", help="the findings and their assessments")
    listing.add_argument("--unassessed", action="store_true", help="only those without a verdict that holds")
    listing.add_argument("--cve", help="only this CVE's")
    listing.set_defaults(run=list_findings)

    adding = commands.add_parser("add", help="a verdict on a CVE, everywhere or where --kind and --target say")
    adding.add_argument("cve")
    adding.add_argument("--status", required=True, choices=STATUSES)
    adding.add_argument("--kind", help="only installations of this kind (a finding's target_kind)")
    adding.add_argument("--target", help="only this target, or the targets under it (needs --kind)")
    adding.add_argument("--justification", choices=JUSTIFICATIONS, help="why it's not_affected")
    adding.add_argument("--impact", help="why it's not_affected, in words")
    adding.add_argument("--action", help="what to do about it, when it's affected")
    adding.add_argument("--author", help="who's saying so (default: VEX_AUTHOR)")
    adding.set_defaults(run=add)

    pruning = commands.add_parser("prune", help="the statements that apply to no finding, to move to the archive")
    pruning.add_argument("--apply", action="store_true", help="move them (without it, only list them)")
    pruning.set_defaults(run=prune)

    terminal = commands.add_parser("tui", help="the findings and a form for verdicts, in the terminal")
    terminal.add_argument("--author", help="the verdicts' author (default: VEX_AUTHOR)")
    terminal.set_defaults(run=tui)
    return root


def main(argv: Sequence[str]) -> int:
    args = parser().parse_args(argv)
    try:
        args.run(args)
    except (ValueError, OSError) as error:
        print(f"advisory-map vex: {error}", file=sys.stderr)
        return 1
    return 0
