"""Which verdict applies to each finding: the latest statement naming its vulnerability and covering its
installation."""

from collections.abc import Iterable, Sequence

from advisory_map.findings import Finding
from advisory_map.vex.openvex import Statement, product


def _covers(scope: str, installation: str) -> bool:
    """Whether a statement's product covers an installation: it's that one, or one above it."""
    return installation == scope or installation.startswith(f"{scope}/")


def assess(
    findings: Sequence[Finding], statements: Iterable[Statement]
) -> tuple[list[Statement | None], list[Statement]]:
    """Each finding's verdict (None without one), and the statements that match no finding: about a
    vulnerability that's gone, or installations that aren't there. Of statements made at the same time,
    the last one read decides."""
    statements = list(statements)
    decided: list[Statement | None] = []
    matched: set[int] = set()
    for finding in findings:
        installation = product(finding.target_kind, finding.target)
        applying = [
            index
            for index, statement in enumerate(statements)
            if finding.cve in statement.names and any(_covers(scope, installation) for scope in statement.products)
        ]
        matched.update(applying)
        latest = max(applying, key=lambda index: (statements[index].timestamp, index), default=None)
        decided.append(None if latest is None else statements[latest])
    return decided, [statement for index, statement in enumerate(statements) if index not in matched]


def assessment(statement: Statement | None) -> tuple[str, str]:
    """A finding's assessment and justification labels."""
    if statement is None:
        return "unassessed", ""
    return statement.status, statement.justification
