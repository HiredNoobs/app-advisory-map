"""Verdicts on findings, as the OpenVEX documents (https://github.com/openvex/spec, v0.2.0) in VEX_DIR. A
statement's products are installations, as IRIs of advisory-map's own: every installation, a kind's, or
a target's. Statements are never edited: a later one about the same vulnerability and installation takes
over, so a document is also its verdicts' history. Those that apply to nothing any more are moved to an
archive of the same documents, which isn't read."""

import json
import logging
import re
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from advisory_map.advisories.feed import write_atomic

log = logging.getLogger(__name__)

CONTEXT = "https://openvex.dev/ns/v0.2.0"
PRODUCT = "advisory-map:installation"
# The directory in VEX_DIR where Store.archive moves statements: its documents aren't read.
ARCHIVE = "archive"
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)


def product(kind: str | None = None, target: str | None = None) -> str:
    """The product naming every installation, those of a kind, or one target. A kind is one segment of
    the IRI, a target as many as its labels: a product also covers the targets under it."""
    if target is not None and kind is None:
        raise ValueError("a target needs its kind")
    segments = [quote(kind, safe="")] if kind is not None else []
    if target is not None:
        segments.append(quote(target, safe="/"))
    return "/".join([PRODUCT, *segments])


@dataclass(frozen=True)
class Statement:
    vulnerability: str
    aliases: tuple[str, ...]
    # Product IRIs: the @id of each, else its purl.
    products: tuple[str, ...]
    status: str
    justification: str
    impact_statement: str
    action_statement: str
    timestamp: datetime
    author: str

    @property
    def names(self) -> set[str]:
        """Every ID the vulnerability is known by."""
        return {self.vulnerability, *self.aliases}


class Invalid(ValueError):
    """A document, or a statement, that isn't valid OpenVEX."""


def _text(item: dict[str, Any], key: str) -> str:
    value = item.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise Invalid(f"{key} isn't text")
    return value


def _timestamp(text: Any, key: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text)
    except TypeError, ValueError:
        raise Invalid(f"{key} isn't an ISO 8601 timestamp: {text!r}") from None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _product(item: Any) -> str:
    """A product's @id, else its purl."""
    if isinstance(item, dict):
        identifiers = item.get("identifiers")
        found = item.get("@id") or (identifiers.get("purl") if isinstance(identifiers, dict) else None)
        if found and isinstance(found, str):
            return found
    raise Invalid("products: each needs an @id or a purl")


def _statement(item: Any, author: str, timestamp: datetime) -> Statement:
    """A statement, with what it inherits from its document."""
    if not isinstance(item, dict):
        raise Invalid("a statement isn't an object")
    vulnerability = item.get("vulnerability")
    name = vulnerability.get("name") if isinstance(vulnerability, dict) else vulnerability
    if not name or not isinstance(name, str):
        raise Invalid("vulnerability: needs a name")
    aliases = vulnerability.get("aliases", []) if isinstance(vulnerability, dict) else []
    if not isinstance(aliases, list):
        raise Invalid(f"{name}: aliases: a list")
    products = item.get("products")
    if not products or not isinstance(products, list):
        raise Invalid(f"{name}: products: needs at least one")
    status = item.get("status")
    if status not in STATUSES:
        raise Invalid(f"{name}: status must be one of {', '.join(STATUSES)}, not {status!r}")
    justification = _text(item, "justification")
    if justification and justification not in JUSTIFICATIONS:
        raise Invalid(f"{name}: justification must be one of {', '.join(JUSTIFICATIONS)}, not {justification!r}")
    impact = _text(item, "impact_statement")
    action = _text(item, "action_statement")
    if status == "not_affected" and not (justification or impact):
        raise Invalid(f"{name}: not_affected needs a justification or an impact_statement")
    if status == "affected" and not action:
        raise Invalid(f"{name}: affected needs an action_statement")
    return Statement(
        vulnerability=name,
        aliases=tuple(str(alias) for alias in aliases),
        products=tuple(_product(entry) for entry in products),
        status=status,
        justification=justification,
        impact_statement=impact,
        action_statement=action,
        timestamp=_timestamp(item["timestamp"], "timestamp") if item.get("timestamp") else timestamp,
        author=author,
    )


def _document(raw: bytes) -> tuple[dict[str, Any], list[Statement]]:
    """The document, and its statements: Invalid if it or any of them isn't valid."""
    try:
        content = json.loads(raw)
    except ValueError as error:
        raise Invalid(f"not JSON: {error}") from None
    if not isinstance(content, dict):
        raise Invalid("not an object")
    if not str(content.get("@context", "")).startswith("https://openvex.dev/ns"):
        raise Invalid(f"@context isn't OpenVEX's: {content.get('@context')!r}")
    for key in ("@id", "author", "timestamp"):
        if not content.get(key) or not isinstance(content[key], str):
            raise Invalid(f"{key}: required")
    if not isinstance(content.get("version"), int):
        raise Invalid("version: required, an integer")
    timestamp = _timestamp(content["timestamp"], "timestamp")
    statements = content.get("statements")
    if not isinstance(statements, list):
        raise Invalid("statements: required, a list")
    return content, [_statement(item, content["author"], timestamp) for item in statements]


def _file_name(author: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", author.lower()).strip("-.")
    if not slug:
        raise ValueError(f"no file name in the author {author!r}")
    return f"{slug}.json"


class Store:
    """The documents in a directory, read again when a file changes. A document that isn't valid, or
    can't be read, is left out whole, and listed in invalid with the reason."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.invalid: dict[str, str] = {}
        self._seen: tuple[tuple[str, int, int], ...] | None = None
        self._statements: list[Statement] = []

    def _files(self) -> list[Path]:
        if not self.path.is_dir():
            return []
        return sorted(path for path in self.path.glob("*.json") if not path.name.startswith("."))

    @staticmethod
    def _version(path: Path) -> tuple[str, int, int]:
        """The file's name, modification time and size: what changes when it's written."""
        try:
            stat = path.stat()
        except OSError:
            return path.name, -1, -1
        return path.name, stat.st_mtime_ns, stat.st_size

    def statements(self) -> list[Statement]:
        files = self._files()
        seen = tuple(self._version(path) for path in files)
        if seen != self._seen:
            # Swapped in whole: scrapes can read them at the same time.
            statements: list[Statement] = []
            invalid: dict[str, str] = {}
            for path in files:
                try:
                    statements.extend(_document(path.read_bytes())[1])
                except (Invalid, OSError) as error:
                    invalid[path.name] = str(error)
                    log.warning("VEX document %s left out: %s", path.name, error)
            self._statements, self.invalid, self._seen = statements, invalid, seen
        return self._statements

    def add(
        self,
        author: str,
        vulnerability: str,
        product_id: str,
        status: str,
        now: datetime,
        justification: str = "",
        impact_statement: str = "",
        action_statement: str = "",
    ) -> Statement:
        """A statement appended to the author's document (created without one), which is written whole."""
        item: dict[str, Any] = {
            "vulnerability": {"name": vulnerability},
            "products": [{"@id": product_id}],
            "status": status,
            "justification": justification,
            "impact_statement": impact_statement,
            "action_statement": action_statement,
            "timestamp": now.isoformat(),
        }
        item = {key: value for key, value in item.items() if value}
        statement = _statement(item, author, now)
        path = self.document(author)
        content = _opened(path, author, now)
        content["statements"].append(item)
        _write(path, content)
        return statement

    def document(self, author: str) -> Path:
        """The author's document, where add writes their statements."""
        return self.path / _file_name(author)

    def _own(self) -> Iterator[tuple[Path, dict[str, Any], list[Statement]]]:
        """Each author's own document (named for its author: the one add writes), with its statements.
        Those that aren't valid are left out, as they are when read."""
        for path in self._files():
            try:
                content, statements = _document(path.read_bytes())
                own = path.name == _file_name(content["author"])
            except ValueError, OSError:
                continue
            if own:
                yield path, content, statements

    def archivable(self, statements: Iterable[Statement]) -> list[Statement]:
        """Those of these statements that archive would move: the ones in authors' own documents."""
        wanted = set(statements)
        return [statement for _, _, own in self._own() for statement in own if statement in wanted]

    def archive(self, statements: Iterable[Statement], now: datetime) -> list[Statement]:
        """Those of these statements in authors' own documents, moved to the authors' documents in the
        archive (VEX_DIR/archive, which isn't read), each with its timestamp. Each archive is written
        before the document its statements leave: after a crash between the two, a statement in both is
        archived once when it's moved again."""
        wanted = set(statements)
        # Every document and archive read first: one that isn't valid stops the move before any write.
        moving = [
            (path, content, own, _opened(self.path / ARCHIVE / path.name, content["author"], now))
            for path, content, own in self._own()
            if wanted.intersection(own)
        ]
        moved = []
        for path, content, own, archived in moving:
            kept = []
            for item, statement in zip(content["statements"], own):
                if statement not in wanted:
                    kept.append(item)
                    continue
                item = {"timestamp": statement.timestamp.isoformat()} | item
                if item not in archived["statements"]:
                    archived["statements"].append(item)
                moved.append(statement)
            _write(self.path / ARCHIVE / path.name, archived)
            content["statements"] = kept
            _write(path, _changed(content, now))
        return moved


def _opened(path: Path, author: str, now: datetime) -> dict[str, Any]:
    """The author's document at path, to be changed, or a new one."""
    if not path.exists():
        return {
            "@context": CONTEXT,
            "@id": f"urn:uuid:{uuid.uuid4()}",
            "author": author,
            "timestamp": now.isoformat(),
            "version": 1,
            "statements": [],
        }
    content, _ = _document(path.read_bytes())
    if content["author"] != author:
        raise ValueError(f"{path.name} is {content['author']!r}'s document")
    return _changed(content, now)


def _changed(content: dict[str, Any], now: datetime) -> dict[str, Any]:
    """The document with its next version."""
    content["version"] += 1
    content["last_updated"] = now.isoformat()
    return content


def _write(path: Path, content: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(path, (json.dumps(content, indent=2) + "\n").encode())
