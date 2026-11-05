"""MITRE's CWE catalogue: the names of the weaknesses that CVE records and OSV advisories cite by ID."""

import zipfile
from pathlib import Path
from xml.etree import ElementTree

from advisory_map.advisories.feed import Download

# The catalogue's entries a record can cite: weaknesses, groupings (categories, in older releases) and views.
_ENTRIES = {"Weakness", "Grouping", "Category", "View"}


class Cwe(Download[dict[str, str]]):
    name = "cwe"
    url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    def __init__(self, data_dir: Path) -> None:
        super().__init__(data_dir)
        self.path = data_dir / "cwe.xml.zip"

    def parse(self, path: Path) -> dict[str, str]:
        """CWE ID -> name. The ~20 MB of XML is streamed, each entry dropped once read; the namespace,
        which names the schema's version, is ignored."""
        names = {}
        with zipfile.ZipFile(path) as archive, archive.open(archive.namelist()[0]) as xml:
            for _, element in ElementTree.iterparse(xml):
                if element.tag.rpartition("}")[2] in _ENTRIES:
                    names[f"CWE-{element.get('ID')}"] = element.get("Name", "")
                    element.clear()
        if not names:
            raise ValueError("no CWE entries")
        return names

    def records(self) -> int:
        return len(self.data or {})
