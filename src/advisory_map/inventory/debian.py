"""Debian hosts and their packages, from node_exporter: node_os_info, and dpkg_package_info from a textfile
(see the README)."""

from collections import defaultdict
from dataclasses import dataclass

from advisory_map.inventory.prometheus import PrometheusAPI


@dataclass(frozen=True)
class DebianHost:
    instance: str
    # The release's codename (e.g. trixie), the tracker's key.
    release: str
    # (source package, source version): the tracker is by source package. A source can be in more than
    # one version while an upgrade is partial.
    packages: frozenset[tuple[str, str]]


def debian_hosts(prometheus: PrometheusAPI) -> list[DebianHost]:
    """The Debian hosts with their packages. Hosts are told apart by their instance label."""
    packages: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for series in prometheus.query("dpkg_package_info"):
        labels = series["metric"]
        packages[labels["instance"]].add((labels["source"], labels["source_version"]))
    hosts = []
    for series in prometheus.query('node_os_info{id="debian"}'):
        instance, release = series["metric"]["instance"], series["metric"]["version_codename"]
        hosts.append(DebianHost(instance, release, frozenset(packages[instance])))
    return hosts
