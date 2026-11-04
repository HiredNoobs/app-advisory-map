from pathlib import Path
from typing import Any

import pytest

from advisory_map.inventory.mapping import (
    Found,
    Installed,
    Package,
    Product,
    find,
    load_mapping,
)

MAPPING = """
[images]
query = "kube_pod_container_info"

[[software]]
query = 'node_os_info{id="talos"}'
vendor = "SideroLabs"
product = "Talos"
version_label = "version_id"
version_regex = 'v?(.+)'
kind = "os"

[[software]]
query = 'kube_pod_container_info{image=~".*/vault:.*"}'
vendor = "hashicorp"
product = "vault"
ecosystem = "Go"
package = "github.com/hashicorp/vault"
version_label = "image"
version_regex = '(?<=:)[0-9.]+'
target_labels = ["namespace", "pod", "container"]

[[software]]
query = 'gotk_resource_info{customresource_kind="HelmRelease", name="cert-manager"}'
ecosystem = "Go"
package = "github.com/cert-manager/cert-manager"
version_label = "chart_app_version"
target_labels = ["exported_namespace", "name"]
images = '^quay\\.io/jetstack/cert-manager-'
"""


def mapping_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "mapping.toml"
    path.write_text(text)
    return path


def test_load_mapping(tmp_path: Path) -> None:
    mapping = load_mapping(mapping_file(tmp_path, MAPPING))
    talos, vault, cert_manager = mapping.software
    assert (talos.product, talos.package) == (Product("siderolabs", "talos"), None)
    assert (talos.version_label, talos.target_labels, talos.kind) == ("version_id", ("instance",), "os")
    assert (vault.product, vault.package) == (
        Product("hashicorp", "vault"),
        Package("Go", "github.com/hashicorp/vault"),
    )
    assert (vault.kind, vault.target_labels) == ("software", ("namespace", "pod", "container"))
    assert cert_manager.product is None and cert_manager.images is not None
    assert (mapping.images_query, mapping.image_label) == ("kube_pod_container_info", "image")


@pytest.mark.parametrize(
    "text",
    [
        '[[software]]\nquery = "x"',
        '[[software]]\nquery = "x"\nvendor = "v"',
        '[[software]]\nquery = "x"\necosystem = "Go"',
        '[[software]]\nquery = "x"\nvendor = "v"\nproduct = "p"\nversion_regex = "("',
    ],
)
def test_load_mapping_rejects(tmp_path: Path, text: str) -> None:
    with pytest.raises(ValueError, match="entry 1"):
        load_mapping(mapping_file(tmp_path, text))


def test_images_need_a_query(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"\[images\]"):
        load_mapping(mapping_file(tmp_path, '[images]\nlabel = "image"'))


class FakePrometheus:
    def __init__(self, series: dict[str, list[dict[str, str]]]) -> None:
        self.series = series

    def query(self, promql: str) -> list[dict[str, Any]]:
        return [{"metric": labels} for labels in self.series[promql]]


def pod(name: str, image: str, namespace: str = "vault") -> dict[str, str]:
    return {"namespace": namespace, "pod": name, "container": name.rsplit("-", 1)[0], "image": image}


def test_find(tmp_path: Path) -> None:
    vault = pod("vault-0", "hashicorp/vault:2.1.2@sha256:ab")
    latest = pod("vault-1", "hashicorp/vault:latest")
    cert_manager = pod("cert-manager-0", "quay.io/jetstack/cert-manager-controller:v1.16.2", "cert-manager")
    prometheus = FakePrometheus(
        {
            'node_os_info{id="talos"}': [
                {"instance": "node-1", "version_id": "v1.14.4"},
                # No version: skipped.
                {"instance": "node-2"},
            ],
            # The regex doesn't match vault:latest: skipped, and so unmapped.
            'kube_pod_container_info{image=~".*/vault:.*"}': [vault, latest],
            'gotk_resource_info{customresource_kind="HelmRelease", name="cert-manager"}': [
                {"exported_namespace": "cert-manager", "name": "cert-manager", "chart_app_version": "v1.16.2"}
            ],
            "kube_pod_container_info": [vault, latest, cert_manager, pod("redis-0", "redis:8.2", "redis")],
        }
    )
    assert find(prometheus, load_mapping(mapping_file(tmp_path, MAPPING))) == Found(  # type: ignore[arg-type]
        [
            Installed("os", "node-1", "", Product("siderolabs", "talos"), None, "1.14.4"),
            Installed(
                "software",
                "cert-manager/cert-manager",
                "",
                None,
                Package("Go", "github.com/cert-manager/cert-manager"),
                "v1.16.2",
            ),
            Installed(
                "software",
                "vault/vault-0/vault",
                "vault",
                Product("hashicorp", "vault"),
                Package("Go", "github.com/hashicorp/vault"),
                "2.1.2",
            ),
        ],
        ["hashicorp/vault:latest", "redis:8.2"],
    )
