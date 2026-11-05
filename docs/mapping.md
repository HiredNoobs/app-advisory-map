# Mapping

`MAPPING_FILE` is a TOML file saying which series are installations of what. Each `[[software]]` entry
is a PromQL query; every series it returns is one installation, matched against the CVE List records
that name its product, the OSV advisories for its package, or both.

```toml
# Running images: those no entry covers are reported.
[images]
query = "kube_pod_container_info"

# An OS, from node_exporter.
[[software]]
query = 'node_os_info{id="talos"}'
vendor = "siderolabs"
product = "talos"
version_label = "version_id"
version_regex = 'v?(.+)'
kind = "os"

# Container images, from kube-state-metrics: in the CVE List and in OSV.
[[software]]
query = 'kube_pod_container_info{image=~".*/vault:.*"}'
vendor = "hashicorp"
product = "vault"
ecosystem = "Go"
package = "github.com/hashicorp/vault"
version_label = "image"
version_regex = ':v?([0-9][^@]*)'
target_labels = ["namespace", "pod", "container"]

# A Helm release, from Flux: its pods' images are covered by this entry.
[[software]]
query = 'gotk_resource_info{customresource_kind="HelmRelease", name="cert-manager"}'
ecosystem = "Go"
package = "github.com/cert-manager/cert-manager"
version_label = "chart_app_version"
target_labels = ["exported_namespace", "name"]
images = '^quay\.io/jetstack/cert-manager-'

# A binary's own build info.
[[software]]
query = "grafana_build_info"
vendor = "grafana"
product = "grafana"
```

| Key | Default | Meaning |
| --- | --- | --- |
| `query` | (required) | an instant query; each series is an installation |
| `vendor`, `product` | | the product as CVE records name it (`affected[].vendor` and `.product`), in any case |
| `ecosystem`, `package` | | the package as OSV names it (`affected[].package`): an ecosystem as its exports do (`Go`, `PyPI`, `npm`, `crates.io`, ...), and the exact name |
| `version_label` | `version` | the label holding the version |
| `version_regex` | (none) | the version is its first group (or its whole match, without groups); a series it doesn't match is skipped |
| `target_labels` | `["instance"]` | the labels naming an installation, joined with `/` into the findings' `target` |
| `kind` | `software` | the findings' `target_kind` |
| `images` | (none) | a regex of the images the entry covers when its series don't carry them (an `image` label) |

An entry needs a product, a package, or both. A series' `namespace` label, if it has one, becomes the
findings' `namespace`.

## Unmapped images

With an `[images]` query (`label` is the label holding each image, `image` by default), every running
image not covered by an entry is served as `advisory_map_unmapped_image_info{image}`, so the gaps show.
An image is covered when an entry's series that gave a version carries it, or the entry's `images`
regex matches it; images are compared without their digests. An image whose version an entry couldn't
read (a `latest` tag its regex skips) is reported too.

## Product and package names

CVE records name a product the way their CNA does, so look at a recent record for it on
[cve.org](https://www.cve.org/): the vendor and product in its affected list. Some products are named
more than one way (a vendor's own records, and GitHub's as `owner`/`repository`); give each name its own
entry with the same query.

OSV names a package as its ecosystem does: a Go module path, a PyPI or npm package name. An advisory on
[osv.dev](https://osv.dev/) shows it under "Affected packages".

Where an installation has a package, OSV decides the CVEs it has records for in that package: its
ranges are per package version, where CVE records often only name releases loosely. The CVE List adds
the rest (a vendor's advisories that never reached a package database).

OSV's records of one vulnerability (GitHub's, the Go team's, ...) become one finding. Where they
disagree, those that say where the affected versions end (every range ends in a fix or a last affected
version) decide over those that leave a range open. A range is left open when the fix isn't a version
of the package: the Go module, for apps released as Grafana 13 or Vault 2 without a `/v13` or `/v2`
module path. Where every OSV record leaves it open, a CVE record that says where it ends decides
instead, under any of the installation's entries (the entries with the same query).

Changing the mapping's products or packages makes the next refresh read every record of that source
again (about a minute for the CVE List, seconds for an OSV ecosystem), instead of only the changed ones.
Meanwhile the findings of what's still mapped stay, from the records already read.

## Versions

Versions are compared as most projects number them: `1.2.3-rc.1` < `1.2.3` < `1.2.10`, with a leading
`v` and `+build` metadata ignored. A range that can't be compared isn't guessed at: it's counted in
`advisory_map_unmatched_records` by reason:

- `git`: given as commits.
- `unspecified`, `unparsable`: no version, or one that isn't a version.
- `ecosystem` (OSV): a range in an ecosystem whose ordering isn't the one above (PyPI's PEP 440,
  Maven's, ...), in a record without its list of affected versions. Records with the list (most do)
  are matched by it.

A CVE record that lists only affected versions but sets `defaultStatus` to `affected` makes every other
version affected too, including every later, fixed release; some vendors' records are written that
way. A version outside its ranges is a finding with `status="unconfirmed"`: only the default says it's
affected. Records that also list
unaffected versions (`unaffected` from the fix onwards, `affected` by default) are matched as written.
