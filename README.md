# advisory-map

Matches the software versions a Prometheus-compatible server (Prometheus, VictoriaMetrics, ...) knows
about against vulnerability advisories, and serves the CVEs that apply as Prometheus metrics.

Advisories are downloaded whole and matched locally:

- **Debian Security Tracker**: CVEs per source package and release, with the fixed version.
- **CVE List** ([cvelistV5](https://github.com/CVEProject/cvelistV5)): every CVE record, for the
  products in the [mapping](docs/mapping.md), and the CVSS severity and CWEs of any CVE.
- **OSV** ([osv.dev](https://osv.dev)'s bulk exports): advisories per package ecosystem (Go, PyPI, npm,
  ...), for the packages in the mapping. Where it has records for a CVE in a package, its ranges decide.
- **CISA KEV**: flags matches known to be exploited.
- **MITRE's [CWE](https://cwe.mitre.org) catalogue**: names the weaknesses the records cite.
- **Releases**: the tags of the repositories and images the mapping names, so a CVE List or OSV
  finding's fix is a release that exists ([fixes](docs/mapping.md#fixes)).

Each feed's last good copy is kept in `DATA_DIR`; a failed or invalid download keeps using it. Feeds
are read a record at a time, so memory stays small (~50 MB with the full Debian tracker). The CVE List
is a head-only git clone (~340 MB on disk), and OSV an index of the mapped packages' records (each
ecosystem's archive is downloaded once: 13 MB for Go, 220 MB for npm); each refresh reads only the
records that changed. Findings come from the copies in use while the feeds refresh, so a restart
doesn't wait for them.

A finding's severity is from the source updated most recently: a CVE record's CVSS severity (CNA or
ADP) or GitHub's level in OSV, whichever was updated last, else Debian's urgency. Its weaknesses
(CWEs) are those its CVE record's CNA and ADPs cite, else those of its OSV records.

## Requirements

- **A Prometheus-compatible server** whose query API (`/api/v1/query`) the app can reach. It only
  queries it: the versions must already be scraped there, and scraping advisory-map's own `/metrics`
  is up to you.
- **For Debian hosts:** [node_exporter](https://github.com/prometheus/node_exporter) on each one, with
  the textfile collector, and [contrib/package-versions](contrib/package-versions) writing
  `dpkg_package_info` into it hourly and after every APT run: [Debian hosts](docs/debian-hosts.md).
- **For anything else:** a series with its version in a label, and a [mapping](docs/mapping.md) entry
  for it.
- **Outbound HTTPS** to the feeds (security-tracker.debian.org, github.com,
  osv-vulnerabilities.storage.googleapis.com, www.cisa.gov, cwe.mitre.org), or mirrors for the CVE List
  and OSV (`CVELIST_URL`, `OSV_URL`), and to the git hosts and registries the mapping's `releases`
  name. Nothing about what's installed is sent: only the mapped names are looked up.
- **A writable `DATA_DIR`**, 2 GB to be safe: the CVE List's clone (twice its size while it's
  repacked), the Debian tracker, and each mapped ecosystem's archive while it's first read.

## Versions it reads

- `node_os_info{id="debian", version_codename, instance}`: node_exporter's, for each host's release.
- `dpkg_package_info{instance, package, version, source, source_version}`: one series per installed
  package, from node_exporter's textfile collector ([contrib/package-versions](contrib/package-versions)).

Hosts are matched on `instance`, so both series need the same one for a host.

Anything else with a version in a label (an OS, container images, a Helm release, a `*_build_info`
series) is matched against the CVE List and OSV through the [mapping](docs/mapping.md), which can also
report the running images it doesn't cover.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `PROMETHEUS_URL` | (required) | the server's base URL, where versions are queried |
| `PROMETHEUS_CA_FILE` | (system CAs) | CA bundle for `PROMETHEUS_URL` |
| `MAPPING_FILE` | (none) | the [mapping](docs/mapping.md) of series to CVE List products and OSV packages |
| `CVELIST_URL` | `https://github.com/CVEProject/cvelistV5.git` | where the CVE List is fetched from (a mirror) |
| `OSV_URL` | `https://osv-vulnerabilities.storage.googleapis.com` | where OSV's exports are fetched from (a mirror) |
| `DATA_DIR` | `/data` | the feeds' copies |
| `LISTEN_PORT` | `8080` | `/metrics` |
| `MATCH_INTERVAL` | `15m` | how often versions are read and matched |
| `FEED_REFRESH` | `24h` | how often the feeds are refreshed (conditional GETs, git fetches, changed records) |
| `FEED_REFRESH_<FEED>` | `FEED_REFRESH` | per feed: `DEBIAN`, `CVELIST`, `OSV`, `KEV`, `CWE`, `RELEASES` |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |

## Metrics

- `advisory_map_vulnerability_info{cve, severity, severity_source, source, target_kind, target, namespace, package, installed_version, fixed_version, status, kev, kev_date_added, kev_ransomware}`: 1 per CVE that applies (an OSV advisory's own ID where it has no CVE), gone once it doesn't. `source` is `debian`, `cve.org` or `osv`; `status` is `fix-available`, or why there's no fix (`open`, `no-dsa`, `postponed`, `ignored`, `undetermined`), or `unconfirmed`: affected only by the record's default (see [versions](docs/mapping.md#versions)).
- `advisory_map_vulnerability_cwe_info{cve, cwe, cwe_name}`: 1 per weakness (CWE) of a CVE in `advisory_map_vulnerability_info`, with its name in the catalogue (empty for an ID it doesn't have). Joined on `cve`, e.g. CVEs per weakness: `count by (cwe, cwe_name) (advisory_map_vulnerability_cwe_info and on (cve) advisory_map_vulnerability_info{target_kind="debian-package"})`.
- `advisory_map_inventory_packages{target_kind, target}`: packages known per host (0: no `dpkg_package_info` for it), and mapped installations per target.
- `advisory_map_unmapped_image_info{image}`: a running image no mapping entry covers, when the mapping has an `[images]` query.
- `advisory_map_unmatched_records{source, reason}`: affected ranges that couldn't be compared with an installed version in the last match (`git` commits, `unspecified` or `unparsable` versions, OSV `ecosystem` ranges without a list of versions), so they're neither findings nor silently dropped.
- `advisory_map_feed_last_success_timestamp_seconds{feed}`, `advisory_map_feed_last_attempt_timestamp_seconds{feed}`, `advisory_map_feed_records{feed}`.
- `advisory_map_match_last_success_timestamp_seconds`.

## Development

The package `advisory_map` (tests mirror it):

- `inventory/`: what's installed, from Prometheus (`debian.py` hosts and packages, `mapping.py` everything else).
- `advisories/`: a module per feed (`debian.py`, `cvelist.py`, `osv.py`, `kev.py`, `cwe.py`, `releases.py`), each with its matcher; `feed.py` is their base, `ranges.py` the version ranges they match.
- `common/`: HTTP and streamed JSON.
- `app.py` the match loop, `findings.py` its result, `metrics.py` `/metrics`, `config.py` the settings.

```sh
python -m venv venv && . venv/bin/activate
pip install -e ".[dev]"
pytest
```

A version tag (`X.Y.Z`, or `X.Y.Z-rcN`) builds and pushes `hirednoobs/advisory-map:<tag>`.
