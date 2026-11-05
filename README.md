# advisory-map

Matches the software versions a Prometheus-compatible server (Prometheus, VictoriaMetrics, ...) knows
about against vulnerability advisories, and serves the CVEs that apply as Prometheus metrics.

Advisories are downloaded whole and matched locally:

- **Debian Security Tracker**: CVEs per source package and release, with the fixed version.
- **CVE List** ([cvelistV5](https://github.com/CVEProject/cvelistV5)): every CVE record, for the
  products in the [mapping](docs/mapping.md), and the CVSS severity of any CVE.
- **OSV** ([osv.dev](https://osv.dev)'s bulk exports): advisories per package ecosystem (Go, PyPI, npm,
  ...), for the packages in the mapping. Where it has records for a CVE in a package, its ranges decide.
- **CISA KEV**: flags matches known to be exploited.

Each feed's last good copy is kept in `DATA_DIR`; a failed or invalid download keeps using it. Feeds
are read a record at a time, so memory stays small (~50 MB with the full Debian tracker). The CVE List
is a head-only git clone (~340 MB on disk), and OSV an index of the mapped packages' records (each
ecosystem's archive is downloaded once: 13 MB for Go, 220 MB for npm); each refresh reads only the
records that changed. Findings come from the copies in use while the feeds refresh, so a restart
doesn't wait for them.

A finding's severity is from the source updated most recently: a CVE record's CVSS severity (CNA or
ADP) or GitHub's level in OSV, whichever was updated last, else Debian's urgency.

## Versions it reads

- `node_os_info{id="debian", version_codename, instance}`: node_exporter's, for each host's release.
- `dpkg_package_info{instance, package, version, source, source_version}`: one series per installed
  package, from node_exporter's textfile collector, e.g.

  ```sh
  dpkg-query -W -f '${Package}\t${Version}\t${source:Package}\t${source:Version}\n' |
    awk -F'\t' '{ printf "dpkg_package_info{package=\"%s\",version=\"%s\",source=\"%s\",source_version=\"%s\"} 1\n", $1, $2, $3, $4 }' \
    > /var/lib/node_exporter/dpkg.prom.tmp && mv /var/lib/node_exporter/dpkg.prom.tmp /var/lib/node_exporter/dpkg.prom
  ```

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
| `FEED_REFRESH_<FEED>` | `FEED_REFRESH` | per feed: `DEBIAN`, `CVELIST`, `OSV`, `KEV` |

## Metrics

- `advisory_map_vulnerability_info{cve, severity, severity_source, source, target_kind, target, namespace, package, installed_version, fixed_version, status, kev, kev_date_added, kev_ransomware}`: 1 per CVE that applies (an OSV advisory's own ID where it has no CVE), gone once it doesn't. `source` is `debian`, `cve.org` or `osv`; `status` is `fix-available`, or why there's no fix (`open`, `no-dsa`, `postponed`, `ignored`, `undetermined`), or `unconfirmed`: affected only by the record's default (see [versions](docs/mapping.md#versions)).
- `advisory_map_inventory_packages{target_kind, target}`: packages known per host (0: no `dpkg_package_info` for it), and mapped installations per target.
- `advisory_map_unmapped_image_info{image}`: a running image no mapping entry covers, when the mapping has an `[images]` query.
- `advisory_map_unmatched_records{source, reason}`: affected ranges that couldn't be compared with an installed version in the last match (`git` commits, `unspecified` or `unparsable` versions, OSV `ecosystem` ranges without a list of versions), so they're neither findings nor silently dropped.
- `advisory_map_feed_last_success_timestamp_seconds{feed}`, `advisory_map_feed_last_attempt_timestamp_seconds{feed}`, `advisory_map_feed_records{feed}`.
- `advisory_map_match_last_success_timestamp_seconds`.

## Development

The package `advisory_map` (tests mirror it):

- `inventory/`: what's installed, from Prometheus (`debian.py` hosts and packages, `mapping.py` everything else).
- `advisories/`: a module per feed (`debian.py`, `cvelist.py`, `osv.py`, `kev.py`), each with its matcher; `feed.py` is their base, `ranges.py` the version ranges they match.
- `common/`: HTTP and streamed JSON.
- `app.py` the match loop, `findings.py` its result, `metrics.py` `/metrics`, `config.py` the settings.

```sh
python -m venv venv && . venv/bin/activate
pip install -e ".[dev]"
pytest
```

A version tag (`X.Y.Z`, or `X.Y.Z-rcN`) builds and pushes `hirednoobs/advisory-map:<tag>`.
