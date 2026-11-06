# Debian hosts

A Debian host's findings need two series from its node_exporter, with the same `instance` once
scraped:

- `node_os_info`, from node_exporter's os collector (on by default): the host's release.
- `dpkg_package_info`, one per installed package, which [contrib/package-versions](../contrib/package-versions)
  writes into the textfile collector's directory.

The examples use `/var/lib/node_exporter/textfile` as that directory and `node_exporter` as the
exporter's user. Debian's `prometheus-node-exporter` package uses `/var/lib/prometheus/node-exporter`
and the user `prometheus`.

## node_exporter

Start it with the textfile collector's directory, e.g.
`--collector.textfile.directory=/var/lib/node_exporter/textfile`, and create the directory, writable by
the user the script runs as:

```sh
install -d -o node_exporter -g node_exporter -m 0755 /var/lib/node_exporter/textfile
```

## The script

```sh
install -m 0755 contrib/package-versions /usr/local/bin/package-versions
```

It writes every installed package to the file it's given, replacing it whole, and fails without
touching it if `dpkg-query` fails.

## Running it

Hourly, and after every APT run so upgrades show at once:

```ini
# /etc/systemd/system/package-versions.service
[Unit]
Description=Write the installed Debian packages for node_exporter

[Service]
Type=oneshot
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/package-versions /var/lib/node_exporter/textfile/package-versions.prom
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/node_exporter/textfile
ProtectHome=yes
PrivateTmp=yes
```

```ini
# /etc/systemd/system/package-versions.timer
[Unit]
Description=Hourly package versions for node_exporter

[Timer]
OnCalendar=hourly

[Install]
WantedBy=timers.target
```

```text
// /etc/apt/apt.conf.d/90package-versions: without waiting for it, and never failing APT.
DPkg::Post-Invoke { "systemctl start --no-block package-versions.service || true"; };
```

```sh
systemctl daemon-reload
systemctl enable --now package-versions.timer
systemctl start package-versions.service
```

## Checking it

On the host, a series per installed package and no textfile error:

```sh
curl -s localhost:9100/metrics | grep -c '^dpkg_package_info{'
dpkg-query -W -f '${db:Status-Status}\n' | grep -c '^installed$'
curl -s localhost:9100/metrics | grep '^node_textfile_scrape_error'
```

A package installed for two architectures counts once in the first and twice in the second. After
advisory-map's next match, `advisory_map_inventory_packages{target="<instance>"}` counts the host's
source packages (Debian's tracker is by source package, so it's fewer than the series); 0 means it has
`node_os_info` but no `dpkg_package_info` with the same `instance`.
