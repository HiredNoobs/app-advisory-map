# Verdicts

A finding says a vulnerable version is running, not that it can be exploited where it runs: the
vulnerable feature may be turned off, or the component never reached. A verdict records that judgement,
as an [OpenVEX](https://github.com/openvex/spec) (v0.2.0) statement in a document in `VEX_DIR`. Each
finding is served with the verdict that applies to it, so a dashboard can tell the findings nobody has
looked at from those that were judged harmless:

```promql
advisory_map_vulnerability_info{assessment=~"unassessed|expired"}
advisory_map_vulnerability_info{assessment!="not_affected"}
```

`assessment` is the verdict's status, `expired` once it no longer holds ([expiry](#expiry)), or
`unassessed` without one; `justification` is its justification, if it gives one. The documents are read
again whenever one changes, at the next scrape.

## The command line

`advisory-map vex` runs in the app's container, where `VEX_DIR` is set and the app's `/metrics` (the
findings and their assessments) is on `127.0.0.1:$LISTEN_PORT`:

```sh
kubectl -n advisory-map exec deploy/advisory-map -- advisory-map vex list --unassessed
kubectl -n advisory-map exec deploy/advisory-map -- advisory-map vex add CVE-2026-0001 \
  --kind container --target web/frontend \
  --status not_affected --justification vulnerable_code_not_in_execute_path \
  --impact "The OIDC login is not configured" --author alice
kubectl -n advisory-map exec -it deploy/advisory-map -- advisory-map vex tui --author alice
```

(`docker exec` works the same way.) Whoever can exec into the container can add verdicts, as anyone.

- `list`: the findings with their assessments; `--unassessed` for those without a verdict that holds
  (`unassessed` or `expired`), `--cve` for one CVE's.
- `add <cve> --status <status>`: a verdict on the CVE wherever it's found, or only on `--kind`'s
  installations (a finding's `target_kind`), or only on `--target` and the targets under it (a
  finding's `target`, with its `--kind`). `not_affected` needs a `--justification` or an `--impact`
  (why, in words), `affected` an `--action` (what to do about it), and no other status takes them. It
  says how many findings the verdict applies to.
- `prune`: the statements that apply to no finding ([unmatched](#unmatched-statements)); `--apply`
  moves them to the archive.
- `tui`: the findings in a table, read again every minute (`r` reads them now), and a form for a verdict
  on the selected one (`a` or Enter) that asks for what its status needs. `u` shows only those without a
  verdict that holds; `/` filters them by words in any column, or `column:value` in one
  (`severity:critical`, `target:web/`), Enter keeping the filter and Escape clearing it. Tab (or →)
  completes the word being typed: a column's name, then its values (severities the most severe first,
  others the most common), or any column's. They're sorted by kind, target and CVE; a column's header,
  or its number (`1` to `8`, left to right), sorts them by it (severity most severe first), again the
  other way, and again as they were, its arrow saying which: ▲, or ▼ reversed. `o` copies the selected
  finding's advisory link to the clipboard of the terminal it's shown in: Debian's security tracker for
  a Debian package, cve.org for any other CVE, osv.dev for the rest.

The author is `--author`, or `VEX_AUTHOR`. `--vex-dir` and `--url` (the app's `/metrics`) are for
running it elsewhere.

## The page

With `WEB_PORT` set, the app also serves a page for a CVE's findings, which a dashboard links to:

```text
/assess?cve=CVE-2026-0001&kind=container&target=web/frontend
/assess?cve=CVE-2026-0002&package=openssl
```

`kind`, `target` and `package` (each optional) narrow it to some of the CVE's findings. It shows them
with their assessments, every statement about the CVE, and a form for a new verdict, which starts from
the one they share. A verdict is never edited: a new one takes over.
It can cover the one target (when the page shows one), every installation of a kind the findings are,
or everything.

The page writes verdicts, so it's on a port of its own, for an authenticating proxy to reach and nothing
else: the app trusts the header `WEB_AUTHOR_HEADER` names to say who's saving, and refuses a save
without it. Set it to the header your proxy passes the signed-in user in: `Remote-User` (Authelia,
Caddy's `forward_auth`), `X-Forwarded-User` (oauth2-proxy), `X-authentik-username` (authentik),
`Tailscale-User-Login` (Tailscale Serve), or whichever an ext-auth or forward-auth setup (Envoy,
Traefik, nginx's `auth_request`) is told to pass on. The proxy must set the header itself, replacing any
the client sent, and nothing else may reach the port: anyone who can send the header can save as
anyone. Forms sent from another site are refused. Without `WEB_AUTHOR_HEADER` the form asks for the
author: only for running it locally.

## Statuses and justifications

| Status | Means |
| --- | --- |
| `not_affected` | It can't be exploited here: needs a justification or an impact statement |
| `affected` | It can: needs an action statement |
| `fixed` | It's been fixed here (a backported patch the version doesn't show) |
| `under_investigation` | Someone's looking into it |

A `not_affected` justification is one of `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary` or
`inline_mitigations_already_exist` ([what each means](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)).

## Documents

Each author has a document, `<author>.json` (the author's name lowercased, characters other than
letters, digits, `.`, `_` and `-` replaced by `-`). `add` appends a statement to it, with when it was
made, and increments its version; statements are never changed, and only `prune` removes them (to the
archive). Of the statements about a finding, the latest decides, so a document is also its verdicts'
history.

Other documents in `VEX_DIR` (any `*.json` whose name doesn't start with a dot) are read too, but never
written: they can come from elsewhere, such as [vexctl](https://github.com/openvex/vexctl). A document
that isn't valid OpenVEX is left out whole, logged, and counted in `advisory_map_vex_invalid_documents`.

A statement's products are installations, as IRIs of advisory-map's own:

| Product `@id` | Covers |
| --- | --- |
| `advisory-map:installation` | every installation |
| `advisory-map:installation/<kind>` | every installation of a kind (a finding's `target_kind`) |
| `advisory-map:installation/<kind>/<target>` | a finding's `target`, and the targets under it (`container/monitoring` covers every container in `monitoring`) |

Kinds and targets are percent-encoded, except a target's `/`. A statement applies to a finding when its
vulnerability's name or one of its aliases is the finding's `cve`, and one of its products covers the
finding's installation. Statements about other products (purls) are read, but apply to nothing.

## Unmatched statements

Statements that apply to no finding, their vulnerability fixed or their installations gone, are
counted in `advisory_map_vex_unmatched_statements`. `prune` lists those in authors' documents, and with
`--apply` moves them to the author's document in `VEX_DIR/archive`: valid OpenVEX, each statement with
when it was made, and not read, so they're kept as history but no longer count. To restore one, move it
back. Documents from elsewhere are never written, so their unmatched statements (and those about purls)
still count.

A finding missing for a while also leaves its statements unmatched: a host Prometheus doesn't scrape
for a time, or a feed whose copy hasn't loaded. `prune` says how many findings there are and when the
app matched them; check that they're all there before `--apply`. It refuses before the app's first
match.

## Expiry

A verdict is judged on what its vulnerability's advisories said at the time. It expires, and the
finding's assessment becomes `expired`, when:

- **The advisories change what they say of how or where it's exploited.** For a CVE, that's its record's
  state, or its CNA's descriptions, affected products, configurations or workarounds: not what's added
  around them (scores, weaknesses, references, an ADP's enrichment). For an advisory without a CVE
  record, its OSV records' affected ranges. The app keeps what they were when each verdict first
  applied to a finding, in `VEX_DIR/.fingerprints.json`.
- **It's been known to be exploited since:** CISA's KEV added it after the day the verdict was made.

A new verdict on the finding, the same as before or not, holds until the next change. Losing
`.fingerprints.json` only loses the comparison: verdicts start again from what the advisories say
when the app next matches.

`VEX_DIR`, its archive included, isn't a cache: back it up, and keep it apart from `DATA_DIR`, which can be thrown away.
