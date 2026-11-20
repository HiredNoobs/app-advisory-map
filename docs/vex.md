# Verdicts

A finding says a vulnerable version is running, not that it can be exploited where it runs: the
vulnerable feature may be turned off, or the component never reached. A verdict records that judgement,
as an [OpenVEX](https://github.com/openvex/spec) (v0.2.0) statement in a document in `VEX_DIR`. Each
finding is served with the verdict that applies to it, so a dashboard can tell the findings nobody has
looked at from those that were judged harmless:

```promql
advisory_map_vulnerability_info{assessment="unassessed"}
advisory_map_vulnerability_info{assessment!="not_affected"}
```

`assessment` is the verdict's status, or `unassessed` without one; `justification` is its
justification, if it gives one. The documents are read again whenever one changes, at the next scrape.

## The command line

`advisory-map vex` runs in the app's container, where `VEX_DIR` is set and the app's `/metrics` (the
findings) is on `127.0.0.1:$LISTEN_PORT`:

```sh
kubectl -n advisory-map exec deploy/advisory-map -- advisory-map vex list --unassessed
kubectl -n advisory-map exec deploy/advisory-map -- advisory-map vex add CVE-2026-0001 \
  --kind container --target web/frontend \
  --status not_affected --justification vulnerable_code_not_in_execute_path \
  --impact "The OIDC login is not configured" --author alice
kubectl -n advisory-map exec -it deploy/advisory-map -- advisory-map vex tui --author alice
```

(`docker exec` works the same way.) Whoever can exec into the container can add verdicts: there's no
port to secure.

- `list`: the findings with their assessments; `--unassessed` for those without a verdict, `--cve` for
  one CVE's.
- `add <cve> --status <status>`: a verdict on the CVE wherever it's found, or only on `--kind`'s
  installations (a finding's `target_kind`), or only on `--target` and the targets under it (a
  finding's `target`, with its `--kind`). `not_affected` needs a `--justification` or an `--impact`
  (why, in words), `affected` an `--action` (what to do about it). It says how many findings the
  verdict applies to.
- `tui`: the findings in a table (`u` shows only the unassessed, `r` reads them again), and a form for
  a verdict on the selected one (`a` or Enter).

The author is `--author`, or `VEX_AUTHOR`. `--vex-dir` and `--url` (the app's `/metrics`) are for
running it elsewhere.

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
made, and increments its version; statements are never changed or removed. Of the statements about a
finding, the latest decides, so a document is also its verdicts' history.

Other documents in `VEX_DIR` (any `*.json`) are read too, but never written: they can come from
elsewhere, such as [vexctl](https://github.com/openvex/vexctl). A document that isn't valid OpenVEX is
left out whole, logged, and counted in `advisory_map_vex_invalid_documents`.

A statement's products are installations, as IRIs of advisory-map's own:

| Product `@id` | Covers |
| --- | --- |
| `advisory-map:installation` | every installation |
| `advisory-map:installation/<kind>` | every installation of a kind (a finding's `target_kind`) |
| `advisory-map:installation/<kind>/<target>` | a finding's `target`, and the targets under it (`container/monitoring` covers every container in `monitoring`) |

Kinds and targets are percent-encoded, except a target's `/`. A statement applies to a finding when its
vulnerability's name or one of its aliases is the finding's `cve`, and one of its products covers the
finding's installation. Statements about other products (purls) are read, but apply to nothing.

Statements that apply to no finding, their vulnerability fixed or their installations gone, are
counted in `advisory_map_vex_unmatched_statements`.

`VEX_DIR` isn't a cache: back it up, and keep it apart from `DATA_DIR`, which can be thrown away.
