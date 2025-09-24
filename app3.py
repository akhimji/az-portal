
#!/usr/bin/env python3
import argparse, csv, json
from collections import defaultdict, Counter
from pathlib import Path
from typing import Any, Dict, Set, List

# ---- Empty value pruning helpers ----
DEFAULT_EMPTY_TOKENS = {"null", "[]", "{}", ""}

def _parse_token_list(args_list):
    tokens = set()
    for item in (args_list or []):
        for t in (x.strip() for x in item.split(",") if x.strip()):
            tokens.add(t)
    return tokens

def _prune_set(values_set, empty_tokens):
    return {v for v in values_set if v not in empty_tokens}

# ---- Normalization ----
def _normalize_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (int, float, bool)):
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    try:
        if isinstance(v, list):
            nv = sorted(_normalize_value(e) for e in v)
            return json.dumps(nv, separators=(",", ":"), sort_keys=True)
        if isinstance(v, dict):
            nv = {k: _normalize_value(vv) for k, vv in v.items()}
            return json.dumps(nv, separators=(",", ":"), sort_keys=True)
    except Exception:
        pass
    try:
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    except Exception:
        return str(v)

# ---- MG extraction ----
def _extract_mg(rec: Dict[str, Any]) -> str | None:
    for key in ("assignmentScope", "scope", "policyScope"):
        scope = rec.get(key)
        if isinstance(scope, str):
            low = scope.lower()
            if "/managementgroups/" in low:
                try:
                    idx = low.index("/managementgroups/")
                    tail = scope[idx + len("/managementgroups/"):]
                    mg = tail.split("/")[0]
                    if mg:
                        return mg
                except Exception:
                    pass
    for key in ("managementGroupId", "managementGroupName", "mg", "mgName", "mgId"):
        mg = rec.get(key)
        if isinstance(mg, str) and mg.strip():
            return mg.strip()
    return None

# ---- Load data ----
def load_data(jsonl_path: Path, requested_fields: Set[str]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    mg_map: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            mg = _extract_mg(rec)
            if not mg:
                continue
            alias = rec.get("policyAlias") or rec.get("alias")
            if not alias:
                continue

            entry = mg_map.setdefault(mg, {}).setdefault(alias, {"values": set(), "fields": defaultdict(set)})
            val = rec.get("resolvedEffectiveValue")
            entry["values"].add(_normalize_value(val))

            for fld in requested_fields:
                if fld in rec:
                    entry["fields"][fld].add(_normalize_value(rec[fld]))
                elif fld == "assignmentDisplayName":
                    for k in ("assignmentDisplayName","displayName"):
                        ad = rec.get(k)
                        if ad:
                            entry["fields"][fld].add(_normalize_value(ad))
                if fld in ("parameters", "resolvedParameters"):
                    for k in ("parameters","resolvedParameters"):
                        if k in rec:
                            entry["fields"][fld].add(_normalize_value(rec[k]))
    return mg_map

# ---- Compute rows ----
def compute_rows(
    mg_map: Dict[str, Dict[str, Dict[str, Any]]],
    source_mg: str,
    dest_mg: str,
    include_equals: bool,
    include_missing: bool,
    alias_filter: Set[str] | None,
    extra_fields: List[str],
    do_prune: bool,
    empty_tokens: Set[str],
    drop_empty_rows: bool,
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []

    src_aliases = set(mg_map.get(source_mg, {}))
    dst_aliases = set(mg_map.get(dest_mg, {}))

    if alias_filter:
        src_aliases &= alias_filter
        dst_aliases &= alias_filter

    common_aliases = sorted(src_aliases & dst_aliases)
    src_only = sorted(src_aliases - dst_aliases) if include_missing else []
    dst_only = sorted(dst_aliases - src_aliases) if include_missing else []

    def field_str(entry: Dict[str, Any], fld: str) -> str:
        vals = entry["fields"].get(fld, set())
        return "; ".join(sorted(vals))

    # Common
    for alias in common_aliases:
        s_entry = mg_map[source_mg][alias]
        d_entry = mg_map[dest_mg][alias]
        s_vals = s_entry["values"]
        d_vals = d_entry["values"]
        if do_prune:
            s_vals = _prune_set(s_vals, empty_tokens)
            d_vals = _prune_set(d_vals, empty_tokens)
        if drop_empty_rows and not s_vals and not d_vals:
            continue
        equal = (s_vals == d_vals)
        if not include_equals and equal:
            continue
        row = {
            "policyAlias": alias,
            "source_mg": source_mg,
            "dest_mg": dest_mg,
            "source_values": "; ".join(sorted(s_vals)),
            "dest_values": "; ".join(sorted(d_vals)),
            "only_in_source": "; ".join(sorted(s_vals - d_vals)) if (s_vals - d_vals) else "",
            "only_in_dest": "; ".join(sorted(d_vals - s_vals)) if (d_vals - s_vals) else "",
        }
        for fld in extra_fields:
            row[f"source_{fld}"] = field_str(s_entry, fld)
            row[f"dest_{fld}"] = field_str(d_entry, fld)
        row["delta"] = "true" if not equal else "false"
        rows.append(row)

    # Source-only
    for alias in src_only:
        s_entry = mg_map[source_mg][alias]
        s_vals = s_entry["values"]
        if do_prune:
            s_vals = _prune_set(s_vals, empty_tokens)
        if drop_empty_rows and not s_vals:
            continue
        row = {
            "policyAlias": alias,
            "source_mg": source_mg,
            "dest_mg": dest_mg,
            "source_values": "; ".join(sorted(s_vals)),
            "dest_values": "",
            "only_in_source": "; ".join(sorted(s_vals)),
            "only_in_dest": "",
        }
        for fld in extra_fields:
            row[f"source_{fld}"] = "; ".join(sorted(s_entry["fields"].get(fld, set())))
            row[f"dest_{fld}"] = ""
        row["delta"] = "true"
        rows.append(row)

    # Destination-only
    for alias in dst_only:
        d_entry = mg_map[dest_mg][alias]
        d_vals = d_entry["values"]
        if do_prune:
            d_vals = _prune_set(d_vals, empty_tokens)
        if drop_empty_rows and not d_vals:
            continue
        row = {
            "policyAlias": alias,
            "source_mg": source_mg,
            "dest_mg": dest_mg,
            "source_values": "",
            "dest_values": "; ".join(sorted(d_vals)),
            "only_in_source": "",
            "only_in_dest": "; ".join(sorted(d_vals)),
        }
        for fld in extra_fields:
            row[f"source_{fld}"] = ""
            row[f"dest_{fld}"] = "; ".join(sorted(d_entry["fields"].get(fld, set())))
        row["delta"] = "true"
        rows.append(row)

    return rows

# ---- Main ----
def main():
    ap = argparse.ArgumentParser(description="Compare policy resolvedEffectiveValue deltas between two management groups (CSV/JSON)")
    ap.add_argument("--file", required=True, help="Path to JSONL source file")
    ap.add_argument("--source", help="Source management group (e.g., mg-01-0002)")
    ap.add_argument("--dest", help="Destination management group (e.g., mg-02-0080)")
    ap.add_argument("--out", default="policy_deltas.csv", help="Output CSV path (default: policy_deltas.csv)")
    ap.add_argument("--json-out", default=None, help="Optional JSON output path (writes same rows as JSON)")
    ap.add_argument("--inspect", action="store_true", help="Print MG and alias inventory and exit")

    ap.add_argument("--include-equals", action="store_true", help="Include aliases where values are equal (delta=false)")
    ap.add_argument("--include-missing", action="store_true", help="Include aliases present in only one MG")
    ap.add_argument("--alias", action="append", default=[], help="Filter to specific alias(es). Repeat or comma-separate")
    ap.add_argument("--include-fields", default="", help="Comma-separated extra fields to include (paired as source_* and dest_*)")
    ap.add_argument("--wide", action="store_true", help="Include a practical wide set of helpful fields")

    ap.add_argument("--prune-empty-values", action="store_true", help="Exclude empty tokens (null/[]/{}/\"\") from comparison and output")
    ap.add_argument("--empty-token", action="append", default=[], help="Additional tokens to treat as empty (repeat or comma-separate)")
    ap.add_argument("--drop-empty-rows", action="store_true", help="After pruning, drop rows where both sides have no values and no extras")

    args = ap.parse_args()
    jsonl_path = Path(args.file)
    if not jsonl_path.exists():
        raise SystemExit(f"File not found: {jsonl_path}")

    wide_fields = [
        "policyDefinitionId",
        "policySetDefinitionId",
        "policyDefinitionReferenceId",
        "policyAssignmentId",
        "assignmentDisplayName",
        "assignmentScope",
        "enforcementMode",
        "exemptionIds",
        "parameters",
        "definitionVersion",
    ]

    user_fields = [f.strip() for f in args.include_fields.split(",") if f.strip()] if args.include_fields else []
    extra_fields = []
    seen = set()
    def add_field(f):
        if f and f not in seen:
            extra_fields.append(f); seen.add(f)
    if args.wide:
        for f in wide_fields:
            add_field(f)
    for f in user_fields:
        add_field(f)

    requested_fields = set(extra_fields)

    alias_filter: Set[str] | None = None
    if args.alias:
        tmp: Set[str] = set()
        for a in args.alias:
            parts = [p.strip() for p in a.split(",") if p.strip()]
            tmp.update(parts)
        alias_filter = tmp

    if args.inspect:
        mg_map_basic = load_data(jsonl_path, requested_fields=set())
        print(f"Found {len(mg_map_basic)} management groups:")
        for mg, amap in sorted(mg_map_basic.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"  {mg}: {len(amap)} aliases")
        alias_counts = Counter()
        for amap in mg_map_basic.values():
            alias_counts.update(amap.keys())
        print("\nTop policyAliases across MGs:")
        for alias, c in alias_counts.most_common(20):
            print(f"  {alias}: in {c} MG(s)")
        return

    if not args.source or not args.dest:
        raise SystemExit("Please specify --source and --dest (or use --inspect).")

    requested_fields = set(extra_fields)

    # Empty pruning
    empty_tokens = set(DEFAULT_EMPTY_TOKENS)
    if args.empty_token:
        empty_tokens |= _parse_token_list(args.empty_token)
    do_prune = args.prune_empty_values

    mg_map = load_data(jsonl_path, requested_fields=requested_fields)

    if args.source not in mg_map:
        raise SystemExit(f"Source management group not found in data: {args.source}")
    if args.dest not in mg_map:
        raise SystemExit(f"Destination management group not found in data: {args.dest}")

    rows = compute_rows(
        mg_map=mg_map,
        source_mg=args.source,
        dest_mg=args.dest,
        include_equals=args.include_equals,
        include_missing=args.include_missing,
        alias_filter=alias_filter,
        extra_fields=extra_fields,
        do_prune=do_prune,
        empty_tokens=empty_tokens,
        drop_empty_rows=args.drop_empty_rows,
    )

    base_fields = [
        "policyAlias",
        "source_mg",
        "dest_mg",
        "source_values",
        "dest_values",
        "only_in_source",
        "only_in_dest",
    ]
    paired_extra = []
    for f in extra_fields:
        paired_extra.append(f"source_{f}")
        paired_extra.append(f"dest_{f}")
    field_order = base_fields + paired_extra + ["delta"]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=field_order)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in field_order})
    print(f"Wrote {len(rows)} rows to {out_path}")

    if args.json_out:
        jp = Path(args.json_out)
        jp.parent.mkdir(parents=True, exist_ok=True)
        with jp.open("w", encoding="utf-8") as jf:
            json.dump(rows, jf, indent=2, ensure_ascii=False)
        print(f"Wrote JSON to {jp}")

if __name__ == "__main__":
    main()
