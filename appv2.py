#!/usr/bin/env python3
import argparse, csv, json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

def _normalize_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, str):
        return v.strip().lower()
    if isinstance(v, (int, float, bool)):
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    try:
        if isinstance(v, list):
            return json.dumps(sorted(_normalize_value(e) for e in v),
                              separators=(",", ":"), sort_keys=True)
        if isinstance(v, dict):
            nv = {k: _normalize_value(vv) for k, vv in v.items()}
            return json.dumps(nv, separators=(",", ":"), sort_keys=True)
    except Exception:
        pass
    try:
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    except Exception:
        return str(v)

def _extract_mg(rec: Dict[str, Any]) -> str | None:
    # Try scope-like fields first
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
    # Try explicit fields
    for key in ("managementGroupId", "managementGroupName", "mg", "mgName", "mgId"):
        mg = rec.get(key)
        if isinstance(mg, str) and mg.strip():
            return mg.strip()
    return None

def _serialize_meta(v: Any) -> str:
    try:
        if v is None:
            return ""
        if isinstance(v, (str, int, float, bool)):
            return str(v)
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except Exception:
        return str(v)

def load_mg_alias_values(jsonl_path: Path, verbose: bool = False) -> Tuple[Dict[str, Dict[str, Dict[str, Any]]], Dict[str, Any]]:
    """
    Load management-group -> alias -> {'values': set(...), 'meta': {...}}.
    Returns (mg_map, stats). If verbose is True, samples of problematic lines are collected.
    """
    mg_map: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(lambda: defaultdict(lambda: {"values": set(), "meta": {}}))

    # Counters and samples
    total = 0
    parsed = 0
    blank = 0
    json_errors = 0
    no_mg = 0
    no_alias = 0
    sample_limit = 5
    sample_json_errors: List[str] = []
    sample_no_mg: List[str] = []
    sample_no_alias: List[str] = []

    meta_fields = [
        "policyDefinitionId",
        "policySetDefinitionId",
        "policyDefinitionReferenceId",
        "policyAssignmentId",
        "assignmentDisplayName",
        "assignmentScope",
        "enforcementMode",
        "exemptionIds",
        "definitionVersion",
        # parameters handled specially below
    ]

    with jsonl_path.open("r", encoding="utf-8") as f:
        for line in f:
            total += 1
            orig_line = line.rstrip("\n")
            line = line.strip()
            if not line:
                blank += 1
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                json_errors += 1
                if verbose and len(sample_json_errors) < sample_limit:
                    sample_json_errors.append(orig_line)
                continue
            parsed += 1
            mg = _extract_mg(rec)
            if not mg:
                no_mg += 1
                if verbose and len(sample_no_mg) < sample_limit:
                    sample_no_mg.append(orig_line)
                continue
            alias = rec.get("policyAlias") or rec.get("alias")
            if not alias:
                no_alias += 1
                if verbose and len(sample_no_alias) < sample_limit:
                    sample_no_alias.append(orig_line)
                continue
            val = rec.get("resolvedEffectiveValue")
            entry = mg_map[mg][alias]
            entry["values"].add(_normalize_value(val))

            # store meta fields if not already present (prefer first seen)
            meta = entry["meta"]
            for fkey in meta_fields:
                if fkey not in meta or meta.get(fkey) in (None, ""):
                    if fkey in rec and rec.get(fkey) not in (None, ""):
                        meta[fkey] = rec.get(fkey)
            # parameters: prefer resolvedParameters then parameters
            if "parameters" not in meta or meta.get("parameters") in (None, ""):
                if "resolvedParameters" in rec and rec.get("resolvedParameters") not in (None, ""):
                    meta["parameters"] = rec.get("resolvedParameters")
                elif "parameters" in rec and rec.get("parameters") not in (None, ""):
                    meta["parameters"] = rec.get("parameters")

    stats = {
        "total_lines": total,
        "parsed": parsed,
        "blank": blank,
        "json_errors": json_errors,
        "no_mg": no_mg,
        "no_alias": no_alias,
        "sample_json_errors": sample_json_errors,
        "sample_no_mg": sample_no_mg,
        "sample_no_alias": sample_no_alias,
    }
    return mg_map, stats

def compare_deltas(
    mg_map: Dict[str, Dict[str, Dict[str, Any]]],
    source_mg: str,
    dest_mg: str,
    include_fields: Optional[set] = None,
    include_equals: bool = False,
    include_missing: bool = False,
    alias_filter: Optional[str] = None,
) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    include_fields = include_fields or set()

    source_aliases = set(mg_map.get(source_mg, {}))
    dest_aliases = set(mg_map.get(dest_mg, {}))

    # handle aliases present in both
    common_aliases = sorted(source_aliases & dest_aliases)
    for alias in common_aliases:
        if alias_filter and alias_filter.lower() not in alias.lower():
            continue
        src_entry = mg_map[source_mg][alias]
        dst_entry = mg_map[dest_mg][alias]
        src_vals = src_entry["values"]
        dst_vals = dst_entry["values"]
        equal = src_vals == dst_vals
        if equal and not include_equals:
            continue
        row: Dict[str, str] = {"policyAlias": alias}
        # identity/meta fields
        for f in ("policyDefinitionId", "policySetDefinitionId", "policyDefinitionReferenceId",
                  "policyAssignmentId", "assignmentDisplayName", "assignmentScope"):
            if f in include_fields:
                row[f] = _serialize_meta(src_entry["meta"].get(f) or dst_entry["meta"].get(f) or "")
        # comparison fields
        row.update({
            "source_mg": source_mg,
            "dest_mg": dest_mg,
            "source_values": "; ".join(sorted(src_vals)),
            "dest_values": "; ".join(sorted(dst_vals)),
            "only_in_source": "; ".join(sorted(src_vals - dst_vals)) or "",
            "only_in_dest": "; ".join(sorted(dst_vals - src_vals)) or "",
        })
        # root-cause helpers
        for f in ("enforcementMode", "exemptionIds", "parameters", "definitionVersion"):
            if f in include_fields:
                row[f] = _serialize_meta(src_entry["meta"].get(f) or dst_entry["meta"].get(f) or "")
        row["delta"] = "false" if equal else "true"
        rows.append(row)

    # handle aliases only in source or only in dest if requested
    if include_missing:
        only_source = sorted(source_aliases - dest_aliases)
        only_dest = sorted(dest_aliases - source_aliases)
        for alias in only_source:
            if alias_filter and alias_filter.lower() not in alias.lower():
                continue
            src_entry = mg_map[source_mg][alias]
            row: Dict[str, str] = {"policyAlias": alias}
            for f in ("policyDefinitionId", "policySetDefinitionId", "policyDefinitionReferenceId",
                      "policyAssignmentId", "assignmentDisplayName", "assignmentScope"):
                if f in include_fields:
                    row[f] = _serialize_meta(src_entry["meta"].get(f) or "")
            row.update({
                "source_mg": source_mg,
                "dest_mg": dest_mg,
                "source_values": "; ".join(sorted(src_entry["values"])),
                "dest_values": "",
                "only_in_source": "; ".join(sorted(src_entry["values"])) or "",
                "only_in_dest": "",
                "delta": "true",
            })
            for f in ("enforcementMode", "exemptionIds", "parameters", "definitionVersion"):
                if f in include_fields:
                    row[f] = _serialize_meta(src_entry["meta"].get(f) or "")
            rows.append(row)
        for alias in only_dest:
            if alias_filter and alias_filter.lower() not in alias.lower():
                continue
            dst_entry = mg_map[dest_mg][alias]
            row: Dict[str, str] = {"policyAlias": alias}
            for f in ("policyDefinitionId", "policySetDefinitionId", "policyDefinitionReferenceId",
                      "policyAssignmentId", "assignmentDisplayName", "assignmentScope"):
                if f in include_fields:
                    row[f] = _serialize_meta(dst_entry["meta"].get(f) or "")
            row.update({
                "source_mg": source_mg,
                "dest_mg": dest_mg,
                "source_values": "",
                "dest_values": "; ".join(sorted(dst_entry["values"])),
                "only_in_source": "",
                "only_in_dest": "; ".join(sorted(dst_entry["values"])) or "",
                "delta": "true",
            })
            for f in ("enforcementMode", "exemptionIds", "parameters", "definitionVersion"):
                if f in include_fields:
                    row[f] = _serialize_meta(dst_entry["meta"].get(f) or "")
            rows.append(row)

    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--source")
    ap.add_argument("--dest")
    ap.add_argument("--out", default="policy_deltas.csv")
    ap.add_argument("--inspect", action="store_true")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show counts and samples of skipped/invalid JSON lines")

    ap.add_argument("--include-fields", help="Comma-separated fields to include (policyDefinitionId,policySetDefinitionId,policyAssignmentId,enforcementMode,exemptionIds,parameters,definitionVersion,policyDefinitionReferenceId,assignmentDisplayName,assignmentScope)")
    ap.add_argument("--include-equals", action="store_true", help="Include rows where source and dest values are equal (delta=false)")
    ap.add_argument("--include-missing", action="store_true", help="Include aliases present in only one MG")
    ap.add_argument("--alias", help="Filter alias (substring, case-insensitive)")
    ap.add_argument("--wide", action="store_true", help="Include a broad set of fields automatically")
    ap.add_argument("--json-out", help="Write parallel JSON report")
    args = ap.parse_args()

    p = Path(args.file)
    if not p.exists():
        raise SystemExit(f"File not found: {p}")

    mg_map, stats = load_mg_alias_values(p, args.verbose)

    if args.verbose:
        print("Load summary:")
        print(f"  total lines: {stats['total_lines']}")
        print(f"  parsed: {stats['parsed']}")
        print(f"  blank lines: {stats['blank']}")
        print(f"  json decode errors: {stats['json_errors']}")
        print(f"  records missing management group: {stats['no_mg']}")
        print(f"  records missing alias: {stats['no_alias']}")
        if stats["sample_json_errors"]:
            print("\nSample JSON decode failures:")
            for s in stats["sample_json_errors"]:
                print("  ", s)
        if stats["sample_no_mg"]:
            print("\nSample records missing MG:")
            for s in stats["sample_no_mg"]:
                print("  ", s)
        if stats["sample_no_alias"]:
            print("\nSample records missing alias:")
            for s in stats["sample_no_alias"]:
                print("  ", s)
        print("")

    if args.inspect:
        print(f"Found {len(mg_map)} management groups:")
        for mg, amap in sorted(mg_map.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"  {mg}: {len(amap)} aliases")
        # Also suggest close matches if user provided a source/dest that don't exist
        if args.source and args.source not in mg_map:
            print(f"\nSource '{args.source}' not found. Here are some similar-looking MGs:")
            for k in mg_map.keys():
                if args.source.lower()[:4] in k.lower():
                    print(" ", k)
        if args.dest and args.dest not in mg_map:
            print(f"\nDest '{args.dest}' not found. Here are some similar-looking MGs:")
            for k in mg_map.keys():
                if args.dest.lower()[:4] in k.lower():
                    print(" ", k)
        return

    if not args.source or not args.dest:
        raise SystemExit("Please specify --source and --dest (or use --inspect).")

    if args.source not in mg_map:
        raise SystemExit(f"Source management group not found in data: {args.source}")
    if args.dest not in mg_map:
        raise SystemExit(f"Destination management group not found in data: {args.dest}")

    include_fields = set()
    if args.wide:
        include_fields.update([
            "policyDefinitionId","policySetDefinitionId","policyDefinitionReferenceId",
            "policyAssignmentId","assignmentDisplayName","assignmentScope",
            "enforcementMode","exemptionIds","parameters","definitionVersion"
        ])
    if args.include_fields:
        for f in args.include_fields.split(","):
            if f.strip():
                include_fields.add(f.strip())

    rows = compare_deltas(
        mg_map,
        args.source,
        args.dest,
        include_fields=include_fields,
        include_equals=args.include_equals,
        include_missing=args.include_missing,
        alias_filter=args.alias,
    )

    # build CSV header in requested order: Identity, Scope & assignment, Comparison, Root cause helpers, delta last
    header: List[str] = ["policyAlias"]
    identity_order = ["policyDefinitionId","policySetDefinitionId","policyDefinitionReferenceId"]
    scope_order = ["policyAssignmentId","assignmentDisplayName","assignmentScope"]
    comp_order = ["source_mg","dest_mg","source_values","dest_values","only_in_source","only_in_dest"]
    root_order = ["enforcementMode","exemptionIds","parameters","definitionVersion"]
    for group in (identity_order, scope_order):
        for h in group:
            if h in include_fields:
                header.append(h)
    header.extend(comp_order)
    for h in root_order:
        if h in include_fields:
            header.append(h)
    header.append("delta")

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        # ensure all rows have keys for header
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in header})
    print(f"Wrote {len(rows)} delta rows to {outp}")

    if args.json_out:
        jpath = Path(args.json_out)
        jpath.parent.mkdir(parents=True, exist_ok=True)
        with jpath.open("w", encoding="utf-8") as jf:
            json.dump(rows, jf, ensure_ascii=False, indent=2)
        print(f"Wrote JSON report to {jpath}")

if __name__ == "__main__":
    main()
