
#!/usr/bin/env python3
import argparse, csv, json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Set, List

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

def load_mg_alias_values(jsonl_path: Path):
    mg_map = defaultdict(lambda: defaultdict(set))
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
            val = rec.get("resolvedEffectiveValue")
            mg_map[mg][alias].add(_normalize_value(val))
    return mg_map

def compare_deltas(mg_map, source_mg, dest_mg):
    rows = []
    source_aliases = set(mg_map.get(source_mg, {}))
    dest_aliases = set(mg_map.get(dest_mg, {}))
    common_aliases = sorted(source_aliases & dest_aliases)
    for alias in common_aliases:
        src_vals = mg_map[source_mg][alias]
        dst_vals = mg_map[dest_mg][alias]
        if src_vals != dst_vals:
            rows.append({
                "policyAlias": alias,
                "delta": "true",
                "source_mg": source_mg,
                "dest_mg": dest_mg,
                "source_values": "; ".join(sorted(src_vals)),
                "dest_values": "; ".join(sorted(dst_vals)),
                "only_in_source": "; ".join(sorted(src_vals - dst_vals)) or "",
                "only_in_dest": "; ".join(sorted(dst_vals - src_vals)) or "",
            })
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--source")
    ap.add_argument("--dest")
    ap.add_argument("--out", default="policy_deltas.csv")
    ap.add_argument("--inspect", action="store_true")
    args = ap.parse_args()

    p = Path(args.file)
    if not p.exists():
        raise SystemExit(f"File not found: {p}")

    mg_map = load_mg_alias_values(p)

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

    rows = compare_deltas(mg_map, args.source, args.dest)
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "policyAlias",
                "source_mg",
                "dest_mg",
                "source_values",
                "dest_values",
                "only_in_source",
                "only_in_dest",
                "delta",
            ]
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} delta rows to {outp}")

if __name__ == "__main__":
    main()
