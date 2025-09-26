#!/usr/bin/env python3
"""
Compare Azure Policy resolvedEffectiveValue deltas between two management groups (MGs).

Features:
- Aggregates values per (management group, policyAlias) from a JSONL file.
- Compares the *sets* of normalized resolvedEffectiveValue values between a source MG and a destination MG.
- Optional flags to include equal rows, include “missing” policies (present in only one MG), filter to specific aliases,
  add an extended “wide” set of helpful context fields, output JSON in addition to CSV, and prune empty tokens.

Typical usage:
  python3 app.py --file data.jsonl --source mg-02-0022 --dest mg-03-0014 --out report.csv

Helpful options:
  --inspect             Print inventory of MGs and alias counts, then exit.
  --include-equals      Include rows where source and destination values are equal (delta=false).
  --include-missing     Include aliases present only in one MG (delta=true).
  --alias az-208        Filter to one or more aliases (repeat flag or comma-separated).
  --wide                Add a practical set of extra paired fields (source_*/dest_*).
  --include-fields ...  Add specific extra fields (comma-separated).
  --json-out report.json  Write JSON mirror of the CSV rows.
  --prune-empty-values  Remove “empty” tokens from value sets prior to compare/output.
  --empty-token ...     Add custom empty tokens (repeat flag or comma-separated).
  --drop-empty-rows     After pruning, drop rows where both sides are empty.

Output columns (CSV order):
  policyAlias, source_mg, dest_mg, source_values, dest_values, only_in_source, only_in_dest,
  [source_<field1>, dest_<field1>, source_<field2>, dest_<field2>, ...],
  delta   # always last
"""

import argparse
import csv
import json
from collections import defaultdict, Counter
from pathlib import Path
from typing import Any, Dict, Set, List

# --------------------------------------------------------------------------------------
# Configuration for “empty” tokens. These are the textual, normalized forms we consider
# as “empty” when the --prune-empty-values flag is enabled.
# --------------------------------------------------------------------------------------
DEFAULT_EMPTY_TOKENS = {"null", "[]", "{}", ""}


def _parse_token_list(args_list) -> Set[str]:
    """
    Parse one or more CLI --empty-token values into a set of tokens.
    Each occurrence of --empty-token may carry a comma-separated list.
    Example: --empty-token "N/A,none" --empty-token "{}"
    """
    tokens: Set[str] = set()
    for item in (args_list or []):
        # Split by comma, trim whitespace, ignore blanks.
        for t in (x.strip() for x in item.split(",") if x.strip()):
            tokens.add(t)
    return tokens


def _prune_set(values_set: Set[str], empty_tokens: Set[str]) -> Set[str]:
    """
    Remove entries from a set of normalized strings that match the empty token set.
    This runs *after* normalization and aggregation.
    """
    return {v for v in values_set if v not in empty_tokens}


# --------------------------------------------------------------------------------------
# Normalization: convert any Python value to a stable string so we can aggregate and diff
# consistently (e.g., sort lists, sort dict keys, JSON dump scalars).
# --------------------------------------------------------------------------------------
def _normalize_value(v: Any) -> str:
    """
    Normalize values into comparable, deterministic strings.

    - None        -> "null"
    - str         -> trimmed (keeps original case)
    - bool/num    -> JSON-serialized ("true"/"false", "1", "1.0", etc.)
    - list        -> each element normalized, list sorted, JSON-serialized
    - dict        -> values normalized, keys sorted, JSON-serialized
    - fallback    -> try JSON-serialize; if that fails, str(v)
    """
    if v is None:
        return "null"
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, (int, float, bool)):
        return json.dumps(v, separators=(",", ":"), sort_keys=True)

    try:
        if isinstance(v, list):
            # Normalize each element, then sort the normalized strings for stability.
            nv = sorted(_normalize_value(e) for e in v)
            return json.dumps(nv, separators=(",", ":"), sort_keys=True)
        if isinstance(v, dict):
            # Normalize dict values; key sort ensures deterministic order.
            nv = {k: _normalize_value(vv) for k, vv in v.items()}
            return json.dumps(nv, separators=(",", ":"), sort_keys=True)
    except Exception:
        # If normalization of nested structures fails, fall through to generic JSON/str fallback.
        pass

    try:
        return json.dumps(v, separators=(",", ":"), sort_keys=True)
    except Exception:
        return str(v)


# --------------------------------------------------------------------------------------
# Management group extraction: prefer scope-like fields, then fall back to explicit keys.
# We look for "/managementgroups/<MGID>" case-insensitively in scope-like fields.
# --------------------------------------------------------------------------------------
def _extract_mg(rec: Dict[str, Any]) -> str | None:
    """
    Extract a management group (MG) identifier from a record.
    Precedence:
      1) scope-like fields containing '/managementgroups/<MGID>': assignmentScope, scope, policyScope
      2) explicit fields: managementGroupId, managementGroupName, mg, mgName, mgId
    Returns None if no MG can be found.
    """
    for key in ("assignmentScope", "scope", "policyScope"):
        scope = rec.get(key)
        if isinstance(scope, str):
            low = scope.lower()
            if "/managementgroups/" in low:
                try:
                    # Find the index in the original string using the lowercase match for stability.
                    idx = low.index("/managementgroups/")
                    # Slice the original string after '/managementgroups/' to preserve original case of MG id.
                    tail = scope[idx + len("/managementgroups/") :]
                    # Take the next path segment as the MG id.
                    mg = tail.split("/")[0]
                    if mg:
                        return mg
                except Exception:
                    # If parsing fails for this field, continue to the next method.
                    pass

    # Fallback: explicit MG fields (first non-empty string wins).
    for key in ("managementGroupId", "managementGroupName", "mg", "mgName", "mgId"):
        mg = rec.get(key)
        if isinstance(mg, str) and mg.strip():
            return mg.strip()

    return None


# --------------------------------------------------------------------------------------
# Loader: single pass over the JSONL file to aggregate per (MG, policyAlias).
# We store both:
#   - a set of normalized resolvedEffectiveValue strings
#   - a dict of requested extra fields -> sets of normalized strings (paired later).
# --------------------------------------------------------------------------------------
def load_data(jsonl_path: Path, requested_fields: Set[str]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    Build an in-memory map of:
      mg_map[mg][alias] = {
        "values": set(str),
        "fields": { field_name: set(str), ... }
      }
    Only fields listed in requested_fields are captured into 'fields' to keep memory bounded.
    """
    mg_map: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)

    with jsonl_path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            # Parse a single JSON object per line; skip malformed lines.
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract MG and alias; if either missing, skip this record.
            mg = _extract_mg(rec)
            if not mg:
                continue
            alias = rec.get("policyAlias") or rec.get("alias")
            if not alias:
                continue

            # Initialize the (MG, alias) bucket with a set of values and a set-of-sets for extra fields.
            entry = mg_map.setdefault(mg, {}).setdefault(
                alias, {"values": set(), "fields": defaultdict(set)}
            )

            # Collect the normalized resolvedEffectiveValue into the value set.
            val = rec.get("resolvedEffectiveValue")
            entry["values"].add(_normalize_value(val))

            # Collect any requested extra fields (paired later as source_* / dest_*).
            # Only capture fields we explicitly asked for via CLI to constrain memory use.
            for fld in requested_fields:
                # Direct capture if present at top level.
                if fld in rec:
                    entry["fields"][fld].add(_normalize_value(rec[fld]))
                # assignmentDisplayName may also appear as displayName in some payloads.
                elif fld == "assignmentDisplayName":
                    for k in ("assignmentDisplayName", "displayName"):
                        ad = rec.get(k)
                        if ad:
                            entry["fields"][fld].add(_normalize_value(ad))
                # Parameters/resolvedParameters: attempt a few common keys.
                if fld in ("parameters", "resolvedParameters"):
                    for k in ("parameters", "resolvedParameters"):
                        if k in rec:
                            entry["fields"][fld].add(_normalize_value(rec[k]))

    return mg_map


# --------------------------------------------------------------------------------------
# Comparator: shape rows for output (CSV/JSON) according to flags.
# We operate on *sets* of normalized value strings for each side.
# --------------------------------------------------------------------------------------
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
    """
    Build a list of row dicts that summarize differences (and optionally equals/missing).
    Each row contains:
      - core compare fields (values and only_in_* deltas),
      - paired extra fields (source_<fld>, dest_<fld>),
      - and a final 'delta' flag ('true' if sets differ, else 'false').
    """
    rows: List[Dict[str, str]] = []

    # Determine which aliases are present in each side.
    src_aliases = set(mg_map.get(source_mg, {}))
    dst_aliases = set(mg_map.get(dest_mg, {}))

    # Optional alias filtering (exact match).
    if alias_filter:
        src_aliases &= alias_filter
        dst_aliases &= alias_filter

    # Partition into common and (optionally) missing buckets.
    common_aliases = sorted(src_aliases & dst_aliases)
    src_only = sorted(src_aliases - dst_aliases) if include_missing else []
    dst_only = sorted(dst_aliases - src_aliases) if include_missing else []

    def field_str(entry: Dict[str, Any], fld: str) -> str:
        """Format a requested extra field's set of values as a semicolon-joined string."""
        vals = entry["fields"].get(fld, set())
        return "; ".join(sorted(vals))

    # -----------------------------
    # A) Common aliases (in both MGs)
    # -----------------------------
    for alias in common_aliases:
        s_entry = mg_map[source_mg][alias]
        d_entry = mg_map[dest_mg][alias]

        # Copy value sets (they are sets of strings), optionally prune “empty” tokens.
        s_vals = s_entry["values"]
        d_vals = d_entry["values"]
        if do_prune:
            s_vals = _prune_set(s_vals, empty_tokens)
            d_vals = _prune_set(d_vals, empty_tokens)

        # Optional: drop rows that end up empty on both sides after pruning.
        if drop_empty_rows and not s_vals and not d_vals:
            continue

        # Decide if this is a delta (sets unequal) or equal.
        equal = (s_vals == d_vals)
        if not include_equals and equal:
            # Skip equals entirely unless explicitly requested.
            continue

        # Build the core comparison row.
        row: Dict[str, str] = {
            "policyAlias": alias,
            "source_mg": source_mg,
            "dest_mg": dest_mg,
            "source_values": "; ".join(sorted(s_vals)),
            "dest_values": "; ".join(sorted(d_vals)),
            "only_in_source": "; ".join(sorted(s_vals - d_vals)) if (s_vals - d_vals) else "",
            "only_in_dest": "; ".join(sorted(d_vals - s_vals)) if (d_vals - s_vals) else "",
        }

        # Add paired extra fields (source_*/dest_*) for context.
        for fld in extra_fields:
            row[f"source_{fld}"] = field_str(s_entry, fld)
            row[f"dest_{fld}"] = field_str(d_entry, fld)

        # Final flag: 'true' if sets differ, else 'false'.
        row["delta"] = "true" if not equal else "false"

        rows.append(row)

    # -----------------------------------------
    # B) Source-only aliases (if include-missing)
    # -----------------------------------------
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

        # A missing counterpart is, by definition, a delta.
        row["delta"] = "true"

        rows.append(row)

    # -------------------------------------------
    # C) Destination-only aliases (if include-missing)
    # -------------------------------------------
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


# --------------------------------------------------------------------------------------
# Main: parse CLI, compute which fields to collect, load/aggregate, compare, and write.
# --------------------------------------------------------------------------------------
def main() -> None:
    # ------------------------
    # 1) CLI flags and options
    # ------------------------
    ap = argparse.ArgumentParser(
        description="Compare policy resolvedEffectiveValue deltas between two management groups (CSV/JSON)"
    )
    ap.add_argument("--file", required=True, help="Path to JSONL source file")
    ap.add_argument("--source", help="Source management group (e.g., mg-01-0002)")
    ap.add_argument("--dest", help="Destination management group (e.g., mg-02-0080)")
    ap.add_argument("--out", default="policy_deltas.csv", help="Output CSV path (default: policy_deltas.csv)")
    ap.add_argument("--json-out", default=None, help="Optional JSON output path (writes same rows as JSON)")
    ap.add_argument("--inspect", action="store_true", help="Print MG and alias inventory and exit")

    # Row selection and extra columns
    ap.add_argument("--include-equals", action="store_true", help="Include aliases where values are equal (delta=false)")
    ap.add_argument("--include-missing", action="store_true", help="Include aliases present in only one MG")
    ap.add_argument("--alias", action="append", default=[], help="Filter to specific alias(es). Repeat or comma-separate")
    ap.add_argument(
        "--include-fields",
        default="",
        help="Comma-separated extra fields to include (paired as source_* and dest_*)"
    )
    ap.add_argument("--wide", action="store_true", help="Include a practical wide set of helpful fields")

    # Normalization/pruning behavior
    ap.add_argument(
        "--prune-empty-values",
        action="store_true",
        help='Exclude empty tokens (null/[]/{}/"") from comparison and output'
    )
    ap.add_argument(
        "--empty-token",
        action="append",
        default=[],
        help="Additional tokens to treat as empty (repeat or comma-separate)"
    )
    ap.add_argument(
        "--drop-empty-rows",
        action="store_true",
        help="After pruning, drop rows where both sides have no values and no extras"
    )

    args = ap.parse_args()

    # Validate the input file exists.
    jsonl_path = Path(args.file)
    if not jsonl_path.exists():
        raise SystemExit(f"File not found: {jsonl_path}")

    # -----------------------------------------
    # 2) Decide which extra fields we will collect
    # -----------------------------------------
    # Practical “wide” set that provides strong operational context in most environments.
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

    # Parse user-provided fields from --include-fields (comma-separated).
    user_fields = [f.strip() for f in args.include_fields.split(",") if f.strip()] if args.include_fields else []

    # Compose final list of extra fields, deduplicated and ordered.
    extra_fields: List[str] = []
    seen: Set[str] = set()

    def add_field(f: str) -> None:
        if f and f not in seen:
            extra_fields.append(f)
            seen.add(f)

    if args.wide:
        for f in wide_fields:
            add_field(f)
    for f in user_fields:
        add_field(f)

    # Convert to a set for loader lookups (which fields to even attempt to capture).
    requested_fields = set(extra_fields)

    # -----------------------------------------
    # 3) Build alias filter set from --alias flags
    # -----------------------------------------
    alias_filter: Set[str] | None = None
    if args.alias:
        tmp: Set[str] = set()
        for a in args.alias:
            # Allow comma-separated entries inside a single --alias, and repeatable --alias flags.
            parts = [p.strip() for p in a.split(",") if p.strip()]
            tmp.update(parts)
        alias_filter = tmp

    # -----------------------------------------
    # 4) Inventory-only mode (early exit)
    # -----------------------------------------
    if args.inspect:
        mg_map_basic = load_data(jsonl_path, requested_fields=set())  # no extra fields needed
        print(f"Found {len(mg_map_basic)} management groups:")
        # Order MGs by number of aliases (desc), then by MG id.
        for mg, amap in sorted(mg_map_basic.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"  {mg}: {len(amap)} aliases")

        # Display the most common aliases across MGs.
        alias_counts = Counter()
        for amap in mg_map_basic.values():
            alias_counts.update(amap.keys())
        print("\nTop policyAliases across MGs:")
        for alias, c in alias_counts.most_common(20):
            print(f"  {alias}: in {c} MG(s)")
        return  # Exit after inventory

    # Guard: for comparison you must provide both MGs.
    if not args.source or not args.dest:
        raise SystemExit("Please specify --source and --dest (or use --inspect).")

    # -----------------------------------------
    # 5) Pruning configuration
    # -----------------------------------------
    empty_tokens = set(DEFAULT_EMPTY_TOKENS)
    if args.empty_token:
        empty_tokens |= _parse_token_list(args.empty_token)
    do_prune = args.prune_empty_values

    # -----------------------------------------
    # 6) Load the data (aggregate per MG/alias)
    # -----------------------------------------
    mg_map = load_data(jsonl_path, requested_fields=requested_fields)

    # Validate MGs exist in the aggregated map.
    if args.source not in mg_map:
        raise SystemExit(f"Source management group not found in data: {args.source}")
    if args.dest not in mg_map:
        raise SystemExit(f"Destination management group not found in data: {args.dest}")

    # -----------------------------------------
    # 7) Compute the comparison rows
    # -----------------------------------------
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

    # -----------------------------------------
    # 8) Prepare column order and write CSV
    # -----------------------------------------
    # Base compare columns always present.
    base_fields = [
        "policyAlias",
        "source_mg",
        "dest_mg",
        "source_values",
        "dest_values",
        "only_in_source",
        "only_in_dest",
    ]

    # Paired extra fields (source_<fld>, dest_<fld>) in the order they were requested.
    paired_extra: List[str] = []
    for f in extra_fields:
        paired_extra.append(f"source_{f}")
        paired_extra.append(f"dest_{f}")

    # 'delta' always last.
    field_order = base_fields + paired_extra + ["delta"]

    # Write CSV to disk.
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=field_order)
        writer.writeheader()
        for r in rows:
            # Project each row dict onto the field order; default to empty string for missing keys
            writer.writerow({k: r.get(k, "") for k in field_order})

    print(f"Wrote {len(rows)} rows to {out_path}")

    # -----------------------------------------
    # 9) Optional JSON mirror
    # -----------------------------------------
    if args.json_out:
        jp = Path(args.json_out)
        jp.parent.mkdir(parents=True, exist_ok=True)
        with jp.open("w", encoding="utf-8") as jf:
            json.dump(rows, jf, indent=2, ensure_ascii=False)
        print(f"Wrote JSON to {jp}")


if __name__ == "__main__":
    main()
