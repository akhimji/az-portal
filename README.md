# Azure Policy Delta Comparator

Compare **Azure Policy** `resolvedEffectiveValue` differences between two **Management Groups (MGs)** from a **JSONL** dataset.  
Generates a clean **CSV** (and optional **JSON**) report with per-alias deltas, optional context fields (assignment, definition IDs, parameters), and powerful filters.

---

## Features

- **Single-pass ingest** of large JSONL datasets.
- **Set-based comparison** of `resolvedEffectiveValue` per `(MG, policyAlias)` to capture all distinct values.
- **Robust MG detection** from scope-like fields or explicit MG fields.
- **Actionable reports**: CSV with `delta` flag (last column), and optional JSON mirror.
- **Flex output shape** via flags:
  - `--wide` to include a practical set of context fields.
  - `--include-fields` to add specific fields you care about.
  - `--include-equals` to show unchanged rows.
  - `--include-missing` to include aliases present in only one MG.
  - `--alias` filter for one or many aliases.
  - **Pruning**: remove empty tokens, drop rows that become empty.
- **Inventory mode** to discover MGs and aliases before you compare.

---

## Requirements

- Python **3.8+**
- Standard library only (no extra packages).

---

## 🚀 Quick Start

1) Put your dataset at `data.jsonl`. Each line must be a JSON object.

2) Run a basic compare:
```bash
python3 app.py --file data.jsonl --source mg-02-0022 --dest mg-03-0014 --out policy_deltas.csv
```

3) See what’s inside (MGs & alias coverage):
```bash
python3 app.py --file data.jsonl --inspect
```

4) Add more context + JSON mirror:
```bash
python3 app.py --file data.jsonl \
  --source mg-02-0022 --dest mg-03-0014 \
  --wide --include-equals --include-missing \
  --out policy_deltas_wide.csv \
  --json-out policy_deltas_wide.json
```

---

## Input Format (JSONL)

- The tool reads **JSON Lines**: **one** JSON object per line.
- For each record, the app tries to find:
  - **Management Group (MG)** via either:
    - scope-like fields: `assignmentScope`, `scope`, or `policyScope` containing `"/managementGroups/<MGID>"` (case-insensitive match on the path segment);
    - or explicit fields: `managementGroupId`, `managementGroupName`, `mg`, `mgName`, `mgId`.
  - **Alias** via `policyAlias` (or fallback `alias`).
  - **Value** via `resolvedEffectiveValue`.
- All found values are **normalized** and **aggregated** per `(MG, alias)`.

> Records without a detectable MG or alias are **skipped**.

---

## Normalization (How values are compared)

To avoid false diffs due to ordering/formatting, values are normalized to **stable strings**:

- `None` → `"null"`  
- `str` → `.strip()` (keeps case by default)  
- `int/float/bool` → JSON (`1`, `1.0`, `true/false`)  
- `list` → normalize each element, **sort**, JSON-dump  
- `dict` → normalize values, **sort keys**, JSON-dump  
- fallback → try `json.dumps`, else `str(v)`

This ensures, for example, two lists with the same elements in different orders compare equal.

---

## CLI Reference

```text
--file <path>              Path to JSONL input (required)
--source <MG>              Source management group (required unless --inspect)
--dest <MG>                Destination management group (required unless --inspect)
--out <csv>                CSV output path (default: policy_deltas.csv)
--json-out <json>          Also write JSON output
--inspect                  Print MG & alias inventory, then exit

--include-equals           Include equal rows (delta=false)
--include-missing          Include source-only and dest-only aliases (delta=true)
--alias <a1[,a2,...]>      Filter to exact alias(es); repeat flag or comma-separate
--include-fields <csv>     Add extra fields (paired as source_* and dest_*)
--wide                     Add a practical set of context fields (listed below)

--prune-empty-values       Remove empty tokens from value sets before compare/output
--empty-token <csv>        Add custom empties (repeat or comma-separate)
--drop-empty-rows          After pruning, drop rows with no values on both sides
```

### `--wide` includes (paired as `source_*` and `dest_*`)

- `policyDefinitionId`
- `policySetDefinitionId`
- `policyDefinitionReferenceId`
- `policyAssignmentId`
- `assignmentDisplayName`
- `assignmentScope`
- `enforcementMode`
- `exemptionIds`
- `parameters`
- `definitionVersion`

Use `--include-fields` to add any additional top-level fields present in your data.

---

## CSV Schema

Columns are written in this exact order:

```
policyAlias,
source_mg, dest_mg,
source_values, dest_values,
only_in_source, only_in_dest,
[ source_<field1>, dest_<field1>, source_<field2>, dest_<field2>, ... ],
delta
```

- `source_values` / `dest_values` are **sorted** and **semicolon-joined** sets of normalized strings.
- `only_in_source` = values present in `source_values` but not in `dest_values`.
- `only_in_dest` = values present in `dest_values` but not in `source_values`.
- `delta` is `"true"` when the value sets differ, `"false"` otherwise (only present for common aliases; missing rows always have `delta="true"`).

---

## Examples

**Basic compare (CSV):**
```bash
python3 app.py --file data.jsonl \
  --source mg-02-0022 --dest mg-03-0014 \
  --out policy_deltas.csv
```

**Filter to specific aliases:**
```bash
python3 app.py --file data.jsonl \
  --source mg-02-0022 --dest mg-03-0014 \
  --alias az-208,ngc-022 \
  --include-equals \
  --out filtered_aliases.csv
```

**Include missing + wide + JSON mirror:**
```bash
python3 app.py --file data.jsonl \
  --source mg-02-0022 --dest mg-03-0014 \
  --include-missing --wide \
  --out policy_deltas_wide.csv \
  --json-out policy_deltas_wide.json
```

**Prune empty values and drop rows that become empty:**
```bash
python3 app.py --file data.jsonl \
  --source mg-02-0022 --dest mg-03-0014 \
  --include-equals \
  --prune-empty-values --drop-empty-rows \
  --out policy_deltas_pruned.csv
```

**Custom empties:**
```bash
python3 app.py --file data.jsonl \
  --source mg-02-0022 --dest mg-03-0014 \
  --include-equals \
  --prune-empty-values \
  --empty-token "N/A,none,{}" \
  --out policy_deltas_custom_empty.csv
```

---

## How MGs are detected

1. **Preferred**: look for `"/managementgroups/<MGID>"` in **scope-like fields**  
   Checks in order: `assignmentScope`, `scope`, `policyScope` (case-insensitive on the path segment).
2. **Fallback**: explicit MG fields  
   `managementGroupId`, `managementGroupName`, `mg`, `mgName`, `mgId` (first non-empty string wins).

> If an MG ID appears only in unrelated fields (e.g., comments or nested blobs) and not in the scope/explicit fields above, it will **not** be counted. This prevents false positives.

---

## Comparison Semantics

- Comparison is done on **sets** of normalized `resolvedEffectiveValue` per `(MG, alias)`:
  - If there are multiple records for that pair, every distinct normalized value is included.
  - Deltas are determined by set inequality.
- `--include-equals` shows common aliases even when the sets are equal (`delta=false`).
- `--include-missing` shows aliases present in only one MG (always `delta=true`).

---

## Pruning & Empty Rows

- Enable pruning via `--prune-empty-values`. Defaults pruned: `""`, `"null"`, `"[]"`, `"{}"`.
- Add custom empties: `--empty-token "N/A,none"` (can repeat the flag).
- With `--drop-empty-rows`, rows are **skipped** when both sides become empty after pruning.

> Pruning affects equality decisions. For example, if both sides only have `"null"` and you prune `"null"`, the row may be dropped (when `--drop-empty-rows`) or become `delta=false` (if equals included and both are empty).

---

## Troubleshooting

**“Source management group not found in data”**  
- Run `--inspect` and confirm the exact MG IDs present in your file.
- Ensure `assignmentScope`/`scope`/`policyScope` truly contains `/managementGroups/<MGID>`, or explicit MG fields are present.

**“Zero rows produced”**  
- The two MGs may share no aliases; or all rows were dropped due to pruning + `--drop-empty-rows`.
- Try removing `--drop-empty-rows`, or add `--include-missing` to see source-only/dest-only aliases.

**“All rows have delta=true”**  
- You may be excluding equals (`--include-equals` not provided). Add `--include-equals` to see `delta=false` rows.
- Consider case sensitivity or formatting; current normalization keeps string case. If you need case-insensitive compare, ask to add that switch.

**Performance tips**  
- Pre-filter aliases using `--alias` when validating specific policies.
- Avoid `--wide` if you don’t need extra fields to reduce memory usage.
- Use `--inspect` to confirm relevant MGs before running large comparisons.

---

## License


---

## Contributing

- Open to enhancements like case-insensitive normalization, HTML report, parameter diffs, or priority scoring.
- Keep changes documented in the README and add flags with clear help text.
