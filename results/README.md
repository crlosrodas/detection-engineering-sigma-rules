# Step 4 - Rule testing: tooling and method

This directory holds the results of running the 5 Sigma rules in `../rules/`
against the 5 sample logs in `../logs/` (a full 5x5 matrix, 25 cells).

## Tool chosen: Zircolite

**[Zircolite](https://github.com/wagga40/Zircolite) v3.7.6** (git commit
`b37b51e`), run from a project-local clone at `../tools/zircolite/` provisioned
by `../tools/setup_zircolite.sh` (pinned to tag `v3.7.6`), with its dependencies
satisfied by the project `.venv`.

### Why Zircolite

- It runs **native Sigma rules** directly (no manual pre-compilation): it uses
  pySigma + the pySigma SQLite backend to convert each rule to SQL, loads the
  events into an in-memory SQLite DB, and runs the query. That means the exact
  same rule YAML we validated in Step 3 is what gets executed here.
- It reads **both** of our input shapes natively:
  - the Emotet **`.evtx`** (T1059) via the bundled `evtx` Rust parser, and
  - the four OTRF **JSON-lines** captures via `-j` / `--jsonl`.
- It applies the standard Windows/Sysmon **pySigma pipelines** (`sysmon`,
  `windows-logsources`, `windows-audit`), so our generic Sigma logsources
  (`process_access`, `create_remote_thread`, `registry_set`, `ps_script`,
  `service:security`) are translated into the correct `EventID`/`Channel`
  predicates automatically.
- It emits structured **JSON results** (used here as the raw evidence in
  `raw/`) and can render HTML/GUI reports.

> Note: `pip install zircolite` does **not** work - Zircolite is not published
> on PyPI as an installable package. It is distributed as a repo you clone and
> run (`python3 zircolite.py ...`). Its dependencies (`evtx`,
> `pysigma-backend-sqlite`, `pysigma-pipeline-sysmon`,
> `pysigma-pipeline-windows`, `orjson`, `rich`, etc.) are already covered by the
> project `.venv`. The clone lives at `../tools/zircolite/`, pinned to tag
> `v3.7.6` by `../tools/setup_zircolite.sh`, and `run_matrix.sh` invokes
> `zircolite.py` from there.

### Reproduce

```bash
source ../.venv/bin/activate
# one-time: provision the pinned (v3.7.6) project-local Zircolite clone.
# Clones into ../tools/zircolite/ and verifies the venv has its deps.
bash ../tools/setup_zircolite.sh
# run the full 5x5 matrix -> results/raw/<rule>__<log>.json
bash run_matrix.sh
```

## Verifying Zircolite actually parses the OTRF flat NDJSON

The OTRF Security-Datasets logs are **flat** NDJSON (one JSON object per line
with top-level `EventID`, `Channel`, `TargetImage`, `GrantedAccess`, `Details`,
... - not the nested `Event.System.*` evtx_dump shape). Before trusting any
counts, this was verified end-to-end:

- Zircolite's `config/fieldMappings.yaml` defines a log-source signature named
  **`windows_evtx_json_flat`** with `signature_fields: [Channel, EventID]`,
  which is exactly this shape, and its `event_filter` recognises `EventID` and
  `Channel` as top-level fields. So the flat OTRF lines are parsed and their
  `EventID`/`Channel` are mapped correctly **without any conversion** - the
  files in `logs/` were never modified.
- Confirmed empirically on the smallest file first (the 184-line T1003 log):
  Zircolite reported **2** matches for the LSASS rule, which reconciles exactly
  with a manual `jq`/python count of EID 10 lsass events carrying a dump-style
  `GrantedAccess` mask (`0x1fffff`, `0x1410`). Case-insensitive matching also
  works: the log stores `0x1fffff` (lower case) and the rule lists `0x1FFFFF`.

No NDJSON-to-evtx_dump conversion script was needed.

## CRITICAL gotcha found and fixed: per-rule pipeline selection

Concatenating all three pipelines (`-p sysmon windows-logsources
windows-audit`) onto **every** rule silently breaks the `registry_set` rule
(T1547). Both the `sysmon` pipeline **and** the `windows-audit` pipeline claim
the generic `registry_set` category:

- `sysmon` -> Sysmon **EventID 13**, value field **`Details`**
- `windows-audit` -> Security auditing **EventID 4657**, value field **`NewValue`**

Stacked together they produce a self-contradictory query -
`... (EventID=4657 AND OperationType='...') AND (... EventID=13 AND ... NewValue LIKE ...)` -
which can never match (an event is not both 4657 and 13) and also looks at the
wrong field name (`NewValue` instead of `Details`). Result: **0** matches on a
log that genuinely contains the persistence event.

This is a **harness/pipeline bug, not a rule bug** - the T1547 rule is a
correct, standard Sysmon-13 registry rule. The fix is in `run_matrix.sh`: each
rule is run with **only** the pipeline that matches its logsource:

| rule (logsource)                       | pipeline             | resolves to        |
|----------------------------------------|----------------------|--------------------|
| t1003 lsass (`process_access`)         | `sysmon`             | EventID 10         |
| t1055 remote thread (`create_remote_thread`) | `sysmon`       | EventID 8          |
| t1547 run key (`registry_set`)         | `sysmon`             | EventID 13, Details|
| t1059 script block (`ps_script`)       | `windows-logsources` | EventID 4104, PS ch|
| t1021 smb pipe (`service:security`)    | `windows-audit`      | EventID 5145, Sec ch|

With the correct per-rule pipeline the T1547 query becomes
`EventID=13 AND TargetObject LIKE '%...\CurrentVersion\Run%' AND (Details LIKE '%powershell%' OR ...)`
and matches the 1 expected event. No rule file was changed.

## Files here

- `run_matrix.sh` - runs the 25-cell matrix (per-rule pipeline selection).
- `gen_report.py` - renders a single Zircolite JSON result into a self-contained
  HTML detection report (used to produce `../screenshots/*.png`). Every value
  shown is taken verbatim from Zircolite's JSON output.
- `raw/<rule>__<log>.json` - raw Zircolite result for each of the 25 cells
  (`[]` = no match). Each match object contains the full original event.
- `raw/<rule>__<log>.log` - Zircolite's per-run log (rule conversion + event
  counts), kept as run evidence.
- `TEST_RESULTS.md` - the 5x5 match-count grid, ground-truth reconciliation,
  and off-diagonal tuning targets.

## Environment versions

- Zircolite v3.7.6 (commit `b37b51e`)
- pySigma 1.4.0, pySigma-backend-sqlite 1.2.0,
  pysigma-pipeline-sysmon 2.0.0, pysigma-pipeline-windows 2.0.0
