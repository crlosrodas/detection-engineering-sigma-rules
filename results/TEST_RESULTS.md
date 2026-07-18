# Test results (5 rules x 5 logs)

Tool: **Zircolite v3.7.6** run per-rule with the correct pySigma pipeline (see
`README.md`). Raw evidence: `raw/<rule>__<log>.json`. Reproduce: `run_matrix.sh`.

> **Current state of `raw/`: POST-TUNING (Step 5).** The `raw/*.json` files in
> this directory reflect the **tuned** `t1003` LSASS rule (benign `SourceImage`
> FPs filtered). The **[Step 5 - Tuning](#step-5---tuning-t1003-lsass-rule)**
> section at the bottom has the post-tuning grid and tuning log. The Step 4
> section immediately below is kept **as historical record of the pre-tuning
> state** - its grid still shows the two `t1003` false positives that Step 5
> removed (T1021 1->0, T1547 2->0).

## Step 4 match-count grid (PRE-tuning - historical)

Rows = rules, columns = logs. `*` marks the **diagonal** (a rule against its own
intended log = the expected true positive). All other cells are off-diagonal.
This grid documents the state **before** Step 5 tuning; the `t1003` T1021 (1)
and T1547 (2) cells below are the false positives that Step 5 removed.

| rule \\ log                       | T1003 lsass | T1021 smb | T1055 inject | T1547 runkey | T1059 ps (evtx) |
|-----------------------------------|:-----------:|:---------:|:------------:|:------------:|:---------------:|
| **t1003** lsass proc-access dump  |   **2** *   |     1     |      0       |      2       |        0        |
| **t1021** smb admin-share pipe    |     0       |  **1** *  |      0       |      0       |        0        |
| **t1055** create remote thread    |     0       |     0     |    **88** *  |      0       |        0        |
| **t1547** registry run key        |     0       |     0     |      0       |    **1** *   |        0        |
| **t1059** ps download cradle      |     0       |     1     |      1       |      1       |      **1** *    |

## Diagonal (true-positive) check vs. ground truth

Every diagonal cell has >= 1 match, and each count was independently
cross-checked against the raw log with `jq`/python.

| rule            | Zircolite | ground truth | reconciles | evidence                                                              |
|-----------------|:---------:|:------------:|:----------:|-----------------------------------------------------------------------|
| t1003 lsass     |     2     |      2       |    yes     | 2x EID 10 on `\lsass.exe` with dump masks (`0x1fffff`, `0x1410`)      |
| t1021 smb       |     1     |      1       |    yes     | 1x EID 5145, `ShareName \\*\IPC$`, `RelativeTargetName=svcctl`         |
| t1055 inject    |    88     |     88       |    yes     | 88x EID 8, `powershell.exe` -> `notepad.exe` CreateRemoteThread        |
| t1547 runkey    |     1     |      1       |    yes     | 1x EID 13, `...\CurrentVersion\Run\Updater`, Details = `powershell -enc`|
| t1059 ps        |     1     |      1       |    yes     | single-event EVTX, EID 4104, obfuscated Emotet WebClient/Invoke-Item   |

All five reconcile exactly. (The T1547 diagonal initially read 0 due to a
pipeline-stacking bug in the harness - `sysmon`+`windows-audit` both claim
`registry_set`, yielding an impossible `EventID=4657 AND EventID=13` and the
wrong value field `NewValue`. Fixed by selecting the correct pipeline per rule;
the rule itself was correct and unchanged. Details in `README.md`.)

## Off-diagonal matches (tuning targets, NOT failures)

These are real events present in the captures (each verified against the raw
log). The OTRF datasets are full attack captures, so cross-technique activity
legitimately appears.

| rule fired      | on log        | count | what it is                                                                                                  |
|-----------------|---------------|:-----:|-------------------------------------------------------------------------------------------------------------|
| t1003 lsass     | T1021 smb     |   1   | `CollectGuestLogs.exe` (Azure guest-agent) opens lsass with `0x1410`. Benign monitoring - a classic FP. Tune by baselining trusted `SourceImage`. |
| t1003 lsass     | T1547 runkey  |   2   | `wininit.exe` and `csrss.exe` open lsass with `0x1fffff`. Windows internals - exactly the FP class the rule's `falsepositives` already names. Tune by filtering trusted `SourceImage`. |
| t1059 ps cradle | T1021 smb     |   1   | Empire PowerShell stager script block (EID 4104) containing a WebClient/DownloadString cradle + IEX follow-on. Genuine T1059.001 behaviour co-occurring in the Empire lateral-movement capture. |
| t1059 ps cradle | T1055 inject  |   1   | Same Empire stager script block present in the psinject capture.                                            |
| t1059 ps cradle | T1547 runkey  |   1   | Same Empire stager script block present in the persistence capture.                                         |

### Reading these

- The **t1003** off-diagonals are true false positives - trusted processes
  (Azure agent, `wininit`, `csrss`) legitimately opening LSASS. They are the
  motivation for the `SourceImage` allow-list baselining noted in the rule's
  `falsepositives`. Good candidates for a future tuning filter.
- The **t1059** off-diagonals are *not* false positives in the usual sense:
  the three Empire captures each contain a real obfuscated PowerShell download
  cradle in Script Block Logging, so a T1059.001 cradle rule *should* fire on
  them. They illustrate that multi-stage attacks trip multiple detections at
  once, which is expected and desirable.

## Notes

- Inputs in `../logs/` were never modified. JSON-lines logs read with `-j`; the
  EVTX read via Zircolite's native `evtx` parser.
- `rules/` was not modified in Step 4 - all five rules passed as written
  (re-validated with pySigma 1.4.0 during that step). Step 5 (below) modifies
  **only** the `t1003` rule.

---

# Step 5 - Tuning (t1003 LSASS rule)

**Date:** 2026-07-17. Goal of Step 5: tune one rule to reduce false positives
while preserving its true positive. Target = `t1003` LSASS process-access rule,
which fired on two benign log captures in Step 4.

## What was changed

Only `rules/t1003_001_lsass_process_access_dump.yml` was edited (added
`modified: 2026-07-17`). A SigmaHQ-style `filter_main_*` exclusion was added and
combined with `condition: selection and not 1 of filter_main_*`. The exact
filter added:

```yaml
    filter_main_azure_guest_agent:
        SourceImage|endswith: '\CollectGuestLogs.exe'
    filter_main_windows_internals:
        SourceImage|endswith:
            - ':\Windows\System32\wininit.exe'
            - ':\Windows\System32\csrss.exe'
    condition: selection and not 1 of filter_main_*
```

**Why keyed on `SourceImage`, never on `GrantedAccess`:** the FP masks overlap
the TP masks (the true positive `rundll32.exe` uses `0x1fffff` and `0x1410` -
the very masks the Azure agent and the Windows-internals FPs also use).
Filtering on the mask would kill the true positive. `SourceImage` is the only
discriminating field.

**Precision choices:**
- Azure guest agent lives under a versioned `C:\WindowsAzure\GuestAgent_*\`
  path, so the filter keys on the **basename** `\CollectGuestLogs.exe`.
- `wininit.exe` / `csrss.exe` are anchored to the **System32 path**
  (`:\Windows\System32\...`), **not** bare basenames - so a payload named
  `csrss.exe` in another directory is still detected. Sigma matching is
  case-insensitive, so the lower-case `c:\windows\system32\...` in the log is
  still matched. `GrantedAccess`, `TargetImage` and everything else are
  unchanged.

`falsepositives:` was rewritten to name concretely what testing found (Azure
`CollectGuestLogs.exe` @ `0x1410`; Windows internals `wininit.exe`/`csrss.exe`
@ `0x1fffff`), noting these are now filtered in the rule.

## pySigma re-validation (post-edit)

```
$ .venv/bin/python -c "from sigma.collection import SigmaCollection; from pathlib import Path; \
    c=SigmaCollection.load_ruleset([Path('rules/t1003_001_lsass_process_access_dump.yml')]); \
    print('OK', c.rules[0].detection.condition)"
OK ['selection and not 1 of filter_main_*']
```

Full ruleset also loads clean: `SigmaCollection.load_ruleset([Path('rules')])`
-> `5 rules`.

## Step 5 match-count grid (POST-tuning - current `raw/`)

Full 5x5 matrix re-run via `run_matrix.sh` after the edit. Only the `t1003`
row changed; every other cell is identical to Step 4.

| rule \\ log                       | T1003 lsass | T1021 smb | T1055 inject | T1547 runkey | T1059 ps (evtx) |
|-----------------------------------|:-----------:|:---------:|:------------:|:------------:|:---------------:|
| **t1003** lsass proc-access dump  |   **2** *   |     0     |      0       |      0       |        0        |
| **t1021** smb admin-share pipe    |     0       |  **1** *  |      0       |      0       |        0        |
| **t1055** create remote thread    |     0       |     0     |    **88** *  |      0       |        0        |
| **t1547** registry run key        |     0       |     0     |      0       |    **1** *   |        0        |
| **t1059** ps download cradle      |     0       |     1     |      1       |      1       |      **1** *    |

## Tuning log (before -> after)

| cell (rule vs log)      | before | after | what happened                                                                                 |
|-------------------------|:------:|:-----:|-----------------------------------------------------------------------------------------------|
| t1003 vs **T1021 smb**  |   1    |   0   | FP removed: `...\CollectGuestLogs.exe` (Azure agent, `0x1410`) now caught by `filter_main_azure_guest_agent`. |
| t1003 vs **T1547 runkey** | 2    |   0   | FP removed: `C:\windows\system32\wininit.exe` and `csrss.exe` (`0x1fffff`) now caught by `filter_main_windows_internals`. |
| t1003 vs **T1003 lsass** (diagonal, TP) | 2 | 2 | **True positive preserved**: `C:\Windows\System32\rundll32.exe` @ `0x1fffff` and `0x1410` - `rundll32.exe` is not in any filter, so both matches survive. |

All 22 other cells are unchanged from the Step 4 grid (diagonals t1021=1,
t1055=88, t1547=1, t1059=1; t1059 off-diagonals 1 each vs T1021/T1055/T1547;
everything else 0). Net effect: **3 false-positive matches eliminated, 0 true
positives lost.**
