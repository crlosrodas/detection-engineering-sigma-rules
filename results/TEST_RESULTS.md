# Step 4 - Test results (5 rules x 5 logs)

Tool: **Zircolite v3.7.6** run per-rule with the correct pySigma pipeline (see
`README.md`). Raw evidence: `raw/<rule>__<log>.json`. Reproduce: `run_matrix.sh`.

## Match-count grid

Rows = rules, columns = logs. `*` marks the **diagonal** (a rule against its own
intended log = the expected true positive). All other cells are off-diagonal.

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
- `rules/` was not modified - all five rules pass as written (re-validated with
  pySigma 1.4.0 during this step).
