# Detection Engineering: Sigma Rules

A defensive-security portfolio project: writing [Sigma](https://sigmahq.io/)
detection rules for a set of MITRE ATT&CK techniques and testing them against
genuine public sample attack logs (Windows + Sysmon). This is detection
engineering only - reading attacker telemetry and writing detections for it.
There is no offensive tooling and no live attacks in this repository.

## Status: in progress

Currently at step 2 (sample logs gathered). Rules not yet written.

## Plan

1. Pick techniques - **done** (5 techniques, see table below)
2. Gather sample logs - **done** (one real public sample per technique, verified)
3. Write Sigma rules - one detection rule per technique
4. Test - run each rule against its sample log and confirm it fires
5. Tune - reduce false positives, refine conditions
6. Publish

## Techniques covered

| # | Technique | ID | ATT&CK Tactic |
|---|-----------|----|---------------|
| 1 | Command and Scripting Interpreter: PowerShell | T1059.001 | Execution |
| 2 | OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access |
| 3 | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | Persistence |
| 4 | Process Injection | T1055 | Defense Evasion / Privilege Escalation |
| 5 | Remote Services: SMB/Windows Admin Shares | T1021.002 | Lateral Movement |

## Layout

```
rules/        Sigma detection rules (empty for now)
logs/         Sample attack logs, one subfolder per technique
              + ATTRIBUTION.md (sources/licenses) and per-folder SOURCE.md
screenshots/  Evidence of rules firing (empty for now)
```

## Licensing

This project is MIT-licensed (see `LICENSE`). **The MIT license covers only
Carlos Rodas's original content** - the Sigma rules, scripts, and
documentation. It does **not** cover the third-party sample logs under
`logs/`, which are redistributed from upstream projects and retain their own
licenses. Permissively-licensed (MIT) samples are committed directly;
copyleft (GPL-3.0) samples are not committed but are downloaded on demand by a
`fetch_sample.sh` script and kept out of git. See
[`logs/ATTRIBUTION.md`](logs/ATTRIBUTION.md) for the full breakdown.
