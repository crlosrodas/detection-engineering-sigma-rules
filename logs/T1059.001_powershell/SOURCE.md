# SOURCE - T1059.001 Command and Scripting Interpreter: PowerShell

## Sample file
- **File:** `exec_emotet_ps_4104.evtx` (fetched locally, not committed)
- **Fetch with:** `./fetch_sample.sh` (run from this folder)

## Source
- **Repo:** sbousseaden/EVTX-ATTACK-SAMPLES
- **Path in repo:** `Other/emotet/exec_emotet_ps_4104.evtx`
- **Raw URL:** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Other/emotet/exec_emotet_ps_4104.evtx

## License and vendored-vs-fetched decision
- **License:** GPL-3.0 (`LICENSE.GPL` in the source repo root).
- **Decision:** FETCHED, not vendored.
- **Reasoning:** GPL-3.0 is a copyleft license. This project's own content is
  MIT-licensed, and we do not want to mix a copyleft-licensed file into the
  committed MIT tree. Redistribution is legal, but to keep the committed repo
  cleanly MIT the file is downloaded on demand by `fetch_sample.sh` and is
  listed in the repo `.gitignore` so it is never committed. It is present
  locally (the fetch script has been run) for rule testing.

## Why not the MIT (Security-Datasets) option?
OTRF/Security-Datasets (MIT) does have a T1059.001 dataset
(`psh_powershell_httplistener`), but on inspection that capture contains no
PowerShell process-creation event (Sysmon EID 1) and no Script Block Logging
event (EID 4104) - only downstream Sysmon EID 10/13/22 activity from an
already-running PowerShell process. Those are the two artifacts a T1059.001
Sigma rule normally keys on, so the GPL Emotet sample below is a materially
better and more accurate test case. The tradeoff (a fetch script + gitignore
instead of a vendored file) is worth it for detection accuracy.

## What the log actually contains
Verified by parsing the .evtx with `python-evtx` and by `strings -el`:
- A **single event record**, **EventID 4104** (PowerShell Script Block Logging),
  on channel **Microsoft-Windows-PowerShell/Operational**, host `DESKTOP-RIPCLIP`,
  timestamp `2020-08-26 05:09:28 UTC`.
- The `ScriptBlockText` is a real, heavily string-concatenation-obfuscated
  **Emotet** PowerShell downloader one-liner. Deobfuscated behaviour:
  - `New-Object Net.WebClient` then `.DownloadFile(...)`
  - iterates over a list of ~8 hard-coded payload URLs (compromised WordPress
    sites) and downloads to `$env:temp\word\2019\<name>.exe`
  - sets `[Net.ServicePointManager]::SecurityProtocol` to TLS 1.2/1.1/1.0
  - on a successful download over 28315 bytes, executes it via `Invoke-Item`.

## Event IDs a future Sigma rule will key on
- **EID 4104** (Microsoft-Windows-PowerShell/Operational) - Script Block
  Logging. Rule logic would match on `ScriptBlockText` containing tell-tale
  obfuscation / download-cradle indicators (e.g. `New-Object Net.WebClient`,
  `.DownloadFile`, `Net.ServicePointManager`, large numbers of `+`
  concatenation operators, `-enc`/`FromBase64String`, `IEX`).
