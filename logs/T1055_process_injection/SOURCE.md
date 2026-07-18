# SOURCE - T1055 Process Injection

## Sample file
- **File:** `empire_psinject_PEinjection_2020-08-07143205.json` (fetched locally, not committed)
- **Fetch with:** `./fetch_sample.sh` (run from this folder)
- **Note on size:** ~41 MB (41,664,401 bytes) uncompressed. Full, unmodified
  upstream dataset (5,898 events; the large size is mostly verbose PowerShell
  Script Block Logging message bodies). Kept whole to preserve provenance.

## Source
- **Repo:** OTRF/Security-Datasets (formerly the Mordor project)
- **Dataset ID:** SDWIN-190518200432 - "Empire PSInject"
- **Path in repo:** `datasets/atomic/windows/defense_evasion/host/empire_psinject_PEinjection.zip`
- **Raw URL:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_psinject_PEinjection.zip
- **ATT&CK mapping in dataset metadata:** T1055.003 (Thread Execution
  Hijacking / PE injection), a sub-technique of the assigned T1055.

## License and vendored-vs-fetched decision
- **License:** MIT (permissive).
- **Decision:** FETCHED, not vendored. The REASON is **repo size, not license.**
- **Reasoning:** MIT is permissive and license-compatible with this repo, so
  vendoring (committing) this sample would have been perfectly fine on license
  grounds. It is kept out of git purely because it is large (~41 MB uncompressed)
  and would bloat the history of every clone. `fetch_sample.sh` downloads the
  identical upstream OTRF zip and extracts the JSON, verifying it against a
  pinned sha256 (`46a7b799...ddb122`) so the local file is provably byte-for-byte
  the same bytes `results/` and `screenshots/` were generated against. The
  extracted `.json` is listed in the repo `.gitignore`.

## What the log actually contains
JSON, one event per line. Represents a PowerShell Empire agent reflectively
injecting a portable executable (PE) into another process: it allocates and
writes the PE into the target with `WriteProcessMemory` and runs it via
`CreateRemoteThread`. Verified with Python:
- **Sysmon EID 8 (CreateRemoteThread):** 88 events where `SourceImage` is
  `...\WindowsPowerShell\v1.0\powershell.exe` and `TargetImage` is
  `C:\Windows\System32\notepad.exe` - i.e. PowerShell creating a remote thread
  in notepad, the core injection artifact.
- **Sysmon EID 10 (ProcessAccess):** 561 events (cross-process handle opens,
  including high-rights access consistent with injection).
- Supporting Sysmon EID 7 (image load, 171), 12/13 (registry), plus heavy
  PowerShell Script Block Logging (channels Windows PowerShell / Microsoft-
  Windows-PowerShell/Operational).

## Event IDs a future Sigma rule will key on
- **Sysmon EID 8 (CreateRemoteThread)** - remote thread created in a process
  the source has no legitimate reason to inject into (e.g. `powershell.exe` ->
  `notepad.exe`). Primary signal.
- **Sysmon EID 10 (ProcessAccess)** - `GrantedAccess` masks granting
  write/execute rights (e.g. `0x1F3FFF`, containing `PROCESS_VM_WRITE` /
  `PROCESS_CREATE_THREAD`) to a foreign process. Corroborating signal.
