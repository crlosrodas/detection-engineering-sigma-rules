# SOURCE - T1003.001 OS Credential Dumping: LSASS Memory

## Sample file
- **File:** `psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json` (vendored / committed)

## Source
- **Repo:** OTRF/Security-Datasets (formerly the Mordor project)
- **Dataset ID:** SDWIN-201018195009 - "Lsass Memory Dump via Comsvcs.dll"
- **Path in repo:** `datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip`
- **Raw URL:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip

## License and vendored-vs-fetched decision
- **License:** MIT (permissive).
- **Decision:** VENDORED (downloaded, unzipped, and committed into this repo).
- **Reasoning:** MIT is permissive and license-compatible with this repo, so
  the sample can be redistributed directly with attribution.

## What the log actually contains
JSON, one event per line (OTRF nxlog pipeline). 184 events total; channels
Microsoft-Windows-Sysmon/Operational (148) and Security (36). This captures the
Atomic Red Team T1003.001 "comsvcs.dll MiniDump" technique: dumping LSASS
memory by calling the `MiniDump` export of `comsvcs.dll` via `rundll32.exe`.
Verified with `jq`/Python:
- **Sysmon EID 1** (process creation): `rundll32.exe` with command line
  `"C:\Windows\System32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump
  756 C:\Users\wardog\AppData\Local\...\lsass-comsvcs.dmp full`
  (PID 756 is the target lsass process).
- **Sysmon EID 10** (ProcessAccess): 2 events where `SourceImage` is
  `rundll32.exe` and `TargetImage` is `...\lsass.exe`, with
  `GrantedAccess = 0x1FFFFF` (full rights - the hallmark of an LSASS dump).
- Supporting Sysmon EID 7 (image load), 11 (file create - the .dmp), 12/13
  (registry) events also present.

## Event IDs a future Sigma rule will key on
- **Sysmon EID 10 (ProcessAccess)** - `TargetImage` ending in `lsass.exe` with
  a high `GrantedAccess` mask (e.g. `0x1FFFFF`, `0x1010`, `0x1410`). Primary
  signal.
- **Sysmon EID 1 (process creation)** - `rundll32.exe` command line containing
  `comsvcs.dll` and `MiniDump` (technique-specific signal).
- Optionally **Sysmon EID 11 (FileCreate)** - creation of a `.dmp` file.
