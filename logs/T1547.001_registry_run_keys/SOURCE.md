# SOURCE - T1547.001 Boot or Logon Autostart Execution: Registry Run Keys

## Sample file
- **File:** `empire_persistence_registry_modification_run_keys_standard_user_2020-09-04030609.json` (fetched locally, not committed)
- **Fetch with:** `./fetch_sample.sh` (run from this folder)
- **Note on size:** ~80 MB (80,321,735 bytes) uncompressed. This is the full,
  unmodified upstream dataset (40,569 events across several channels); only a
  couple of those events are the Run-key write itself, the rest is ambient host
  telemetry from the capture window. Kept whole to preserve provenance (not
  trimmed/altered).

## Source
- **Repo:** OTRF/Security-Datasets (formerly the Mordor project)
- **Dataset ID:** SDWIN-190319023812 - "Empire Userland Registry Run Keys"
- **Path in repo:** `datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip`
- **Raw URL:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user.zip

## License and vendored-vs-fetched decision
- **License:** MIT (permissive).
- **Decision:** FETCHED, not vendored. The REASON is **repo size, not license.**
- **Reasoning:** MIT is permissive and license-compatible with this repo, so
  vendoring (committing) this sample would have been perfectly fine on license
  grounds. It is kept out of git purely because it is large (~80 MB uncompressed,
  the biggest sample in the project) and would heavily bloat the history of every
  clone. `fetch_sample.sh` downloads the identical upstream OTRF zip and extracts
  the JSON, verifying it against a pinned sha256 (`9a781f7c...1b9725`) so the local
  file is provably byte-for-byte the same bytes `results/` and `screenshots/` were
  generated against. The extracted `.json` is listed in the repo `.gitignore`.

## What the log actually contains
JSON, one event per line. Represents a PowerShell Empire agent establishing
persistence by writing an autostart entry to a `...\CurrentVersion\Run`
registry key. Verified with Python:
- **Sysmon EID 13** (registry value set) on
  `HKU\S-1-5-21-...-1104\Software\Microsoft\Windows\CurrentVersion\Run\Updater`
  with `Details` =
  `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((...`
  - i.e. a PowerShell payload set to auto-run at logon (the malicious
  persistence). A second EID 13 on
  `HKLM\SOFTWARE\...\CurrentVersion\Run\WindowsDefender` (benign baseline) is
  also present.
- Rich supporting Sysmon telemetry: EID 12 (7,839 registry object
  create/delete), EID 13 (5,376 registry value set), EID 10 (1,931
  ProcessAccess), EID 1 (120 process creation), plus Security 4688/4689 and
  PowerShell logs.

## Event IDs a future Sigma rule will key on
- **Sysmon EID 13 (registry value set)** - `TargetObject` matching
  `\Software\Microsoft\Windows\CurrentVersion\Run\` (or `RunOnce`, and the
  HKLM/`Wow6432Node` equivalents), especially where `Details` points at
  `powershell.exe`, a script, or a suspicious path. Primary signal.
- Optionally **Sysmon EID 12** for Run-key creation, and Windows Security
  **EID 4657** (registry value modified) if that channel is available.
