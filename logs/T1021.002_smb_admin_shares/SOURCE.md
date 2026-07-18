# SOURCE - T1021.002 Remote Services: SMB/Windows Admin Shares

## Sample file
- **File:** `empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json` (vendored / committed)
- **Note on size:** ~20 MB uncompressed. Full, unmodified upstream dataset
  (7,504 events). Kept whole to preserve provenance.

## Source
- **Repo:** OTRF/Security-Datasets (formerly the Mordor project)
- **Dataset ID:** SDWIN-190518210125 - "Empire Invoke SMBExec"
- **Path in repo:** `datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip`
- **Raw URL:** https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip

## License and vendored-vs-fetched decision
- **License:** MIT (permissive).
- **Decision:** VENDORED (downloaded, unzipped, and committed into this repo).
- **Reasoning:** MIT is permissive and license-compatible with this repo, so
  the sample can be redistributed directly with attribution.

## What the log actually contains
JSON, one event per line. Represents SMBExec-style lateral movement: an
attacker remotely creates and starts a Windows service on the target via the
Service Control Manager (svcctl) RPC interface, reached over the SMB `IPC$`
named pipe. Verified with Python:
- **Security EID 5145 (network share object access):** `ShareName = \\*\IPC$`,
  `RelativeTargetName = svcctl`, `SubjectUserName = pgustavo` - the remote
  bind to the SCM RPC endpoint over SMB (the "admin share" access).
- **System EID 7045 (service installed):** `ServiceName = PGUJLOAKFQFVOMHGFQPX`
  (random name - an SMBExec/PsExec hallmark), `ImagePath = %COMSPEC% /C
  "%COMSPEC% /C start /b ...powershell -noP -sta -w 1 -enc <base64>"`.
- **Security EID 4697 (service installed):** same service, Security channel.
- **Sysmon EID 1 (process creation):** `services.exe` -> `cmd.exe /C ... start
  /b powershell -noP -sta -w 1 -enc SQBGAC(...)` - the service launching the
  encoded Empire payload (parent `services.exe` = remote service execution).
- Very high Sysmon EID 10 volume (4,380 ProcessAccess) plus EID 12/13/7.

## Event IDs a future Sigma rule will key on
- **Security EID 5145** - share access where `ShareName` is `IPC$` (or `ADMIN$`
  / `C$`) and `RelativeTargetName` is a service/exec named pipe such as
  `svcctl`, `psexecsvc`, `atsvc`. Primary lateral-movement signal.
- **System EID 7045 / Security EID 4697 (service installed)** - a service whose
  `ImagePath` is `cmd.exe`/`powershell.exe` with `-enc` / `%COMSPEC%`, often
  with a random `ServiceName`.
- **Sysmon EID 1** - `services.exe` spawning `cmd.exe`/`powershell.exe` with an
  encoded command (parent = `services.exe`).
