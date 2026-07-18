# Log Sample Attribution

All sample logs under `logs/` are redistributed from public projects and
retain their upstream licensing. They are NOT covered by this repo's MIT
license (which covers Carlos Rodas's original rules/scripts/docs only). See
each technique folder's `SOURCE.md` for full detail and content verification.

Two handling rules are applied based on the source license:
- **Vendored** = license is permissive (MIT) -> the file is committed into
  this repo with attribution.
- **Fetched** = license is copyleft (GPL-3.0) -> the file is NOT committed; a
  `fetch_sample.sh` downloads it on demand and it is `.gitignore`d, to keep
  the committed tree cleanly MIT.

| Technique | Tactic | Source repo | License | Handling | Content (one line) |
|-----------|--------|-------------|---------|----------|--------------------|
| T1059.001 PowerShell | Execution | sbousseaden/EVTX-ATTACK-SAMPLES | GPL-3.0 | Fetched (gitignored) | 1x PowerShell Script Block Log (EID 4104) of a real obfuscated Emotet download-cradle one-liner. |
| T1003.001 LSASS Memory | Credential Access | OTRF/Security-Datasets | MIT | Vendored | Sysmon EID 10 rundll32 -> lsass.exe (GrantedAccess 0x1FFFFF) + EID 1 comsvcs.dll MiniDump. |
| T1547.001 Registry Run Keys | Persistence | OTRF/Security-Datasets | MIT | Vendored | Sysmon EID 13 value-set on ...\CurrentVersion\Run\Updater pointing at powershell.exe (Empire persistence). |
| T1055 Process Injection | Defense Evasion / Priv Esc | OTRF/Security-Datasets | MIT | Vendored | Sysmon EID 8 CreateRemoteThread powershell.exe -> notepad.exe (Empire PE injection). |
| T1021.002 SMB/Admin Shares | Lateral Movement | OTRF/Security-Datasets | MIT | Vendored | Security EID 5145 IPC$/svcctl + EID 7045/4697 random-named service running powershell -enc (Empire SMBExec). |

## Upstream projects
- **OTRF/Security-Datasets** (formerly Mordor) - https://github.com/OTRF/Security-Datasets - MIT License.
- **sbousseaden/EVTX-ATTACK-SAMPLES** - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES - GPL-3.0 (LICENSE.GPL).

With thanks to Roberto Rodriguez (@Cyb3rWard0g) / the OTRF project and to
Samir Bousseaden for making these datasets public.
