# Log Sample Attribution

All sample logs under `logs/` are redistributed from public projects and
retain their upstream licensing. They are NOT covered by this repo's MIT
license (which covers Carlos Rodas's original rules/scripts/docs only). See
each technique folder's `SOURCE.md` for full detail and content verification.

Handling is decided **per file**, on two independent axes - license and size -
not by a single vendored=MIT / fetched=GPL rule:
- **Vendored** (committed) = the file is both permissively licensed (MIT) **and**
  small enough not to matter for repo size. Only **T1003.001** qualifies
  (~287 KB).
- **Fetched for size** = MIT-licensed (vendoring would be license-fine) but too
  large to commit without bloating every clone. The three large OTRF logs
  (**T1021.002** ~20 MB, **T1055** ~41 MB, **T1547.001** ~80 MB) are fetched
  on demand by `fetch_sample.sh` and `.gitignore`d. Each fetch script verifies
  the extracted file against a pinned sha256, so it is byte-identical to what
  `results/` and `screenshots/` were built from.
- **Fetched for license** = copyleft (GPL-3.0), kept out of the MIT tree on
  license grounds. Only **T1059.001** qualifies; it is likewise fetched by
  `fetch_sample.sh` and `.gitignore`d.

In short: everything except the small T1003.001 sample is fetched on demand -
three for size, one for license.

| Technique | Tactic | Source repo | License | Handling | Content (one line) |
|-----------|--------|-------------|---------|----------|--------------------|
| T1059.001 PowerShell | Execution | sbousseaden/EVTX-ATTACK-SAMPLES | GPL-3.0 | Fetched (license; gitignored) | 1x PowerShell Script Block Log (EID 4104) of a real obfuscated Emotet download-cradle one-liner. |
| T1003.001 LSASS Memory | Credential Access | OTRF/Security-Datasets | MIT | Vendored (~287 KB) | Sysmon EID 10 rundll32 -> lsass.exe (GrantedAccess 0x1FFFFF) + EID 1 comsvcs.dll MiniDump. |
| T1547.001 Registry Run Keys | Persistence | OTRF/Security-Datasets | MIT | Fetched (size ~80 MB; gitignored) | Sysmon EID 13 value-set on ...\CurrentVersion\Run\Updater pointing at powershell.exe (Empire persistence). |
| T1055 Process Injection | Defense Evasion / Priv Esc | OTRF/Security-Datasets | MIT | Fetched (size ~41 MB; gitignored) | Sysmon EID 8 CreateRemoteThread powershell.exe -> notepad.exe (Empire PE injection). |
| T1021.002 SMB/Admin Shares | Lateral Movement | OTRF/Security-Datasets | MIT | Fetched (size ~20 MB; gitignored) | Security EID 5145 IPC$/svcctl + EID 7045/4697 random-named service running powershell -enc (Empire SMBExec). |

## Upstream projects
- **OTRF/Security-Datasets** (formerly Mordor) - https://github.com/OTRF/Security-Datasets - MIT License.
- **sbousseaden/EVTX-ATTACK-SAMPLES** - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES - GPL-3.0 (LICENSE.GPL).

With thanks to Roberto Rodriguez (@Cyb3rWard0g) / the OTRF project and to
Samir Bousseaden for making these datasets public.
