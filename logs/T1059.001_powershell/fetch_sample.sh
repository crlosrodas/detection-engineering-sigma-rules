#!/usr/bin/env bash
#
# fetch_sample.sh - Download the T1059.001 (PowerShell) sample log on demand.
#
# WHY A FETCH SCRIPT INSTEAD OF A COMMITTED (VENDORED) FILE?
# ---------------------------------------------------------
# The sample below comes from sbousseaden/EVTX-ATTACK-SAMPLES, which is
# licensed GPL-3.0 (see LICENSE.GPL in that repo's root). GPL-3.0 is a
# copyleft license. This project (Carlos's original rules/scripts/docs) is
# MIT-licensed, and we do NOT want to pull a copyleft-licensed file into the
# committed tree and risk mixing license obligations. Redistribution of the
# GPL file is legal, but to keep the committed repo cleanly MIT we instead:
#   1. keep only THIS small fetch script in git (our own MIT code),
#   2. .gitignore the downloaded .evtx so it is never committed,
#   3. download it on demand so it is present locally for rule testing.
#
# The equivalent MIT-licensed source (OTRF/Security-Datasets) does have a
# T1059.001 dataset (psh_powershell_httplistener), but that capture does not
# contain a PowerShell process-creation (Sysmon EID 1) or Script Block
# Logging (EID 4104) event - the two artifacts a T1059.001 Sigma rule keys
# on. The EVTX-ATTACK-SAMPLES file below is a real Emotet PowerShell
# downloader captured via Script Block Logging (EID 4104), which is a far
# more accurate T1059.001 test case. See SOURCE.md for full detail.

set -euo pipefail

# Raw file location within the source repo (pinned to the master branch).
URL="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/Other/emotet/exec_emotet_ps_4104.evtx"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_FILE="${OUT_DIR}/exec_emotet_ps_4104.evtx"

echo "[*] Downloading T1059.001 PowerShell sample (GPL-3.0, not committed)..."
echo "    from: ${URL}"
echo "    to:   ${OUT_FILE}"

curl -fSL --retry 3 -m 120 "${URL}" -o "${OUT_FILE}"

echo "[+] Done. $(wc -c < "${OUT_FILE}") bytes written."
echo "    This .evtx is .gitignored (GPL-3.0 - fetched locally, never committed)."
