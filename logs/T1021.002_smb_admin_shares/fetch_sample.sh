#!/usr/bin/env bash
#
# fetch_sample.sh - Download the T1021.002 (SMB/Admin Shares) sample log on demand.
#
# WHY A FETCH SCRIPT INSTEAD OF A COMMITTED (VENDORED) FILE?
# ---------------------------------------------------------
# The REASON here is REPO SIZE, not licensing. This sample comes from
# OTRF/Security-Datasets, which is MIT-licensed (permissive) - vendoring it
# directly into this MIT repo would have been perfectly license-compatible.
# But the uncompressed JSON is ~20 MB, large enough that committing it bloats
# the git history for every future clone. So instead we:
#   1. keep only THIS small fetch script in git (our own MIT code),
#   2. .gitignore the extracted .json so it is never committed,
#   3. download the identical upstream file on demand for rule testing.
#
# The download is the exact upstream OTRF zip; the extracted JSON is verified
# byte-for-byte against a pinned sha256 (below) so the file used for testing is
# provably the same bytes the committed results/ and screenshots/ were built
# from. See SOURCE.md for dataset detail and content verification.

set -euo pipefail

# Upstream source zip (see SOURCE.md). Pinned to the OTRF master branch.
URL="https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl.zip"
FILENAME="empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json"
# sha256 of the extracted JSON - the exact bytes results/ and screenshots/ were
# generated against. The script aborts if the fetched file does not match.
EXPECTED_SHA256="04411a61f42eb9723d4e4abaa1ef9bba9883d118d0e55091993e577e6cb49ff7"

OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_FILE="${OUT_DIR}/${FILENAME}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
ZIP_FILE="${TMP_DIR}/sample.zip"

echo "[*] Downloading T1021.002 SMB/Admin Shares sample (MIT; fetched for repo size)..."
echo "    from: ${URL}"
echo "    to:   ${OUT_FILE}"

curl -fSL --retry 3 -m 300 "${URL}" -o "${ZIP_FILE}"

echo "[*] Extracting ${FILENAME}..."
# OTRF zips are usually NOT password-protected; if a future one is, the OTRF
# convention is the password "infected" (uncomment the -P line below).
unzip -o -q "${ZIP_FILE}" "${FILENAME}" -d "${OUT_DIR}"
# unzip -o -q -P infected "${ZIP_FILE}" "${FILENAME}" -d "${OUT_DIR}"

echo "[*] Verifying sha256..."
ACTUAL_SHA256="$(sha256sum "${OUT_FILE}" | awk '{print $1}')"
if [ "${ACTUAL_SHA256}" != "${EXPECTED_SHA256}" ]; then
    echo "[!] SHA256 MISMATCH - fetched file is not the expected bytes." >&2
    echo "    expected: ${EXPECTED_SHA256}" >&2
    echo "    actual:   ${ACTUAL_SHA256}" >&2
    exit 1
fi

echo "[+] Done. $(wc -c < "${OUT_FILE}") bytes written, sha256 verified."
echo "    This .json is .gitignored (fetched locally for repo-size reasons, never committed)."
