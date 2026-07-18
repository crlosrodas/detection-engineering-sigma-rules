#!/usr/bin/env bash
#
# setup_zircolite.sh - Provision a project-local, version-PINNED Zircolite clone.
#
# WHY PIN, AND WHY PROJECT-LOCAL?
# ------------------------------
# Zircolite is the engine that runs our Sigma rules against the sample logs
# (results/run_matrix.sh). The committed test results (results/raw/, the grids
# in results/TEST_RESULTS.md) and the screenshots were produced with Zircolite
# **v3.7.6** specifically. A newer Zircolite could change pySigma pipeline
# behaviour, conversion, or output shape and silently shift match counts - so
# for the results in this repo to be reproducible, the tool version must be
# pinned, not floating on whatever `master` happens to be today.
#
# This script clones Zircolite into tools/zircolite/ (inside the project, not
# /tmp) at the exact tag v3.7.6. Zircolite is third-party code and is NOT
# vendored into git - tools/zircolite/ is .gitignored; this script is how you
# reproduce it. The clone is what results/run_matrix.sh invokes.

set -euo pipefail

ZIRCO_TAG="v3.7.6"
ZIRCO_URL="https://github.com/wagga40/Zircolite"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJ="$(dirname "${SCRIPT_DIR}")"
DEST="${SCRIPT_DIR}/zircolite"
VENV_PY="${PROJ}/.venv/bin/python"

# --- 1. Clone (or reuse) at the exact pinned tag ------------------------------
need_clone=1
if [ -d "${DEST}/.git" ]; then
    current="$(git -C "${DEST}" describe --tags --always 2>/dev/null || echo '?')"
    if [ "${current}" = "${ZIRCO_TAG}" ]; then
        echo "[=] Zircolite already present at ${DEST} pinned to ${ZIRCO_TAG} - reusing."
        need_clone=0
    else
        echo "[*] Zircolite at ${DEST} is '${current}', not ${ZIRCO_TAG} - re-cloning."
        rm -rf "${DEST}"
    fi
elif [ -e "${DEST}" ]; then
    echo "[*] ${DEST} exists but is not a git clone - removing and re-cloning."
    rm -rf "${DEST}"
fi

if [ "${need_clone}" -eq 1 ]; then
    echo "[*] Cloning Zircolite ${ZIRCO_TAG} into ${DEST} ..."
    # --branch accepts a tag; --depth 1 keeps it a shallow, tag-pinned checkout.
    git clone --branch "${ZIRCO_TAG}" --depth 1 "${ZIRCO_URL}" "${DEST}"
fi

# Confirm the checkout really is the pinned tag (reproducibility guard).
resolved="$(git -C "${DEST}" describe --tags --always 2>/dev/null || echo '?')"
echo "[i] Zircolite checkout resolves to: ${resolved}"
if [ "${resolved}" != "${ZIRCO_TAG}" ]; then
    echo "[!] Expected tag ${ZIRCO_TAG} but got '${resolved}'." >&2
    exit 1
fi

# --- 2. Python dependencies ---------------------------------------------------
# Zircolite's deps are already covered by the project .venv (installed for the
# pySigma validation tooling): pysigma + the sqlite backend, the sysmon/windows
# pipelines, evtx, orjson, rich, py7zr, etc. We verify that here rather than
# blindly reinstalling; if anything is genuinely missing we install Zircolite's
# own requirements.txt into the venv.
if [ ! -x "${VENV_PY}" ]; then
    echo "[!] Project venv not found at ${PROJ}/.venv"
    echo "    Create it first:  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    echo "    Then re-run this script."
    exit 1
fi

echo "[*] Checking Zircolite's Python deps in the project venv ..."
if "${VENV_PY}" - <<'PY'
import importlib, sys
mods = ["orjson","xxhash","rich","chardet","RestrictedPython","requests",
        "jinja2","evtx","lxml","sigma","yaml","psutil","urllib3","py7zr",
        "sigma.backends.sqlite","sigma.pipelines.sysmon","sigma.pipelines.windows"]
missing = []
for m in mods:
    try:
        importlib.import_module(m)
    except Exception:
        missing.append(m)
if missing:
    print("MISSING: " + ", ".join(missing))
    sys.exit(1)
print("all Zircolite deps satisfied by the project venv")
PY
then
    echo "[+] Python deps OK - nothing to install."
else
    echo "[*] Some deps missing - installing Zircolite requirements into the venv ..."
    "${VENV_PY}" -m pip install -r "${DEST}/requirements.txt"
fi

echo
echo "[+] Done. Zircolite ${ZIRCO_TAG} ready at:"
echo "      ${DEST}"
echo "    Run the test matrix with:  bash ${PROJ}/results/run_matrix.sh"
