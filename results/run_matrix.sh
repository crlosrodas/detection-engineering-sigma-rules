#!/usr/bin/env bash
#
# run_matrix.sh - Run the full 5x5 Sigma-rule x log test matrix with Zircolite.
#
# One Zircolite invocation per (rule, log) cell = 25 runs. Each rule is loaded
# on its own and converted with ONLY the pySigma pipeline that matches its
# Sigma logsource:
#
#   rule                                        logsource          pipeline
#   ------------------------------------------  -----------------  -----------------
#   t1003 lsass process access                  process_access     sysmon
#   t1055 create remote thread                  create_remote_thread sysmon
#   t1547 registry run key                      registry_set       sysmon
#   t1059 powershell script-block download      ps_script          windows-logsources
#   t1021 smb admin-share service pipe          service:security   windows-audit
#
# WHY per-rule pipelines (not all three at once): the `sysmon` and
# `windows-audit` pipelines BOTH claim the generic `registry_set` category
# (sysmon -> Sysmon EID 13 with field `Details`; windows-audit -> Security
# auditing EID 4657 with field `NewValue`). Concatenating them onto the same
# rule produces the self-contradictory predicate `EventID=4657 AND EventID=13`
# and renames `Details` to `NewValue`, so the registry rule can never match a
# Sysmon EID 13 log. Selecting the correct pipeline per rule avoids this.
#
# Inputs in logs/ are NEVER modified. JSON-lines OTRF logs use -j; the EVTX
# uses Zircolite native auto-detection.
#
# Requires: the project .venv activated, and the project-local Zircolite clone
# provisioned by tools/setup_zircolite.sh (pinned to tag v3.7.6).
set -euo pipefail

PROJ="/home/carlos/projects/detection-engineering-sigma-rules"
ZIRCO="$PROJ/tools/zircolite"
OUT="$PROJ/results/raw"
mkdir -p "$OUT"

# --- rules: key|file|pipeline --------------------------------------------------
RULE_KEYS=(t1003_lsass t1021_smb t1055_inject t1547_runkey t1059_ps)
declare -A RULE_FILE=(
  [t1003_lsass]="$PROJ/rules/t1003_001_lsass_process_access_dump.yml"
  [t1021_smb]="$PROJ/rules/t1021_002_smb_admin_share_service_pipe.yml"
  [t1055_inject]="$PROJ/rules/t1055_create_remote_thread_from_scripting_process.yml"
  [t1547_runkey]="$PROJ/rules/t1547_001_registry_run_key_suspicious_payload.yml"
  [t1059_ps]="$PROJ/rules/t1059_001_powershell_download_cradle.yml"
)
declare -A RULE_PIPE=(
  [t1003_lsass]="sysmon"
  [t1021_smb]="windows-audit"
  [t1055_inject]="sysmon"
  [t1547_runkey]="sysmon"
  [t1059_ps]="windows-logsources"
)

# --- logs: key|file|input-flag -------------------------------------------------
LOG_KEYS=(T1003_lsass T1021_smb T1055_injection T1547_runkeys T1059_powershell)
declare -A LOG_FILE=(
  [T1003_lsass]="$PROJ/logs/T1003.001_lsass_dump/psh_lsass_memory_dump_comsvcs_2020-10-18T19500924.json"
  [T1021_smb]="$PROJ/logs/T1021.002_smb_admin_shares/empire_smbexec_dcerpc_smb_svcctl_2020-09-20025716.json"
  [T1055_injection]="$PROJ/logs/T1055_process_injection/empire_psinject_PEinjection_2020-08-07143205.json"
  [T1547_runkeys]="$PROJ/logs/T1547.001_registry_run_keys/empire_persistence_registry_modification_run_keys_standard_user_2020-09-04030609.json"
  [T1059_powershell]="$PROJ/logs/T1059.001_powershell/exec_emotet_ps_4104.evtx"
)
declare -A LOG_FLAG=(
  [T1003_lsass]="-j"
  [T1021_smb]="-j"
  [T1055_injection]="-j"
  [T1547_runkeys]="-j"
  [T1059_powershell]=""     # EVTX: native auto-detect
)

for rk in "${RULE_KEYS[@]}"; do
  for lk in "${LOG_KEYS[@]}"; do
    echo "=== rule=$rk  log=$lk  (pipeline=${RULE_PIPE[$rk]}) ==="
    args=(-e "${LOG_FILE[$lk]}"
          -r "${RULE_FILE[$rk]}"
          -p ${RULE_PIPE[$rk]}
          -o "$OUT/${rk}__${lk}.json"
          -l "$OUT/${rk}__${lk}.log" -q)
    flag="${LOG_FLAG[$lk]}"
    [ -n "$flag" ] && args+=("$flag")
    ( cd "$ZIRCO" && python3 zircolite.py "${args[@]}" ) || true
  done
done
echo "=== DONE ==="
