#!/usr/bin/env bash
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$REPO_ROOT/build}"
RESULT_DIR="${RESULT_DIR:-$BUILD_DIR/test-results}"
LOG_DIR="$RESULT_DIR/logs"
RESULTS_TSV="$RESULT_DIR/auto-results.tsv"
AUTO_RESULTS="$RESULT_DIR/auto-results.json"
RUN_BUILD=1

usage() {
    cat <<'EOF'
Usage: scripts/run-validation-suite.sh [--skip-build]

Runs the conservative automated validation suite and writes:
  build/test-results/auto-results.json
  build/test-results/logs/*.log

Environment overrides:
  BUILD_DIR=/path/to/build
  RESULT_DIR=/path/to/results
  PYTHON_BIN=/path/to/python
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build)
            RUN_BUILD=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -n "${PYTHON_BIN:-}" ]]; then
    PYTHON="$PYTHON_BIN"
elif [[ -x "$REPO_ROOT/C2Client/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/C2Client/.venv/bin/python"
else
    PYTHON="python3"
fi
AGGREGATOR_PYTHON="${AGGREGATOR_PYTHON:-python3}"

export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"

mkdir -p "$RESULT_DIR" "$LOG_DIR"
: > "$RESULTS_TSV"

BUILD_TARGETS=(
    testsTestServer
    testsTeamServerHelpService
    testsTeamServerCommandPreparationService
    testsTeamServerListenerArtifactService
    testsTeamServerArtifactCatalog
    testsTeamServerCommandCatalog
    testsTeamServerSocksService
    TestsSocksServer
    testsTeamServerTermLocalService
    testsTeamServerListenerSessionService
    testsTeamServerHttpListenerTransport
    testsModuleCmd
    testsTools
    testsAssemblyExec
    testsCat
    testsChangeDirectory
    testsChisel
    testsCimExec
    testsCoffLoader
    testsDcomExec
    testsDotnetExec
    testsDownload
    testsEnumerateRdpSessions
    testsEnumerateShares
    testsEvasion
    testsGetEnv
    testsInject
    testsIpConfig
    testsKerberosUseTicket
    testsKeyLogger
    testsKillProcess
    testsListDirectory
    testsListProcesses
    testsMakeToken
    testsMiniDump
    testsMkDir
    testsNetstat
    testsPowershell
    testsPrintWorkingDirectory
    testsPsExec
    testsPwSh
    testsRegistry
    testsRemove
    testsRev2self
    testsReversePortForward
    testsRun
    testsScreenShot
    testsScript
    testsShell
    testsSpawnAs
    testsSshExec
    testsStealToken
    testsTaskScheduler
    testsTree
    testsUpload
    testsWhoami
    testsWinRM
    testsWmiExec
)

BUILD_STATUS=0
if [[ "$RUN_BUILD" -eq 1 ]]; then
    echo "[build] ${BUILD_TARGETS[*]}"
    if cmake --build "$BUILD_DIR" --target "${BUILD_TARGETS[@]}" --parallel 2 > "$LOG_DIR/build.log" 2>&1; then
        echo "[build] ok"
    else
        BUILD_STATUS=$?
        echo "[build] failed, see $LOG_DIR/build.log"
    fi
fi

safe_name() {
    local value="$1"
    value="${value//[^A-Za-z0-9_.-]/_}"
    printf '%s' "$value"
}

record_result() {
    local ids="$1"
    local status="$2"
    local source="$3"
    local log_file="$4"
    local detail="$5"
    local id
    for id in $ids; do
        printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$status" "$source" "$log_file" "$detail" >> "$RESULTS_TSV"
    done
}

run_case() {
    local ids="$1"
    local source="$2"
    shift 2
    local log_file="$LOG_DIR/$(safe_name "$source").log"
    local status="pass"
    local detail=""

    echo "[run] $source"
    if [[ "$BUILD_STATUS" -ne 0 && "${1:-}" == "$BUILD_DIR"/* ]]; then
        status="fail"
        detail="build failed before execution"
        printf '%s\n' "$detail" > "$log_file"
    elif [[ ! -x "${1:-}" && "${1:-}" == "$BUILD_DIR"/* ]]; then
        status="blocked"
        detail="executable not found"
        printf '%s: %s\n' "$detail" "${1:-}" > "$log_file"
    else
        "$@" > "$log_file" 2>&1
        local code=$?
        if [[ "$code" -eq 0 ]]; then
            status="pass"
            detail="exit code 0"
        elif [[ "$code" -eq 77 ]]; then
            status="blocked"
            detail="exit code 77"
        else
            status="fail"
            detail="exit code $code"
        fi
    fi

    record_result "$ids" "$status" "$source" "$log_file" "$detail"
    echo "[${status}] $source"
}

cpp_test() {
    local ids="$1"
    local name="$2"
    run_case "$ids" "$name" "$BUILD_DIR/tests/bin/$name"
}

pytest_case() {
    local ids="$1"
    local source="$2"
    shift 2
    run_case "$ids" "$source" "$PYTHON" -m pytest -s -q "$@"
}

cpp_test "TEAMSERVER-STARTUP-TLS-001" "testsTestServer"
cpp_test "TEAMSERVER-COMMAND-CATALOG-001 COMMON-HELP-001 C2CLIENT-CONSOLE-HELP-001" "testsTeamServerHelpService"
cpp_test "TEAMSERVER-COMMAND-PREPARATION-001 TEAMSERVER-FILE-TRANSFER-001 TEAMSERVER-GENERATED-ARTIFACTS-001 ARTIFACT-TOOLS-001 ARTIFACT-SCRIPTS-001 ARTIFACT-UPLOADED-001 MODULE-ASSEMBLYEXEC-CONTRACT-001 MODULE-INJECT-CONTRACT-001 MODULE-DOWNLOAD-CONTRACT-001 MODULE-UPLOAD-CONTRACT-001 MODULE-MINIDUMP-CONTRACT-001 MODULE-SCREENSHOT-CONTRACT-001 MODULE-POWERSHELL-CONTRACT-001 MODULE-PWSH-CONTRACT-001 MODULE-SCRIPT-CONTRACT-001 MODULE-CHISEL-CONTRACT-001 MODULE-DOTNETEXEC-CONTRACT-001 MODULE-PSEXEC-CONTRACT-001 MODULE-KERBEROSUSETICKET-CONTRACT-001 MODULE-COFFLOADER-CONTRACT-001" "testsTeamServerCommandPreparationService"
cpp_test "TEAMSERVER-LISTENER-ARTIFACT-SERVICE-001" "testsTeamServerListenerArtifactService"
cpp_test "TEAMSERVER-ARTIFACT-CATALOG-001 TEAMSERVER-GENERATED-ARTIFACTS-001 ARTIFACT-GENERATED-001 ARTIFACT-LAYOUT-001 ARTIFACT-UPLOADED-001 C2CLIENT-ARTIFACTS-LIST-001" "testsTeamServerArtifactCatalog"
cpp_test "TEAMSERVER-COMMAND-CATALOG-001 MODULE-COMMANDSPEC-COVERAGE-001 COMMON-HELP-001" "testsTeamServerCommandCatalog"
cpp_test "TEAMSERVER-SOCKS-SERVICE-001" "testsTeamServerSocksService"
cpp_test "LIBSOCKS5-PROTOCOL-001" "TestsSocksServer"
cpp_test "TEAMSERVER-HOSTED-ARTIFACTS-001 C2CLIENT-TERMINAL-HOST-001" "testsTeamServerTermLocalService"
cpp_test "TEAMSERVER-LISTENER-SESSION-SERVICE-001 TEAMSERVER-FILE-TRANSFER-001 BEACON-CORE-MODULE-LIFECYCLE-001 COMMON-LOADMODULE-001 COMMON-UNLOADMODULE-001 COMMON-LISTMODULE-001 BEACON-CORE-TASK-QUEUE-001" "testsTeamServerListenerSessionService"
cpp_test "LISTENER-HTTPS-001" "testsTeamServerHttpListenerTransport"

cpp_test "COMMON-HELP-001 COMMON-SLEEP-001 COMMON-END-001 COMMON-LISTENER-001 COMMON-LOADMODULE-001 COMMON-UNLOADMODULE-001 COMMON-LISTMODULE-001 MODULE-COMMANDSPEC-COVERAGE-001 BEACON-CORE-MODULE-LIFECYCLE-001" "testsModuleCmd"
cpp_test "TEAMSERVER-CONFIG-DIRECTORIES-001 ARTIFACT-LAYOUT-001 ARTIFACT-TOOLS-001 ARTIFACT-SCRIPTS-001 ARTIFACT-UPLOADED-001 ARTIFACT-GENERATED-001" "testsTools"

cpp_test "MODULE-ASSEMBLYEXEC-CONTRACT-001 TEAMSERVER-SHELLCODE-SERVICE-001" "testsAssemblyExec"
cpp_test "MODULE-CAT-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsCat"
cpp_test "MODULE-CD-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsChangeDirectory"
cpp_test "MODULE-CHISEL-CONTRACT-001" "testsChisel"
cpp_test "MODULE-CIMEXEC-CONTRACT-001 MODULE-WINDOWS-EXEC-001" "testsCimExec"
cpp_test "MODULE-COFFLOADER-CONTRACT-001" "testsCoffLoader"
cpp_test "MODULE-DCOMEXEC-CONTRACT-001 MODULE-WINDOWS-EXEC-001" "testsDcomExec"
cpp_test "MODULE-DOTNETEXEC-CONTRACT-001" "testsDotnetExec"
cpp_test "MODULE-DOWNLOAD-CONTRACT-001 BEACON-CORE-CHUNKED-RESULTS-001 MODULE-SIMPLE-FILESYSTEM-001" "testsDownload"
cpp_test "MODULE-ENUMERATERDPSESSIONS-CONTRACT-001 MODULE-WINDOWS-ADMIN-001" "testsEnumerateRdpSessions"
cpp_test "MODULE-ENUMERATESHARES-CONTRACT-001 MODULE-WINDOWS-ADMIN-001" "testsEnumerateShares"
cpp_test "MODULE-EVASION-CONTRACT-001 MODULE-WINDOWS-ADMIN-001" "testsEvasion"
cpp_test "MODULE-GETENV-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsGetEnv"
cpp_test "MODULE-INJECT-CONTRACT-001 TEAMSERVER-SHELLCODE-SERVICE-001" "testsInject"
cpp_test "MODULE-IPCONFIG-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsIpConfig"
cpp_test "MODULE-KERBEROSUSETICKET-CONTRACT-001" "testsKerberosUseTicket"
cpp_test "MODULE-KEYLOGGER-CONTRACT-001" "testsKeyLogger"
cpp_test "MODULE-KILLPROCESS-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsKillProcess"
cpp_test "MODULE-LS-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsListDirectory"
cpp_test "MODULE-PS-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsListProcesses"
cpp_test "MODULE-MAKETOKEN-CONTRACT-001 MODULE-WINDOWS-PRIVILEGE-001" "testsMakeToken"
cpp_test "MODULE-MINIDUMP-CONTRACT-001 BEACON-CORE-CHUNKED-RESULTS-001" "testsMiniDump"
cpp_test "MODULE-MKDIR-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsMkDir"
cpp_test "MODULE-NETSTAT-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsNetstat"
cpp_test "MODULE-POWERSHELL-CONTRACT-001 ARTIFACT-SCRIPTS-001" "testsPowershell"
cpp_test "MODULE-PWD-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsPrintWorkingDirectory"
cpp_test "MODULE-PSEXEC-CONTRACT-001" "testsPsExec"
cpp_test "MODULE-PWSH-CONTRACT-001 ARTIFACT-TOOLS-001" "testsPwSh"
cpp_test "MODULE-REGISTRY-CONTRACT-001 MODULE-WINDOWS-ADMIN-001" "testsRegistry"
cpp_test "MODULE-REMOVE-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsRemove"
cpp_test "MODULE-REV2SELF-CONTRACT-001 MODULE-WINDOWS-PRIVILEGE-001" "testsRev2self"
cpp_test "MODULE-REVERSEPORTFORWARD-CONTRACT-001" "testsReversePortForward"
cpp_test "MODULE-RUN-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsRun"
cpp_test "MODULE-SCREENSHOT-CONTRACT-001 BEACON-CORE-CHUNKED-RESULTS-001" "testsScreenShot"
cpp_test "MODULE-SCRIPT-CONTRACT-001 ARTIFACT-SCRIPTS-001" "testsScript"
cpp_test "MODULE-SHELL-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsShell"
cpp_test "MODULE-SPAWNAS-CONTRACT-001 MODULE-WINDOWS-PRIVILEGE-001" "testsSpawnAs"
cpp_test "MODULE-SSHEXEC-CONTRACT-001 MODULE-WINDOWS-EXEC-001" "testsSshExec"
cpp_test "MODULE-STEALTOKEN-CONTRACT-001 MODULE-WINDOWS-PRIVILEGE-001" "testsStealToken"
cpp_test "MODULE-TASKSCHEDULER-CONTRACT-001 MODULE-WINDOWS-ADMIN-001" "testsTaskScheduler"
cpp_test "MODULE-TREE-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsTree"
cpp_test "MODULE-UPLOAD-CONTRACT-001 MODULE-SIMPLE-FILESYSTEM-001" "testsUpload"
cpp_test "MODULE-WHOAMI-CONTRACT-001 MODULE-SIMPLE-SYSTEM-001" "testsWhoami"
cpp_test "MODULE-WINRM-CONTRACT-001 MODULE-WINDOWS-EXEC-001" "testsWinRM"
cpp_test "MODULE-WMIEXEC-CONTRACT-001 MODULE-WINDOWS-EXEC-001" "testsWmiExec"

pytest_case "C2CLIENT-CONFIG-ENV-001 C2CLIENT-CONFIG-CERT-001" "pytest:test_env_loading.py" "$REPO_ROOT/C2Client/tests/test_env_loading.py"
pytest_case "C2CLIENT-RPC-BINDINGS-001" "pytest:test_protocol_bindings.py" "$REPO_ROOT/C2Client/tests/test_protocol_bindings.py"
pytest_case "C2CLIENT-RPC-BINDINGS-001 C2CLIENT-CONFIG-CERT-001" "pytest:test_grpc_client.py" "$REPO_ROOT/C2Client/tests/test_grpc_client.py"
pytest_case "C2CLIENT-STARTUP-GUI-001" "pytest:test_gui_startup.py" "$REPO_ROOT/C2Client/tests/test_gui_startup.py"
pytest_case "C2CLIENT-SESSION-PANEL-001 BEACON-CORE-HEARTBEAT-001 BEACON-CORE-REGISTER-001" "pytest:test_session_panel.py" "$REPO_ROOT/C2Client/tests/test_session_panel.py"
pytest_case "C2CLIENT-LISTENER-PANEL-001 VALIDATION-ERROR-HANDLING-001" "pytest:test_listener_panel.py" "$REPO_ROOT/C2Client/tests/test_listener_panel.py"
pytest_case "C2CLIENT-GRAPH-PANEL-001" "pytest:test_graph_panel.py" "$REPO_ROOT/C2Client/tests/test_graph_panel.py"
pytest_case "C2CLIENT-CONSOLE-FORMATTING-001 C2CLIENT-CONSOLE-AUTOCOMPLETE-001 C2CLIENT-CONSOLE-HELP-001 VALIDATION-ERROR-HANDLING-001 COMMON-LOADMODULE-001 COMMON-UNLOADMODULE-001 COMMON-LISTMODULE-001 MODULE-ASSEMBLYEXEC-CONTRACT-001 MODULE-INJECT-CONTRACT-001 MODULE-DOTNETEXEC-CONTRACT-001" "pytest:test_console_panel.py" "$REPO_ROOT/C2Client/tests/test_console_panel.py"
pytest_case "C2CLIENT-TERMINAL-BASE-001 C2CLIENT-TERMINAL-DROPPER-001 C2CLIENT-TERMINAL-HOST-001" "pytest:test_terminal_panel_dropper_arch.py" "$REPO_ROOT/C2Client/tests/test_terminal_panel_dropper_arch.py"
pytest_case "C2CLIENT-ARTIFACTS-LIST-001 C2CLIENT-ARTIFACTS-UPLOAD-001 C2CLIENT-ARTIFACTS-DOWNLOAD-001 C2CLIENT-ARTIFACTS-DELETE-001 ARTIFACT-UPLOADED-001 TEAMSERVER-ARTIFACT-CATALOG-001" "pytest:test_artifact_panel.py" "$REPO_ROOT/C2Client/tests/test_artifact_panel.py"
pytest_case "C2CLIENT-HOOKS-PANEL-001" "pytest:test_script_panel.py" "$REPO_ROOT/C2Client/tests/test_script_panel.py"
pytest_case "C2CLIENT-AI-PANEL-001" "pytest:test_assistant_panel.py" "$REPO_ROOT/C2Client/tests/test_assistant_panel.py"
pytest_case "C2CLIENT-MAIN-THEME-001 C2CLIENT-SESSION-PANEL-001" "pytest:test_ui_status.py" "$REPO_ROOT/C2Client/tests/test_ui_status.py"
pytest_case "C2CLIENT-AI-PANEL-001 MODULE-COMMANDSPEC-COVERAGE-001 C2CLIENT-CONSOLE-AUTOCOMPLETE-001" "pytest:assistant_agent" "$REPO_ROOT/C2Client/tests/assistant_agent"

if ! "$AGGREGATOR_PYTHON" - "$REPO_ROOT/docs/testing/test-catalog.yaml" "$RESULTS_TSV" "$AUTO_RESULTS" <<'PY'
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

catalog_path = Path(sys.argv[1])
tsv_path = Path(sys.argv[2])
output_path = Path(sys.argv[3])
catalog = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
catalog_ids = {entry["id"] for entry in catalog["entries"]}
precedence = {"fail": 0, "blocked": 1, "pass": 2}
grouped = defaultdict(list)

with tsv_path.open("r", encoding="utf-8", newline="") as handle:
    reader = csv.reader(handle, delimiter="\t")
    for row in reader:
        if not row:
            continue
        result_id, status, source, log_file, detail = row
        if result_id not in catalog_ids:
            raise SystemExit(f"unknown catalog id in auto result: {result_id}")
        grouped[result_id].append({
            "status": status,
            "source": source,
            "log_file": log_file,
            "detail": detail,
        })

results = []
for result_id in sorted(grouped):
    records = grouped[result_id]
    status = min((record["status"] for record in records), key=lambda item: precedence.get(item, -1))
    results.append({
        "id": result_id,
        "status": status,
        "source": ", ".join(record["source"] for record in records),
        "evidence": "; ".join(f"{record['source']} -> {record['detail']}" for record in records),
        "logs": [record["log_file"] for record in records],
    })

output_path.write_text(json.dumps({"schema_version": 1, "results": results}, indent=2) + "\n", encoding="utf-8")
print(f"Wrote {output_path} with {len(results)} result ids")
PY
then
    echo "Failed to aggregate auto validation results." >&2
    exit 1
fi

echo "Auto validation results written to $AUTO_RESULTS"
