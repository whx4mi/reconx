#!/usr/bin/env bash
# Integration tests against a disposable local Git repository. No network,
# system services or real /opt installation are touched.
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT
export RECONX_ROOT="$TEST_DIR/install"
export RECONX_REPO_URL="$TEST_DIR/remote"
export TEST_PYTHON_BIN="${TEST_PYTHON_BIN:-$(command -v python3)}"
export TEST_SERVICE_STATE="$TEST_DIR/service-state"
export TEST_SERVICE_LOG="$TEST_DIR/service-log"
export TEST_FAIL_START=0 TEST_FAIL_DEPS=0
[[ -n "$TEST_PYTHON_BIN" ]] || { echo 'Python necessário para os testes'; exit 1; }
mkdir -p "$RECONX_ROOT/app/templates" "$RECONX_ROOT/results" "$RECONX_REPO_URL/templates"
printf 'old\n' > "$RECONX_ROOT/app/app.py"
printf 'old template\n' > "$RECONX_ROOT/app/templates/index.html"
printf 'scan preserved\n' > "$RECONX_ROOT/results/sentinel.txt"
printf "print('new version')\n" > "$RECONX_REPO_URL/app.py"
printf 'new template\n' > "$RECONX_REPO_URL/templates/index.html"
cp "$PROJECT_DIR/update.sh" "$RECONX_REPO_URL/update.sh"
git -C "$RECONX_REPO_URL" init -q -b main
git -C "$RECONX_REPO_URL" add .
git -C "$RECONX_REPO_URL" -c user.name=UpdaterTest -c user.email=test@example.invalid commit -qm initial
REVISION="$(git -C "$RECONX_REPO_URL" rev-parse HEAD)"

# Only permission enforcement is omitted in the disposable copy so these
# transaction tests can run as an unprivileged user. Production keeps it.
sed '/\[\[ $EUID -eq 0 \]\] || die/d' "$PROJECT_DIR/update.sh" > "$TEST_DIR/update-test.sh"
python3() {
    if [[ "${1:-}" == '-c' && "${2:-}" == 'import flask, flask_socketio' ]]; then
        [[ "$TEST_FAIL_DEPS" == 0 ]]
    else
        "$TEST_PYTHON_BIN" "$@"
    fi
}
flock() { return 0; } # Lock mechanics belong to flock; do not lock the host.
systemctl() {
    printf '%s\n' "$*" >> "$TEST_SERVICE_LOG"
    case "$1" in
        is-active) [[ -f "$TEST_SERVICE_STATE" ]] ;;
        stop) rm -f "$TEST_SERVICE_STATE" ;;
        start)
            if [[ "$TEST_FAIL_START" == 1 ]] && grep -q 'new version two' "$RECONX_ROOT/app/app.py"; then
                return 1
            fi
            touch "$TEST_SERVICE_STATE" ;;
        *) return 1 ;;
    esac
}
export -f python3 flock systemctl
run_update() { bash "$TEST_DIR/update-test.sh" "$@" > "$TEST_DIR/output" 2>&1; }
assert_results() { grep -qx 'scan preserved' "$RECONX_ROOT/results/sentinel.txt"; }

run_update --check
grep -q 'Atualização disponível' "$TEST_DIR/output"
grep -qx old "$RECONX_ROOT/app/app.py"
[[ ! -d "$RECONX_ROOT/backups" ]]
echo 'PASS: check leaves installation unchanged'

TEST_FAIL_DEPS=1
if run_update; then echo 'FAIL: missing dependencies accepted'; exit 1; fi
grep -qx old "$RECONX_ROOT/app/app.py"
assert_results
TEST_FAIL_DEPS=0
echo 'PASS: validation failure leaves old app intact'

run_update
grep -q 'new version' "$RECONX_ROOT/app/app.py"
grep -qx "$REVISION" "$RECONX_ROOT/app/.reconx-version"
grep -qx old "$RECONX_ROOT"/backups/*/app/app.py
assert_results
echo 'PASS: new revision installed with backup and preserved results'

run_update
grep -q 'já está atualizado' "$TEST_DIR/output"
[[ "$(find "$RECONX_ROOT/backups" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 1 ]]
echo 'PASS: unchanged revision does not redeploy'

printf "print('new version two')\n" > "$RECONX_REPO_URL/app.py"
git -C "$RECONX_REPO_URL" add app.py
git -C "$RECONX_REPO_URL" -c user.name=UpdaterTest -c user.email=test@example.invalid commit -qm second
touch "$TEST_SERVICE_STATE"
TEST_FAIL_START=1
if run_update; then echo 'FAIL: failed service startup accepted'; exit 1; fi
grep -qx "$REVISION" "$RECONX_ROOT/app/.reconx-version"
[[ -f "$TEST_SERVICE_STATE" ]]
assert_results
TEST_FAIL_START=0
echo 'PASS: failed service startup rolls back app and restarts old service'

run_update
grep -q 'new version two' "$RECONX_ROOT/app/app.py"
[[ -f "$TEST_SERVICE_STATE" ]]
assert_results
echo 'PASS: active service restarts on successful update'

run_update --force
grep -q 'Atualização aplicada' "$TEST_DIR/output"
assert_results
echo 'PASS: force reapplies current version'
