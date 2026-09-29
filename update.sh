#!/usr/bin/env bash
# Atualiza a instalação, preservando resultados e um backup do app anterior.
# Uso: sudo bash update.sh [--check] [--force] [--branch main]
set -Eeuo pipefail

REPO_URL="${RECONX_REPO_URL:-https://github.com/whx4mi/reconx.git}"
ROOT_DIR="${RECONX_ROOT:-/opt/reconx}"
BRANCH=main
CHECK_ONLY=0
FORCE=0
say() { printf '[*] %s\n' "$*"; }
die() { printf '[-] %s\n' "$*" >&2; exit 1; }
while (($#)); do
    case "$1" in
        --check) CHECK_ONLY=1; shift ;;
        --force) FORCE=1; shift ;;
        --branch) (($# >= 2)) || die '--branch requer um nome'; BRANCH="$2"; shift 2 ;;
        --help|-h)
            printf '%s\n' 'Uso: sudo bash update.sh [--check] [--force] [--branch main]' \
                '--check: consulta a versão sem alterar a instalação.' \
                '--force: reaplica a versão mesmo se o commit já estiver instalado.' \
                'Resultados são preservados; backups ficam em /opt/reconx/backups.'
            exit 0 ;;
        *) die "Argumento desconhecido: $1" ;;
    esac
done
for bin in git python3 mktemp flock realpath tar; do
    command -v "$bin" >/dev/null || die "Dependência ausente: $bin"
done
git check-ref-format --branch "$BRANCH" >/dev/null || die 'Branch inválida'
ROOT_DIR="$(realpath -m -- "$ROOT_DIR")"
case "$ROOT_DIR" in /|/opt|/usr|/usr/local|/home|/root|/tmp|/var) die 'Diretório de instalação amplo demais' ;; esac
APP_DIR="$ROOT_DIR/app"
[[ -f "$APP_DIR/app.py" && -f "$APP_DIR/templates/index.html" ]] || \
    die "ReconX não instalado em $APP_DIR. Rode install.sh primeiro."
[[ ! -L "$APP_DIR" ]] || die 'O diretório app não pode ser um link simbólico'
if (( ! CHECK_ONLY )); then
    [[ $EUID -eq 0 ]] || die 'Execute com sudo para aplicar a atualização'
    exec 9>"$ROOT_DIR/.update.lock"
    flock -n 9 || die 'Outra atualização já está em andamento'
fi

WORK_DIR="$(mktemp -d)"
STAGE_DIR=''
BACKUP_DIR=''
OLD_MOVED=0
NEW_MOVED=0
SERVICE_STOPPED=0
SUCCESS=0
cleanup() {
    local code=$?
    trap - EXIT
    if (( ! SUCCESS && OLD_MOVED )); then
        say 'Falha ao aplicar atualização; restaurando o backup.'
        if (( NEW_MOVED )); then
            mv -- "$APP_DIR" "$BACKUP_DIR/failed-app" || code=1
        fi
        mv -- "$BACKUP_DIR/app" "$APP_DIR" || code=1
    fi
    if (( SERVICE_STOPPED )); then
        systemctl start reconx.service || code=1
    fi
    # Apenas diretórios temporários criados por esta execução são removidos.
    [[ -z "$STAGE_DIR" ]] || rm -rf -- "$STAGE_DIR"
    rm -rf -- "$WORK_DIR"
    exit "$code"
}
trap cleanup EXIT

say "Consultando $REPO_URL (branch $BRANCH)..."
GIT_TERMINAL_PROMPT=0 git clone --quiet --depth 1 --single-branch --branch "$BRANCH" \
    -- "$REPO_URL" "$WORK_DIR/repo"
LATEST="$(git -C "$WORK_DIR/repo" rev-parse HEAD)"
CURRENT='desconhecida'
[[ ! -f "$APP_DIR/.reconx-version" ]] || read -r CURRENT < "$APP_DIR/.reconx-version"
say "Instalada: $CURRENT"
say "Disponível: $LATEST"
if [[ "$CURRENT" == "$LATEST" ]] && (( ! FORCE )); then
    say 'ReconX já está atualizado.'
    SUCCESS=1
    exit 0
fi
if (( CHECK_ONLY )); then
    say 'Atualização disponível (ou instalação sem registro de versão).'
    SUCCESS=1
    exit 0
fi

[[ -f "$WORK_DIR/repo/app.py" && -f "$WORK_DIR/repo/templates/index.html" \
    && -f "$WORK_DIR/repo/update.sh" ]] || die 'Repositório sem arquivos obrigatórios'
say 'Validando Python, updater e testes antes de substituir o app...'
python3 - "$WORK_DIR/repo/app.py" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
compile(path.read_text(encoding='utf-8'), str(path), 'exec')
PY
bash -n "$WORK_DIR/repo/update.sh"
python3 -c 'import flask, flask_socketio' || die 'Instale as dependências Python usando install.sh'
if [[ -d "$WORK_DIR/repo/tests" ]]; then
    python3 -B -m unittest discover -s "$WORK_DIR/repo/tests" -v
fi

# O instalador padrão usa primeiro plano. Não troca arquivos de um scan ativo.
SERVICE_ACTIVE=0
if command -v systemctl >/dev/null && systemctl is-active --quiet reconx.service; then
    SERVICE_ACTIVE=1
else
    python3 - "$APP_DIR" <<'PY'
import pathlib, sys
app = pathlib.Path(sys.argv[1]).resolve()
for process in pathlib.Path('/proc').glob('[0-9]*'):
    try:
        args = (process / 'cmdline').read_bytes().split(b'\0')
        cwd = (process / 'cwd').resolve()
        if any(a == b'app.py' and cwd == app or
               a == str(app / 'app.py').encode() for a in args):
            sys.exit('ReconX está em execução. Encerre-o (Ctrl+C) antes de atualizar.')
    except (OSError, RuntimeError):
        continue
PY
fi

# Staging e app ficam no mesmo filesystem para permitir renomeação.
STAGE_DIR="$(mktemp -d "$ROOT_DIR/.update.XXXXXX")"
mkdir "$STAGE_DIR/app"
git -C "$WORK_DIR/repo" archive HEAD | tar -x -C "$STAGE_DIR/app"
printf '%s\n' "$LATEST" > "$STAGE_DIR/app/.reconx-version"
chmod +x "$STAGE_DIR/app/update.sh"
mkdir -p "$ROOT_DIR/backups"
BACKUP_DIR="$(mktemp -d "$ROOT_DIR/backups/update-$(date +%Y%m%d-%H%M%S).XXXXXX")"
if (( SERVICE_ACTIVE )); then
    SERVICE_STOPPED=1
    systemctl stop reconx.service
fi
mv -- "$APP_DIR" "$BACKUP_DIR/app"
OLD_MOVED=1
mv -- "$STAGE_DIR/app" "$APP_DIR"
NEW_MOVED=1
if (( SERVICE_ACTIVE )); then
    systemctl start reconx.service
    systemctl is-active --quiet reconx.service || die 'Serviço não iniciou após atualizar'
    SERVICE_STOPPED=0
fi
SUCCESS=1
say "Atualização aplicada: $LATEST"
say "Backup: $BACKUP_DIR/app"
say "Resultados preservados em $ROOT_DIR/results"
(( SERVICE_ACTIVE )) || say 'Inicie novamente com: reconx'
exit 0
