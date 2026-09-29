#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  ReconX v5 — Installer
#  Uso: chmod +x install.sh && sudo ./install.sh
#  Flags:
#    --purge-results   também apaga resultados/screenshots antigos
#    --no-tools        não instala/atualiza ferramentas (só app + template)
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${CYAN}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

PURGE_RESULTS=0
INSTALL_TOOLS=1
for arg in "$@"; do
    case "$arg" in
        --purge-results) PURGE_RESULTS=1 ;;
        --no-tools)      INSTALL_TOOLS=0 ;;
        *) warn "Argumento desconhecido: $arg" ;;
    esac
done

echo -e "${BOLD}${GREEN}"
cat << 'BANNER'
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗  ██╗   ██╗██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝  ██║   ██║╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝   ██║   ██║ ╚███╔╝
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗   ╚██╗ ██╔╝ ██╔██╗
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗   ╚████╔╝ ██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═══╝  ╚═╝  ╚═╝
         v5 — Proxy Layer + Maximum Coverage + Robustez
BANNER
echo -e "${NC}"

# ── Verifica root ──────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { err "Execute como root: sudo ./install.sh"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="/opt/reconx"
APP_DIR="$ROOT_DIR/app"
RESULTS_DIR="$ROOT_DIR/results"
PORT=5000

# ═══════════════════════════════════════════════════════════════════
#  LIMPEZA DA INSTALAÇÃO ANTERIOR
# ═══════════════════════════════════════════════════════════════════
info "Procurando instalação anterior do ReconX..."

# 1) Para o serviço systemd, caso exista
if systemctl list-unit-files 2>/dev/null | grep -q '^reconx\.service'; then
    warn "Serviço systemd 'reconx' encontrado — parando e desabilitando..."
    systemctl stop reconx.service 2>/dev/null || true
    systemctl disable reconx.service 2>/dev/null || true
    rm -f /etc/systemd/system/reconx.service
    systemctl daemon-reload 2>/dev/null || true
    ok "Serviço systemd removido"
fi

# 2) Libera a porta (mata quem estiver escutando na 5000 — preciso)
if ss -tlnp 2>/dev/null | grep -q ":$PORT "; then
    warn "Porta $PORT em uso — finalizando processo que a ocupa..."
    if command -v fuser &>/dev/null; then
        fuser -k "${PORT}/tcp" 2>/dev/null || true
    else
        # fallback: extrai PID do ss e mata
        ss -tlnp 2>/dev/null | grep ":$PORT " \
            | grep -oP 'pid=\K[0-9]+' | sort -u \
            | while read -r p; do kill "$p" 2>/dev/null || true; done
    fi
    sleep 1
    ok "Porta $PORT liberada"
fi

# 3) Mata processos remanescentes do app (best-effort)
if pgrep -f "$APP_DIR/app.py" &>/dev/null; then
    pkill -f "$APP_DIR/app.py" 2>/dev/null || true
fi
# o launcher roda 'python3 app.py' com cwd em $APP_DIR
pkill -f "python3 app.py" 2>/dev/null || true
sleep 1

# 4) Remove app antigo e launcher global (PRESERVANDO resultados)
if [[ -d "$APP_DIR" ]]; then
    info "Removendo app anterior em $APP_DIR..."
    rm -rf "$APP_DIR"
    ok "App anterior removido"
fi
rm -f /usr/local/bin/reconx

# 5) Resultados: preserva por padrão; só apaga com --purge-results
if [[ $PURGE_RESULTS -eq 1 ]]; then
    warn "--purge-results: apagando resultados e screenshots antigos..."
    rm -rf "$RESULTS_DIR"
    ok "Resultados antigos apagados"
elif [[ -d "$RESULTS_DIR" ]]; then
    COUNT=$(find "$RESULTS_DIR" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
    ok "Resultados anteriores preservados ($COUNT scans em $RESULTS_DIR)"
fi

ok "Limpeza concluída — pronto para instalar a versão nova"
echo ""

# ═══════════════════════════════════════════════════════════════════
#  INSTALAÇÃO
# ═══════════════════════════════════════════════════════════════════

# ── Cria estrutura ─────────────────────────────────────────────────
info "Criando estrutura de diretórios..."
mkdir -p "$APP_DIR/templates" "$RESULTS_DIR/sqlmap" "$RESULTS_DIR/screenshots"
ok "Diretórios em $APP_DIR"

# ── Copia arquivos ─────────────────────────────────────────────────
info "Copiando app.py e templates..."
cp "$SCRIPT_DIR/app.py"                   "$APP_DIR/app.py"
cp "$SCRIPT_DIR/templates/index.html"     "$APP_DIR/templates/index.html"
if [[ -f "$SCRIPT_DIR/update.sh" ]]; then
    cp "$SCRIPT_DIR/update.sh" "$APP_DIR/update.sh"
    chmod +x "$APP_DIR/update.sh"
fi
if git -C "$SCRIPT_DIR" rev-parse HEAD > "$APP_DIR/.reconx-version" 2>/dev/null; then
    ok "Versão instalada registrada"
else
    rm -f "$APP_DIR/.reconx-version"
fi
ok "Arquivos copiados"

# ── Dependências Python ────────────────────────────────────────────
info "Instalando dependências Python (flask, flask-socketio)..."
# async_mode='threading' — eventlet não é necessário na v5
pip3 install flask flask-socketio --break-system-packages -q
ok "Python deps OK"

# ── Valida JSON do template (não-fatal) ────────────────────────────
info "Validando template..."
VALIDATOR="$(mktemp /tmp/reconx_validate.XXXXXX.py)"
cat > "$VALIDATOR" << 'PYEOF'
import os, sys, re, json
sys.path.insert(0, os.getcwd())  # acha o app.py no diretório onde rodamos (APP_DIR)
try:
    from app import app
    with app.test_client() as c:
        html = c.get('/').data.decode()
except Exception as e:
    import traceback
    print("ERRO ao importar/renderizar app:", e)
    traceback.print_exc()
    raise SystemExit(2)

ok = True
for tag in ['_tools', '_pipes', '_proxies', '_checklist']:
    m = re.search(r'id="%s">(.*?)</script>' % re.escape(tag), html, re.DOTALL)
    if not m:
        print("AUSENTE: bloco <script id=%s> não encontrado no template" % tag)
        ok = False
        continue
    try:
        json.loads(m.group(1))
    except Exception as e:
        print("JSON inválido em %s: %s" % (tag, e))
        ok = False
print("OK" if ok else "INVALIDO")
PYEOF

# Importante: não deixar o set -e abortar o script se a validação falhar.
set +e
VALID="$(cd "$APP_DIR" && python3 "$VALIDATOR" 2>&1)"
VRC=$?
set -e
rm -f "$VALIDATOR"

if [[ $VRC -eq 0 && "$VALID" == *OK* ]]; then
    ok "Template JSON válido — pipelines e ferramentas vão carregar"
else
    warn "Validação do template NÃO passou — a instalação vai continuar mesmo assim."
    warn "Detalhe do erro (verifique templates/index.html):"
    echo "$VALID" | sed 's/^/      /'
    warn "Se as ferramentas não carregarem na UI, comece investigando por aqui."
fi

if [[ $INSTALL_TOOLS -eq 0 ]]; then
    warn "--no-tools: pulando instalação de ferramentas"
else

# ── Ferramentas apt ────────────────────────────────────────────────
info "Verificando ferramentas apt essenciais..."
# v5: + testssl.sh, whatweb, wafw00f, commix, feroxbuster, gowitness (apt no Kali)
APT_TOOLS=(nmap curl wget whois dnsutils nikto sqlmap gobuster \
           testssl.sh whatweb wafw00f commix feroxbuster gowitness)
MISSING_APT=()
for t in "${APT_TOOLS[@]}"; do
    # testssl.sh instala o binário 'testssl.sh'
    command -v "$t" &>/dev/null || MISSING_APT+=("$t")
done
if [[ ${#MISSING_APT[@]} -gt 0 ]]; then
    warn "Instalando: ${MISSING_APT[*]}"
    apt-get update -qq 2>/dev/null || true
    apt-get install -y -qq "${MISSING_APT[@]}" 2>/dev/null && ok "apt tools instaladas" \
        || warn "Alguns pacotes apt podem não existir nesta distro — verifique manualmente"
else
    ok "Todas as ferramentas apt presentes"
fi

# ── Arjun (pip) ────────────────────────────────────────────────────
info "Verificando Arjun (descoberta de parâmetros)..."
if ! command -v arjun &>/dev/null; then
    warn "Arjun ausente — instalando via pip..."
    pip3 install arjun --break-system-packages -q && ok "Arjun OK" || warn "Arjun falhou"
else
    ok "Arjun presente"
fi

# ── Ferramentas do módulo de Verificação/Exploração ──────────────
info "Verificando ferramentas do módulo de Verificação (redis-cli, mongosh, jwt_tool, corsy)..."

# redis-cli — verifica Redis exposto sem auth
if ! command -v redis-cli &>/dev/null; then
    warn "redis-cli ausente — instalando via apt (redis-tools)..."
    apt-get install -y -qq redis-tools 2>/dev/null         && ok "redis-cli OK"         || warn "redis-cli falhou — instale manualmente: apt install redis-tools"
else
    ok "redis-cli presente"
fi

# mongosh — MongoDB Shell (verifica MongoDB exposto)
if ! command -v mongosh &>/dev/null; then
    warn "mongosh ausente — tentando via npm..."
    if command -v npm &>/dev/null; then
        npm install -g mongosh --silent 2>/dev/null             && ok "mongosh OK (npm)"             || warn "mongosh via npm falhou — instale manualmente: https://www.mongodb.com/try/download/shell"
    else
        warn "npm não encontrado — instale Node.js + npm e rode: npm install -g mongosh"
        warn "Ou baixe diretamente: https://www.mongodb.com/try/download/shell"
    fi
else
    ok "mongosh presente"
fi

# jwt_tool — testa fraquezas em tokens JWT
if ! command -v jwt_tool &>/dev/null; then
    warn "jwt_tool ausente — clonando do GitHub..."
    rm -rf /opt/jwt_tool
    if git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null; then
        pip3 install termcolor cprint pycryptodome --break-system-packages -q 2>/dev/null || true
        chmod +x /opt/jwt_tool/jwt_tool.py
        ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool
        ok "jwt_tool OK"
    else
        warn "jwt_tool falhou — instale manualmente: https://github.com/ticarpi/jwt_tool"
    fi
else
    ok "jwt_tool presente"
fi

# corsy — scanner de misconfigurações CORS
if ! command -v corsy &>/dev/null; then
    warn "corsy ausente — clonando do GitHub..."
    rm -rf /opt/corsy
    if git clone --depth=1 https://github.com/s0md3v/Corsy /opt/corsy 2>/dev/null; then
        pip3 install requests --break-system-packages -q 2>/dev/null || true
        chmod +x /opt/corsy/corsy.py
        ln -sf /opt/corsy/corsy.py /usr/local/bin/corsy
        ok "corsy OK"
    else
        warn "corsy falhou — instale manualmente: https://github.com/s0md3v/Corsy"
    fi
else
    ok "corsy presente"
fi

# ── Ferramentas Go ─────────────────────────────────────────────────
info "Verificando ferramentas Go..."
export PATH=$PATH:/root/go/bin:/usr/local/go/bin
export GOPATH=/root/go

# v5: + gowitness (caso não tenha vindo via apt)
GO_TOOLS=(
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
    "ffuf:github.com/ffuf/ffuf/v2@latest"
    "assetfinder:github.com/tomnomnom/assetfinder@latest"
    "waybackurls:github.com/tomnomnom/waybackurls@latest"
    "gau:github.com/lc/gau/v2/cmd/gau@latest"
    "dalfox:github.com/hahwul/dalfox/v2@latest"
    "anew:github.com/tomnomnom/anew@latest"
    "gowitness:github.com/sensepost/gowitness@latest"
)

MISSING_GO=()
for entry in "${GO_TOOLS[@]}"; do
    bin="${entry%%:*}"
    command -v "$bin" &>/dev/null || MISSING_GO+=("$entry")
done

if [[ ${#MISSING_GO[@]} -gt 0 ]]; then
    if command -v go &>/dev/null; then
        warn "${#MISSING_GO[@]} ferramentas Go ausentes — instalando..."
        for entry in "${MISSING_GO[@]}"; do
            bin="${entry%%:*}"
            pkg="${entry##*:}"
            info "  go install $bin..."
            go install "$pkg" 2>/dev/null && ok "  $bin OK" || warn "  $bin falhou"
        done
    else
        warn "Go não encontrado — ferramentas Go não serão instaladas"
        warn "Instale Go: https://go.dev/dl/ e rode o install.sh novamente"
    fi
else
    ok "Todas as ferramentas Go presentes"
fi

# Atualiza templates do nuclei (necessário p/ nuclei_cves/misconfig/takeover/dast)
if command -v nuclei &>/dev/null; then
    info "Atualizando templates do Nuclei..."
    nuclei -update-templates -silent 2>/dev/null && ok "Templates do Nuclei atualizados" \
        || warn "Falha ao atualizar templates do Nuclei (rode 'nuclei -update-templates' depois)"
fi

# ── Tor + Privoxy (para proxy Tor) ────────────────────────────────
info "Verificando Tor + Privoxy..."
if ! command -v tor &>/dev/null; then
    warn "Tor não encontrado — instalando..."
    apt-get install -y -qq tor privoxy 2>/dev/null && ok "Tor + Privoxy instalados" || warn "Falha ao instalar Tor"
else
    ok "Tor presente"
fi

# Configura privoxy para usar tor se instalado
if command -v privoxy &>/dev/null; then
    PRIVOXY_CONF="/etc/privoxy/config"
    if [[ -f "$PRIVOXY_CONF" ]] && ! grep -q "forward-socks5" "$PRIVOXY_CONF"; then
        echo "forward-socks5 / 127.0.0.1:9050 ." >> "$PRIVOXY_CONF"
        ok "Privoxy configurado para Tor (socks5://127.0.0.1:9050 → http://127.0.0.1:8118)"
    fi
fi

# ── Wordlists ──────────────────────────────────────────────────────
info "Verificando wordlists..."
WL_FOUND=0
for wl in \
    "/opt/wordlists/SecLists/Discovery/Web-Content/common.txt" \
    "/usr/share/seclists/Discovery/Web-Content/common.txt" \
    "/usr/share/wordlists/dirb/common.txt"; do
    if [[ -f "$wl" ]]; then
        ok "Wordlist encontrada: $wl"
        WL_FOUND=1
        break
    fi
done

if [[ $WL_FOUND -eq 0 ]]; then
    warn "Nenhuma wordlist encontrada"
    warn "Instale com: sudo apt install seclists"
    warn "Ou: git clone https://github.com/danielmiessler/SecLists /opt/wordlists/SecLists"
fi

fi  # fim do bloco INSTALL_TOOLS

# ── Script global reconx ───────────────────────────────────────────
info "Criando comando global 'reconx'..."
cat > /usr/local/bin/reconx << 'RCEOF'
#!/usr/bin/env bash
export PATH=$PATH:/root/go/bin:/usr/local/go/bin
export GOPATH=/root/go

# Verifica se porta já está em uso e para o processo anterior
if ss -tlnp 2>/dev/null | grep -q ':5000 '; then
    echo -e "\033[0;33m[!] Porta 5000 já em uso — parando processo anterior...\033[0m"
    if command -v fuser &>/dev/null; then
        fuser -k 5000/tcp 2>/dev/null || true
    else
        pkill -f "python3 app.py" 2>/dev/null || true
    fi
    sleep 1
fi

echo ""
echo -e "  \033[0;32mReconX v5\033[0m — Proxy Layer + Maximum Coverage + Robustez"
echo -e "  Bind padrão: \033[0;36m127.0.0.1:5000\033[0m  (use 'reconx --expose' p/ rede)"
echo ""
cd /opt/reconx/app
# repassa quaisquer flags (--host/--port/--expose/--debug) ao app
python3 app.py "$@"
RCEOF
chmod +x /usr/local/bin/reconx

# Alias no zshrc
if [[ -f /root/.zshrc ]] && ! grep -q 'alias reconx=' /root/.zshrc; then
    echo "alias reconx='sudo /usr/local/bin/reconx'" >> /root/.zshrc
fi
# Alias no bashrc também
if [[ -f /root/.bashrc ]] && ! grep -q 'alias reconx=' /root/.bashrc; then
    echo "alias reconx='sudo /usr/local/bin/reconx'" >> /root/.bashrc
fi

ok "Comando 'reconx' disponível globalmente"

# ── Resumo final ───────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ReconX v5 instalado com sucesso!${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════${NC}"
echo ""
echo -e "  Iniciar:   ${YELLOW}reconx${NC}  ou  ${YELLOW}sudo python3 $APP_DIR/app.py${NC}"
echo -e "  Expor LAN: ${YELLOW}reconx --expose${NC}  (bind 0.0.0.0 — use com cautela)"
echo -e "  Interface: ${CYAN}http://localhost:5000${NC}"
echo -e "  Atualizar: ${YELLOW}sudo bash $APP_DIR/update.sh${NC}"
echo -e "  Relatório: ${CYAN}http://localhost:5000/api/report/<scan_id>${NC} (Markdown)"
echo ""
echo -e "  ${CYAN}Novidades v5:${NC} timeout por tool, bind seguro (127.0.0.1),"
echo -e "    novas tools (gowitness, arjun, testssl, nmap_vuln, gobuster_vhost,"
echo -e "    nuclei_takeover/dast) e export de relatório Markdown."
echo ""
echo -e "  ${CYAN}Proxies suportados:${NC}"
echo -e "    🔴 Burp Suite  → 127.0.0.1:8080"
echo -e "    🔵 OWASP ZAP   → 127.0.0.1:8090"
echo -e "    🧅 Tor         → inicie com: ${YELLOW}sudo service tor start${NC}"
echo -e "    ⚙  Customizado → configure na interface"
echo ""
echo -e "  ${CYAN}Para usar com Burp:${NC}"
echo -e "    1. Abra o Burp Suite"
echo -e "    2. Proxy → Options → porta 8080"
echo -e "    3. Na interface ReconX: clique em 'Sem proxy' → Burp Suite"
echo -e "    4. Para HTTPS: instale o cert em ${YELLOW}http://burp/cert${NC}"
echo ""
# Checklist de binários críticos
echo -e "  ${CYAN}Verificando binários disponíveis:${NC}"
ALL_BINS=(nmap curl nikto sqlmap nuclei httpx subfinder ffuf dalfox commix corsy jwt_tool redis-cli mongosh)
MISSING_BINS=()
for b in "${ALL_BINS[@]}"; do
    if command -v "$b" &>/dev/null; then
        echo -e "    ${GREEN}✓${NC} $b"
    else
        echo -e "    ${RED}✗${NC} $b  (ausente)"
        MISSING_BINS+=("$b")
    fi
done
if [[ ${#MISSING_BINS[@]} -gt 0 ]]; then
    echo ""
    warn "Binários ausentes: ${MISSING_BINS[*]}"
    warn "O módulo de Verificação avisará 'tool não instalada' ao tentar usá-los."
fi
echo ""

echo -e "  ${YELLOW}Nota:${NC} resultados anteriores são preservados por padrão."
echo -e "        Use ${YELLOW}sudo ./install.sh --purge-results${NC} para apagá-los."
echo ""
