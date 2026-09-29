"""Inventário persistente por host; execução não implica validação de cobertura."""
import ipaddress
import json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit


CHECKS = {
    'inventory': 'Inventário de hosts, serviços e tecnologias',
    'web': 'Superfície web e rotas',
    'api': 'APIs e documentação/versões',
    'cloud': 'Ativos e configuração cloud',
    'authn': 'Autenticação e sessões',
    'authz': 'Autorização e isolamento entre usuários',
    'inputs': 'Parâmetros, formulários e entradas',
    'business': 'Lógica de negócio',
    'client': 'Frontend e JavaScript',
    'source': 'Código-fonte e configuração (WhiteBox)',
    'validation': 'Reprodução e evidências dos achados',
    'post_access': 'Pós-acesso autorizado e limites de impacto',
}
STATUSES = {'pending', 'in_progress', 'tested', 'inconclusive', 'not_applicable'}
SCHEMA = """
CREATE TABLE IF NOT EXISTS host_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS host_scans (
    host_id INTEGER NOT NULL, scan_id TEXT NOT NULL,
    PRIMARY KEY (host_id, scan_id),
    FOREIGN KEY(host_id) REFERENCES host_profiles(id)
);
CREATE TABLE IF NOT EXISTS host_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER NOT NULL,
    scan_id TEXT NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL,
    status TEXT NOT NULL, exit_code INTEGER, output_path TEXT,
    created_at TEXT NOT NULL, FOREIGN KEY(host_id) REFERENCES host_profiles(id)
);
CREATE INDEX IF NOT EXISTS idx_host_runs_host ON host_runs(host_id, created_at);
CREATE TABLE IF NOT EXISTS host_assets (
    host_id INTEGER NOT NULL, atype TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY(host_id,atype,value),
    FOREIGN KEY(host_id) REFERENCES host_profiles(id)
);
CREATE TABLE IF NOT EXISTS host_services (
    host_id INTEGER NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL,
    service TEXT NOT NULL, scan_id TEXT NOT NULL,
    PRIMARY KEY(host_id,port,protocol,scan_id),
    FOREIGN KEY(host_id) REFERENCES host_profiles(id)
);
CREATE TABLE IF NOT EXISTS host_checks (
    host_id INTEGER NOT NULL, check_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT '', updated_at TEXT,
    PRIMARY KEY(host_id, check_key),
    FOREIGN KEY(host_id) REFERENCES host_profiles(id)
);
"""


def canonical_host(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError('Host inválido')
    value = value.strip()
    if re.search(r'[\s\\\x00-\x1f]', value):
        raise ValueError('Host inválido')
    parsed = urlsplit(value if '://' in value else '//' + value)
    if parsed.username or parsed.password or parsed.scheme not in ('', 'http', 'https'):
        raise ValueError('Use hostname, IP ou URL HTTP(S) sem credenciais')
    try:
        host = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError('Host ou porta inválida') from exc
    if not host:
        raise ValueError('Host inválido')
    host = host.rstrip('.').lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    if len(host) > 253 or not all(
        0 < len(label) <= 63 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
        for label in host.split('.')
    ):
        raise ValueError('Hostname inválido')
    return host


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()

    @contextmanager
    def _db(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        try:
            with con:
                yield con
        finally:
            con.close()

    def init(self):
        with self.lock, self._db() as con:
            con.executescript(SCHEMA)
            # Migração aditiva: scans antigos permanecem intactos.
            if con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'").fetchone():
                for row in con.execute('SELECT scan_id, target FROM scans'):
                    try:
                        self._ensure(con, row['target'], row['scan_id'])
                    except ValueError:
                        continue

    def _ensure(self, con, target, scan_id=None):
        host = canonical_host(target)
        now = datetime.now(timezone.utc).isoformat()
        con.execute('INSERT OR IGNORE INTO host_profiles(host,created_at,updated_at) VALUES(?,?,?)', (host, now, now))
        host_id = con.execute('SELECT id FROM host_profiles WHERE host=?', (host,)).fetchone()['id']
        con.executemany('INSERT OR IGNORE INTO host_checks(host_id,check_key) VALUES(?,?)',
                        [(host_id, key) for key in CHECKS])
        if scan_id:
            con.execute('INSERT OR IGNORE INTO host_scans(host_id,scan_id) VALUES(?,?)', (host_id, scan_id))
        return host_id

    def ensure(self, target, scan_id=None):
        with self.lock, self._db() as con:
            return self._ensure(con, target, scan_id)

    def record_run(self, scan_id, tool, target, status, exit_code=None, output_path=None):
        with self.lock, self._db() as con:
            host_id = self._ensure(con, target, scan_id)
            con.execute('''INSERT INTO host_runs
                (host_id,scan_id,tool,target,status,exit_code,output_path,created_at)
                VALUES(?,?,?,?,?,?,?,?)''',
                (host_id, scan_id, tool, target, status, exit_code, output_path,
                 datetime.now(timezone.utc).isoformat()))
            con.execute('UPDATE host_profiles SET updated_at=? WHERE id=?',
                        (datetime.now(timezone.utc).isoformat(), host_id))

    def record_assets(self, scan_id, source_target, assets):
        with self.lock, self._db() as con:
            source_id = self._ensure(con, source_target, scan_id)
            for asset in assets:
                kind, value = asset.get('type'), asset.get('value')
                if not isinstance(value, str) or not value or len(value) > 2048:
                    continue
                try:
                    host_id = source_id if kind == 'path' else self._ensure(con, value)
                except ValueError:
                    continue
                con.execute('INSERT OR IGNORE INTO host_assets(host_id,atype,value) VALUES(?,?,?)',
                            (host_id, kind, value))

    def record_services(self, scan_id, source_target, tool, raw):
        if tool not in ('nmap_quick', 'nmap_full', 'naabu', 'httpx'):
            return
        with self.lock, self._db() as con:
            host_id = self._ensure(con, source_target, scan_id)
            for line in raw.splitlines():
                port = protocol = service = None
                if tool == 'httpx':
                    try:
                        item = json.loads(line)
                        url = urlsplit(item.get('url', ''))
                        if url.scheme not in ('http', 'https') or not url.hostname:
                            continue
                        host_id = self._ensure(con, item['url'], scan_id)
                        port, protocol, service = url.port or (443 if url.scheme == 'https' else 80), 'tcp', url.scheme
                    except (ValueError, TypeError, KeyError, AttributeError):
                        continue
                elif tool == 'naabu':
                    try:
                        item = json.loads(line)
                        port, protocol = item.get('port'), item.get('protocol', 'tcp')
                        service = ''
                    except (ValueError, TypeError, AttributeError):
                        continue
                else:
                    match = re.match(r'^\s*(\d+)/(tcp|udp)\s+open\s+([^\s]+)', line, re.I)
                    if match:
                        port, protocol, service = match.groups()
                try:
                    port = int(port)
                except (TypeError, ValueError):
                    continue
                if not 1 <= port <= 65535 or protocol not in ('tcp', 'udp'):
                    continue
                con.execute('''INSERT OR REPLACE INTO host_services
                    (host_id,port,protocol,service,scan_id) VALUES(?,?,?,?,?)''',
                    (host_id, port, protocol, str(service or '')[:80], scan_id))

    def list_hosts(self, scanned_only=False):
        with self.lock, self._db() as con:
            return [dict(row) for row in con.execute('''SELECT h.id,h.host,h.created_at,h.updated_at,
                (SELECT COUNT(*) FROM host_scans s WHERE s.host_id=h.id) scan_count,
                (SELECT COUNT(*) FROM host_runs r WHERE r.host_id=h.id) run_count
                FROM host_profiles h
                WHERE (?=0 OR EXISTS (SELECT 1 FROM host_scans s WHERE s.host_id=h.id))
                ORDER BY h.updated_at DESC''', (int(scanned_only),))]

    def get_run(self, host_id, run_id):
        with self.lock, self._db() as con:
            row = con.execute('SELECT * FROM host_runs WHERE host_id=? AND id=?',
                              (host_id, run_id)).fetchone()
            return dict(row) if row else None

    def get(self, host_id):
        with self.lock, self._db() as con:
            host = con.execute('SELECT * FROM host_profiles WHERE id=?', (host_id,)).fetchone()
            if not host:
                return None
            scans = [dict(row) for row in con.execute('''SELECT s.* FROM scans s
                JOIN host_scans hs ON hs.scan_id=s.scan_id WHERE hs.host_id=?
                ORDER BY s.started_at DESC LIMIT 100''', (host_id,))]
            runs = [dict(row) for row in con.execute('''SELECT * FROM host_runs WHERE host_id=?
                ORDER BY id DESC LIMIT 200''', (host_id,))]
            checks = [dict(row) for row in con.execute('''SELECT * FROM host_checks
                WHERE host_id=? ORDER BY check_key''', (host_id,))]
            for check in checks:
                check['label'] = CHECKS.get(check['check_key'], check['check_key'])
            assets = [dict(row) for row in con.execute('''SELECT atype,value FROM host_assets
                WHERE host_id=? ORDER BY atype,value LIMIT 200''', (host_id,))]
            services = [dict(row) for row in con.execute('''SELECT port,protocol,service,scan_id
                FROM host_services WHERE host_id=? ORDER BY port LIMIT 200''', (host_id,))]
            # Só atribui findings com um host explícito; scans podem pivotar para outros alvos.
            findings = []
            if con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='findings'").fetchone():
                for row in con.execute('''SELECT f.id,f.scan_id,f.tool,f.ftype,f.name,f.severity,
                    f.target,f.evidence,f.confidence,f.created_at FROM findings f
                    JOIN host_scans hs ON hs.scan_id=f.scan_id WHERE hs.host_id=?
                    ORDER BY f.id DESC LIMIT 500''', (host_id,)):
                    try:
                        if canonical_host(row['target']) == host['host']:
                            findings.append(dict(row))
                    except ValueError:
                        continue
                    if len(findings) >= 200:
                        break
            complete = {r['tool'] for r in runs if r['status'] == 'completed'}
            web = any(a['atype'] in ('url', 'path') for a in assets) or any(
                s['port'] in (80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 3000, 5000)
                or re.search(r'http|https|ssl', s['service'], re.I) for s in services)
            api = any(re.search(r'/(?:api|graphql|swagger|openapi)(?:/|\b)', a['value'], re.I)
                      for a in assets) or any(re.search(r'/(?:api|graphql|swagger|openapi)(?:/|\b)', r['target'], re.I)
                                             for r in runs)
            recon = bool(complete & {'nmap_quick', 'naabu', 'httpx', 'whatweb', 'curl_headers',
                                     'subfinder', 'assetfinder', 'dnsrecon', 'ai_headers', 'ai_ports'})
            phase = ('revisao_manual' if any(c['status'] in ('in_progress', 'tested', 'inconclusive') for c in checks)
                     else 'recon_segmentado' if recon else 'recon_inicial')
            suggestions = [
                {'key': 'host_recon', 'ready': True, 'reason': 'Inventário inicial independente'},
                {'key': 'web_recon', 'ready': recon and web,
                 'reason': 'Recon inicial e superfície HTTP observada' if recon and web else 'Aguardando recon inicial e evidência HTTP'},
                {'key': 'api_recon', 'ready': recon and api,
                 'reason': 'Rota/API observada no inventário' if recon and api else 'Aguardando rota/API observada'},
            ]
            recommendations = []
            if not recon:
                recommendations.append({'title': 'Executar recon inicial',
                    'reason': 'Ainda não há execução de reconhecimento concluída para este host.',
                    'pipeline': 'host_recon'})
            if recon and web:
                recommendations.append({'title': 'Mapear a superfície web',
                    'reason': 'Serviço ou rota HTTP observada; revise porta e URL antes de executar.',
                    'pipeline': 'web_recon'})
            if recon and api:
                recommendations.append({'title': 'Inventariar endpoints de API',
                    'reason': 'Há indício de rota ou documentação de API neste host.',
                    'pipeline': 'api_recon'})
            if any(f['severity'] in ('critical', 'high') for f in findings):
                recommendations.append({'title': 'Validar achados prioritários',
                    'reason': 'Achados críticos/altos exigem reprodução e revisão de falso positivo.',
                    'pipeline': None})
            if any(c['status'] in ('pending', 'inconclusive') for c in checks):
                recommendations.append({'title': 'Revisar checklist manual',
                    'reason': 'Há itens pendentes ou inconclusivos; registre evidência por host.',
                    'pipeline': None})
            return {**dict(host), 'scans': scans, 'runs': runs, 'checks': checks,
                    'assets': assets, 'services': services, 'findings': findings,
                    'suggestions': suggestions, 'recommendations': recommendations, 'phase': phase}

    def update_check(self, host_id, key, status, note, evidence):
        if key not in CHECKS or status not in STATUSES:
            raise ValueError('Item ou estado inválido')
        if not isinstance(note, str) or not isinstance(evidence, str) or len(note) > 2000 or len(evidence) > 2000:
            raise ValueError('Nota ou evidência inválida (máximo 2000 caracteres)')
        if status == 'tested' and not evidence.strip():
            raise ValueError('Informe evidência para marcar como testado')
        with self.lock, self._db() as con:
            row = con.execute('SELECT 1 FROM host_profiles WHERE id=?', (host_id,)).fetchone()
            if not row:
                return False
            con.execute('''UPDATE host_checks SET status=?,note=?,evidence=?,updated_at=?
                WHERE host_id=? AND check_key=?''',
                (status, note.strip(), evidence.strip(), datetime.now(timezone.utc).isoformat(), host_id, key))
            con.execute('UPDATE host_profiles SET updated_at=? WHERE id=?',
                        (datetime.now(timezone.utc).isoformat(), host_id))
            return True
