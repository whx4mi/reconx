"""Bounded HTML discovery and explainable test planning (no AI dependency)."""
from collections import deque
from html.parser import HTMLParser
import hashlib
import json
import re
import subprocess
from urllib.parse import urljoin, urlsplit, urlunsplit, parse_qsl, urlencode

TOKEN = re.compile(r'csrf|xsrf|token|nonce', re.I)
MUTATION = re.compile(r'delete|remove|logout|signout|reset|destroy|purchase|checkout', re.I)
STATIC = re.compile(r'\.(?:png|jpg|jpeg|gif|svg|ico|css|js|pdf|zip|mp4|woff2?)(?:$)', re.I)


def scoped_url(base, value):
    """Allow only HTTP(S) URLs with the initial origin, including its port."""
    try:
        url = urlsplit(urljoin(base, value))
        origin = urlsplit(base)
        def key(p):
            return p.scheme.lower(), p.hostname, p.port or (443 if p.scheme == 'https' else 80)
        if url.scheme not in ('http', 'https') or url.username or url.password or key(url) != key(origin):
            return None
        return urlunsplit((url.scheme, url.netloc, url.path or '/', url.query, ''))
    except (ValueError, TypeError):
        return None


class PageParser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.links, self.forms = url, [], []
        self.script_sources = []
        self.current = None
        self.textarea = None
        self.select = None
        self.option = None
        self.public_text = ''
        self.scripts, self.current_script = [], None
        self.script_requests = []
        self.ignore_text = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script', 'style', 'textarea'):
            self.ignore_text += 1
        if tag == 'script':
            if a.get('src'):
                self.script_sources.append(urljoin(self.url, a['src']))
            else:
                self.current_script = ''
        if tag == 'a' and a.get('href'):
            self.links.append(urljoin(self.url, a['href']))
        if tag == 'form':
            self.current = {'page': self.url, 'action': urljoin(self.url, a.get('action') or self.url),
                            'method': a.get('method', 'GET').upper(),
                            'enctype': a.get('enctype', 'application/x-www-form-urlencoded').lower(),
                            'fields': [], 'login': False, 'upload': False}
            self.forms.append(self.current)
        if self.current is None or 'disabled' in a:
            return
        if tag in ('input', 'button') and a.get('name'):
            kind = a.get('type', 'submit' if tag == 'button' else 'text').lower()
            self.current['login'] |= kind == 'password'
            self.current['upload'] |= kind == 'file'
            if kind in ('button', 'reset', 'image', 'file'):
                return
            if kind == 'submit':
                if any(f['type'] == 'submit' for f in self.current['fields']):
                    return
                if a.get('formaction'):
                    self.current['action'] = urljoin(self.url, a['formaction'])
                if a.get('formmethod'):
                    self.current['method'] = a['formmethod'].upper()
            if kind in ('checkbox', 'radio') and 'checked' not in a:
                return
            self.current['fields'].append({'name': a['name'], 'type': kind,
                                          'value': a.get('value', 'on' if kind in ('checkbox', 'radio') else '')})
        if tag == 'textarea' and a.get('name'):
            self.textarea = {'name': a['name'], 'type': 'textarea', 'value': ''}
            self.current['fields'].append(self.textarea)
        if tag == 'select' and a.get('name'):
            self.select = {'name': a['name'], 'type': 'select', 'value': '', '_chosen': False}
            self.current['fields'].append(self.select)
        if tag == 'option' and self.select is not None:
            self.option = {'value': a.get('value'), 'text': '', 'selected': 'selected' in a}

    def handle_data(self, data):
        if self.current_script is not None:
            self.current_script += data
        if not self.ignore_text and len(self.public_text) < 2000:
            self.public_text += ' ' + ' '.join(data.split())[:2000 - len(self.public_text)]
        if self.textarea is not None:
            self.textarea['value'] += data
        if self.option is not None:
            self.option['text'] += data

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'textarea'):
            self.ignore_text = max(0, self.ignore_text - 1)
        if tag == 'option' and self.option is not None and self.select is not None:
            if self.option['selected'] or not self.select['_chosen']:
                self.select['value'] = self.option['value'] if self.option['value'] is not None else self.option['text']
                self.select['_chosen'] = True
            self.option = None
        if tag == 'textarea':
            self.textarea = None
        if tag == 'select':
            self.select = self.option = None
        if tag == 'form':
            self.current = self.textarea = self.select = self.option = None
        if tag == 'script' and self.current_script is not None:
            self.scripts.append(self.current_script)
            self.current_script = None


def _script_request_forms(url, scripts):
    """Extract simple same-page fetch/XHR request surfaces from inline JS.

    This intentionally handles only literal URLs and URLSearchParams append
    calls. It does not execute JavaScript and never follows an external URL.
    """
    forms = []
    for script in scripts:
        parameter_sets = {}
        for match in re.finditer(
                r'(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new\s+URLSearchParams\s*\([^)]*\)',
                script):
            variable = match.group(1)
            names = re.findall(
                rf'\b{re.escape(variable)}\.append\s*\(\s*[\'\"]([^\'\"]+)[\'\"]\s*,', script)
            if names:
                parameter_sets[variable] = list(dict.fromkeys(names))
        for match in re.finditer(
                r'fetch\s*\(\s*([\'\"])([^\'\"]+)\1\s*,\s*\{(.*?)\}\s*\)',
                script, re.I | re.S):
            endpoint, options = match.group(2), match.group(3)
            method_match = re.search(r'\bmethod\s*:\s*[\'\"]([A-Za-z]+)[\'\"]', options, re.I)
            method = method_match.group(1).upper() if method_match else 'GET'
            body_match = re.search(r'\bbody\s*:\s*([A-Za-z_$][\w$]*)', options)
            names = parameter_sets.get(body_match.group(1), []) if body_match else []
            if method not in ('GET', 'POST') or not names:
                continue
            forms.append({
                'page': url, 'action': urljoin(url, endpoint), 'method': method,
                'enctype': 'application/x-www-form-urlencoded',
                'fields': [{'name': name, 'type': 'text', 'value': ''} for name in names],
                'login': False, 'upload': False, 'source': 'javascript',
            })
    return forms


def parse_page(url, html):
    parser = PageParser(url)
    parser.feed(html)
    parser.script_requests = _script_request_forms(url, parser.scripts)
    return parser


_JS_HTTP_CALL = re.compile(
    r'(?P<client>fetch|(?:axios|api|client|http|this\.http)\s*\.\s*'
    r'(?P<verb>get|post|put|patch|delete|head|options))\s*\(\s*'
    r'(?P<quote>[\'"`])(?P<url>.*?)(?P=quote)', re.I | re.S)
_XHR_OPEN = re.compile(
    r'\.open\s*\(\s*[\'"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\'"`]\s*,\s*'
    r'([\'"`])(.*?)\2', re.I | re.S)
_STREAM_CALL = re.compile(r'new\s+(WebSocket|EventSource)\s*\(\s*([\'"`])(.*?)\2', re.I | re.S)
_FRONTEND_ROUTE = re.compile(r'\bpath\s*:\s*([\'"`])(/[^\'"`\s]+)\1', re.I)
_SOURCE_MAP = re.compile(r'[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)', re.I)
_GRAPHQL_OPERATION = re.compile(
    r'\b(query|mutation|subscription)\s+([A-Za-z_]\w*)\s*'
    r'(?:\([^{}]*\)\s*)?\{')

_SIGNALS = {
    'authentication': re.compile(
        r'\b(?:authorization|bearer|accessToken|refreshToken|idToken|jwt|oauth|oidc|session|csrf)\b', re.I),
    'authorization': re.compile(
        r'\b(?:role|roles|permission|permissions|scope|scopes|isAdmin|organizationId|tenantId|workspaceId)\b', re.I),
    'identifiers': re.compile(
        r'\b(?:userId|memberId|accountId|organizationId|tenantId|workspaceId|projectId|resourceId)\b', re.I),
    'business_actions': re.compile(
        r'\b(?:create|update|delete|approve|reject|invite|export|transfer|changeRole|reset|checkout|purchase)\w*\b', re.I),
}

_FRAMEWORKS = {
    'React': re.compile(r'\bReact(?:DOM)?\b|__REACT_DEVTOOLS_GLOBAL_HOOK__'),
    'Angular': re.compile(r'\bangular(?:\.module)?\b|ng-version', re.I),
    'Vue': re.compile(r'\bVue\b|__VUE__|createApp\s*\('),
    'Next.js': re.compile(r'__NEXT_DATA__|/_next/'),
    'Nuxt': re.compile(r'__NUXT__|/_nuxt/'),
    'Svelte': re.compile(r'\bSvelteComponent\b|svelte/internal'),
    'Webpack': re.compile(r'webpackChunk|__webpack_require__'),
    'Vite': re.compile(r'/@vite/|__vite__mapDeps'),
}


def _template_url(value):
    """Normalize a literal/template endpoint without executing JavaScript."""
    value = value.strip().replace('\\/', '/')
    value = re.sub(r'\$\{\s*([A-Za-z_$][\w$]*)\s*\}', r'{\1}', value)
    return value if value and len(value) <= 1000 else ''


def _script_provenance(source_url):
    if '#inline-' in source_url:
        return 'inline'
    path = urlsplit(source_url).path.lower()
    name = path.rsplit('/', 1)[-1]
    if ('/vendor/' in path or name.startswith(
            ('jquery', 'bootstrap', 'modernizr', 'datepicker', 'plugins', 'polyfill', 'runtime'))):
        return 'vendor'
    return 'application'


def _jsluice_endpoints(initial_url, source_url, resolution_url, source, binary):
    """Analyze already-fetched JavaScript without allowing an independent fetch."""
    if not binary:
        return [], None
    try:
        process = subprocess.run(
            [binary, 'urls', '--raw-input', '--resolve-paths', resolution_url,
             '--unique', '--ignore-strings'],
            input=source, capture_output=True, text=True, timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return [], f'jsluice não executado: {exc}'
    if process.returncode:
        return [], f'jsluice terminou com código {process.returncode}'

    endpoints, invalid = [], 0
    for line in process.stdout.splitlines():
        try:
            item = json.loads(line)
        except (TypeError, json.JSONDecodeError):
            invalid += 1
            continue
        value = _template_url(str(item.get('url') or ''))
        method = str(item.get('method') or 'GET').upper()
        if not value or method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE',
                                       'HEAD', 'OPTIONS'):
            continue
        endpoints.append({
            'method': method,
            'url': value,
            'kind': f"jsluice:{str(item.get('type') or 'ast')}",
            'in_scope': scoped_url(initial_url, value) is not None,
            'source': source_url,
            'query_parameters': list(dict.fromkeys(
                str(name) for name in item.get('queryParams', []) if name))[:100],
            'body_parameters': list(dict.fromkeys(
                str(name) for name in item.get('bodyParams', []) if name))[:100],
            'detectors': ['jsluice'],
        })
    warning = f'jsluice ignorou {invalid} linha(s) não JSON' if invalid else None
    return endpoints, warning


def analyze_javascript(initial_url, source_url, source, jsluice_binary=None,
                       resolution_url=None):
    """Extract architecture signals from JavaScript as data, never as findings."""
    endpoints = []
    resolution_url = resolution_url or source_url
    provenance = _script_provenance(source_url)

    def add(method, value, kind):
        value = _template_url(value)
        if not value or value.startswith(('data:', 'javascript:', '#')):
            return
        resolved = urljoin(resolution_url, value) if not value.startswith(('ws://', 'wss://')) else value
        endpoints.append({
            'method': method.upper(), 'url': resolved, 'kind': kind,
            'in_scope': scoped_url(initial_url, resolved) is not None,
            'source': source_url, 'detectors': ['builtin'],
        })

    for match in _JS_HTTP_CALL.finditer(source):
        method = (match.group('verb') or 'GET').upper()
        if match.group('client').lower() == 'fetch':
            tail = source[match.end():match.end() + 800]
            method_match = re.search(r'\bmethod\s*:\s*[\'"`]([A-Za-z]+)[\'"`]', tail, re.I)
            if method_match:
                method = method_match.group(1).upper()
        add(method, match.group('url'), 'http')
    for match in _XHR_OPEN.finditer(source):
        add(match.group(1), match.group(3), 'xhr')
    for match in _STREAM_CALL.finditer(source):
        add('CONNECT' if match.group(1).lower() == 'websocket' else 'GET',
            match.group(3), match.group(1).lower())
    for match in _FRONTEND_ROUTE.finditer(source):
        add('ROUTE', match.group(2), 'frontend_route')

    source_maps = []
    for value in _SOURCE_MAP.findall(source):
        value = value.strip().strip('"\'')
        if not value.startswith('data:'):
            source_maps.append(urljoin(source_url, value))
    signals = {name: list(dict.fromkeys(m.group(0) for m in pattern.finditer(source)))[:80]
               for name, pattern in _SIGNALS.items()}
    frameworks = [name for name, pattern in _FRAMEWORKS.items()
                  if pattern.search(source) or pattern.search(source_url)]
    operations = [{'type': kind.lower(), 'name': name}
                  for kind, name in _GRAPHQL_OPERATION.findall(source)][:100]
    supplemental, warning = ([], None)
    if provenance != 'vendor':
        supplemental, warning = _jsluice_endpoints(
            initial_url, source_url, resolution_url, source, jsluice_binary)
    for candidate in supplemental:
        existing = next((item for item in endpoints
                         if item['method'] == candidate['method']
                         and item['url'] == candidate['url']), None)
        if existing:
            existing['detectors'] = list(dict.fromkeys(
                existing.get('detectors', []) + candidate['detectors']))
            for field in ('query_parameters', 'body_parameters'):
                existing[field] = list(dict.fromkeys(
                    existing.get(field, []) + candidate.get(field, [])))
        else:
            endpoints.append(candidate)
    return {
        'source': source_url, 'provenance': provenance,
        'endpoints': endpoints,
        'source_maps': list(dict.fromkeys(source_maps)),
        'signals': signals,
        'frameworks': frameworks,
        'graphql_operations': operations,
        'jsluice_warning': warning,
    }


def reverse_engineer(initial_url, pages, fetch, max_scripts=24, max_source_maps=8,
                       cancelled=lambda: False, jsluice_binary=None):
    """Build a bounded static model from HTML, JS bundles and source maps."""
    report = {
        'scripts': [], 'external_scripts': [], 'source_maps': [], 'endpoints': [],
        'frameworks': [], 'signals': {name: [] for name in _SIGNALS},
        'graphql_operations': [], 'architecture_edges': [], 'errors': [],
        'analyzers': {
            'builtin': {'available': True, 'mode': 'static'},
            'jsluice': {'available': bool(jsluice_binary), 'mode': 'AST/static'},
        },
        'limits': {'scripts': max_scripts, 'source_maps': max_source_maps},
        'truncated': False,
        'limitations': [
            'JavaScript analisado estaticamente; código, estado de SPA e service workers não são executados',
            'Endpoints calculados, módulos carregados em runtime e fluxos autenticados podem permanecer ocultos',
            'Sinais de identidade, autorização e negócio são hipóteses de arquitetura, não vulnerabilidades',
        ],
    }
    if not jsluice_binary:
        report['limitations'].append(
            'jsluice não disponível; extração AST complementar de endpoints não executada')
    analyses = []
    script_urls = []
    script_bases = {}
    for page in pages:
        for index, source in enumerate(page.scripts, 1):
            analyses.append(analyze_javascript(
                initial_url, f'{page.url}#inline-{index}', source, jsluice_binary,
                resolution_url=page.url))
        for url in page.script_sources:
            if scoped_url(initial_url, url):
                script_urls.append(url)
                script_bases.setdefault(url, page.url)
            else:
                report['external_scripts'].append(url)
    script_urls = list(dict.fromkeys(script_urls))
    if len(script_urls) > max_scripts:
        report['truncated'] = True
        script_urls = script_urls[:max_scripts]

    for url in script_urls:
        if cancelled():
            report['truncated'] = True
            break
        try:
            response = fetch(url)
            content_type = response.get('content_type', '').lower()
            if response['status'] != 200:
                raise RuntimeError(f'HTTP {response["status"]}')
            if not (urlsplit(url).path.lower().endswith(('.js', '.mjs')) or
                    any(kind in content_type for kind in ('javascript', 'ecmascript', 'text/plain'))):
                raise RuntimeError(f'Content-Type não JavaScript: {content_type or "ausente"}')
            source = response['body']
            report['scripts'].append({'url': url, 'provenance': _script_provenance(url),
                                      'bytes': len(source.encode('utf-8')),
                                      'sha256': hashlib.sha256(source.encode()).hexdigest()})
            analyses.append(analyze_javascript(
                initial_url, url, source, jsluice_binary,
                resolution_url=script_bases.get(url, initial_url)))
        except (ValueError, OSError, RuntimeError) as exc:
            report['errors'].append({'url': url, 'reason': str(exc)})

    map_urls = list(dict.fromkeys(url for analysis in analyses
                                  for url in analysis['source_maps']
                                  if scoped_url(initial_url, url)))
    if len(map_urls) > max_source_maps:
        report['truncated'] = True
        map_urls = map_urls[:max_source_maps]
    for url in map_urls:
        if cancelled():
            report['truncated'] = True
            break
        try:
            response = fetch(url)
            if response['status'] != 200:
                raise RuntimeError(f'HTTP {response["status"]}')
            payload = json.loads(response['body'])
            sources = [str(item) for item in payload.get('sources', [])]
            report['source_maps'].append({
                'url': url, 'source_root': str(payload.get('sourceRoot') or ''),
                'sources': sources[:200], 'source_count': len(sources),
                'truncated': len(sources) > 200,
            })
        except (ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            report['errors'].append({'url': url, 'reason': f'Source map inválido: {exc}'})

    endpoint_index = {}
    report['analyzers']['jsluice']['sources_analyzed'] = sum(
        1 for analysis in analyses
        if jsluice_binary and analysis['provenance'] != 'vendor')
    report['analyzers']['jsluice']['failures'] = sum(
        1 for analysis in analyses if analysis.get('jsluice_warning'))
    for analysis in analyses:
        if analysis.get('jsluice_warning'):
            report['errors'].append({
                'url': analysis['source'], 'reason': analysis['jsluice_warning']})
        report['frameworks'].extend(analysis['frameworks'])
        if analysis['provenance'] == 'vendor':
            continue
        report['graphql_operations'].extend(analysis['graphql_operations'])
        for category, values in analysis['signals'].items():
            report['signals'][category].extend(values)
        for endpoint in analysis['endpoints']:
            key = (endpoint['method'], endpoint['url'], endpoint['kind'])
            item = endpoint_index.setdefault(key, {k: v for k, v in endpoint.items() if k != 'source'} |
                                                   {'sources': []})
            item['sources'].append(endpoint['source'])
            item['detectors'] = list(dict.fromkeys(
                item.get('detectors', []) + endpoint.get('detectors', [])))
            for field in ('query_parameters', 'body_parameters'):
                item[field] = list(dict.fromkeys(
                    item.get(field, []) + endpoint.get(field, [])))
    for item in endpoint_index.values():
        item['sources'] = list(dict.fromkeys(item['sources']))
        report['endpoints'].append(item)
        report['architecture_edges'].append({
            'from': item['sources'][0], 'operation': item['method'], 'to': item['url'],
            'kind': item['kind'], 'in_scope': item['in_scope'],
        })
    report['frameworks'] = list(dict.fromkeys(report['frameworks']))
    for url in report['external_scripts']:
        report['frameworks'].extend(name for name, pattern in _FRAMEWORKS.items()
                                    if pattern.search(url))
    report['frameworks'] = list(dict.fromkeys(report['frameworks']))
    report['graphql_operations'] = list({(x['type'], x['name']): x
                                         for x in report['graphql_operations']}.values())
    for category in report['signals']:
        report['signals'][category] = list(dict.fromkeys(report['signals'][category]))[:100]
    report['external_scripts'] = list(dict.fromkeys(report['external_scripts']))
    report['summary'] = {
        'scripts_analyzed': len(report['scripts']) + sum(len(p.scripts) for p in pages),
        'source_maps': len(report['source_maps']), 'endpoints': len(report['endpoints']),
        'in_scope_endpoints': sum(1 for item in report['endpoints'] if item['in_scope']),
        'external_references': len(report['external_scripts']) +
                               sum(1 for item in report['endpoints'] if not item['in_scope']),
    }
    return report


def discover(initial_url, fetch, seeds=(), max_pages=12, max_depth=2, cancelled=lambda: False):
    initial_url = scoped_url(initial_url, initial_url)
    if not initial_url:
        raise ValueError('Alvo HTTP(S) inválido')
    queue = deque([(initial_url, 0)])
    queue.extend((u, 0) for s in seeds if (u := scoped_url(initial_url, s)))
    seen, pages, errors = set(), [], []
    while queue and len(seen) < max_pages and not cancelled():
        url, depth = queue.popleft()
        if url in seen or MUTATION.search(urlsplit(url).path) or STATIC.search(urlsplit(url).path):
            continue
        seen.add(url)
        try:
            response = fetch(url)
            status = response['status']
            if 300 <= status < 400:
                redirect = scoped_url(url, response.get('location', ''))
                if redirect and depth < max_depth:
                    queue.append((redirect, depth + 1))
                else:
                    errors.append({'url': url, 'reason': 'Redirecionamento fora do escopo ou limite de profundidade'})
                continue
            if status != 200:
                errors.append({'url': url, 'reason': f'HTTP {status}; conteúdo não analisado'})
                continue
            if 'html' not in response.get('content_type', '').lower():
                errors.append({'url': url, 'reason': 'Resposta não HTML'})
                continue
            page = parse_page(url, response['body'])
            pages.append(page)
            if depth < max_depth:
                for link in page.links:
                    target = scoped_url(initial_url, link)
                    if target:
                        queue.append((target, depth + 1))
        except (ValueError, OSError, RuntimeError) as exc:
            errors.append({'url': url, 'reason': str(exc)})
    return pages, errors, bool(queue)


def plan_tests(initial_url, pages, max_jobs=12):
    jobs, pending, seen = [], [], set()
    def add(tool, url, reason, form=None):
        key = (tool, url, form['method'] if form else 'GET',
               tuple(f['name'] for f in form['fields']) if form else ())
        if key in seen:
            return
        seen.add(key)
        item = {'tool': tool, 'url': url, 'reason': reason, 'form': form}
        jobs.append(item)
    for page in pages:
        if parse_qsl(urlsplit(page.url).query, keep_blank_values=True):
            for tool in ('sqlmap_url', 'dalfox_url'):
                add(tool, page.url, 'Parâmetros na URL')
        for form in [*page.forms, *page.script_requests]:
            action = scoped_url(initial_url, form['action'])
            if not action:
                pending.append({'url': form['page'], 'reason': 'Action do formulário fora do escopo'})
                continue
            if form['upload'] or form['enctype'] != 'application/x-www-form-urlencoded' or form['method'] not in ('GET', 'POST'):
                pending.append({'url': action, 'reason': 'Upload, enctype ou método requer verificação específica'})
                continue
            if MUTATION.search(action):
                pending.append({'url': action, 'reason': 'Formulário com possível alteração destrutiva'})
                continue
            fields = [f for f in form['fields'] if not TOKEN.search(f['name']) and f['type'] not in ('hidden', 'submit')]
            if not fields:
                pending.append({'url': action, 'reason': 'Sem campos editáveis para injection'})
                continue
            if form.get('source') == 'javascript':
                add('sqlmap_url', action, 'JavaScript/fetch: testar SQLi no corpo POST', form)
                add('commix', action, 'JavaScript/fetch: testar command injection no corpo POST', form)
                continue
            # Login detection is evidence of an auth surface, never proof of bypass.
            add('sqlmap_url', action, 'Login: testar injection nos campos de autenticação' if form['login'] else 'Formulário: testar SQLi', form)
            if not form['login']:
                add('dalfox_url', action, 'Formulário: testar XSS', form)
            else:
                pending.append({'url': action, 'reason': 'BF e bypass lógico pendentes: conta/lista e critério de sucesso não configurados'})
    # Prefer login and POST surfaces over repeated generic query scans.
    def priority(job):
        form = job['form']
        return 0 if form and form['login'] else 1 if form and form['method'] == 'POST' else 2 if form else 3
    jobs.sort(key=priority)
    for job in jobs[max_jobs:]:
        pending.append({'url': job['url'], 'reason': 'Limite de tarefas atingido', 'tool': job['tool']})
    return jobs[:max_jobs], pending


def form_request(form):
    values = []
    parameters = []
    tokens = []
    for field in form['fields']:
        value = field['value']
        if TOKEN.search(field['name']):
            tokens.append(field['name'])
        elif field['type'] not in ('hidden', 'submit'):
            parameters.append(field['name'])
            if not value:
                value = '1' if field['type'] in ('number', 'range') else 'reconx_test'
        values.append((field['name'], value))
    data = urlencode(values)
    url = form['action']
    if form['method'] == 'GET':
        parsed = urlsplit(url)
        query = urlencode(parse_qsl(parsed.query, keep_blank_values=True) + values)
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ''))
        data = None
    return {'url': url, 'data': data, 'parameters': parameters, 'tokens': tokens, 'page': form['page']}
