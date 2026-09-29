"""Bounded HTML discovery and explainable test planning (no AI dependency)."""
from collections import deque
from html.parser import HTMLParser
import re
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
        self.current = None
        self.textarea = None
        self.select = None
        self.option = None
        self.public_text = ''
        self.ignore_text = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ('script', 'style', 'textarea'):
            self.ignore_text += 1
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


def parse_page(url, html):
    parser = PageParser(url)
    parser.feed(html)
    return parser


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
        for form in page.forms:
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
