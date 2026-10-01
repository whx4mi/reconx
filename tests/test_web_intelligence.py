import ast
from pathlib import Path
import sys
import tempfile
import json
import http.cookiejar
import urllib.request
import subprocess
import os
from login_testing import candidate_sources, run_login_tests, eligible_login_forms, validate_config
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from web_intelligence import (scoped_url, parse_page, discover, plan_tests, form_request,
                              reverse_engineer)
from test_proxy import load_helpers

BASE = 'http://lab.test:8080/meOwna/'


class WebIntelligenceTests(unittest.TestCase):
    def response(self, html, **overrides):
        return dict(status=200, body=html, content_type='text/html', **overrides)

    def test_same_origin_enforces_scheme_host_port_and_credentials(self):
        self.assertEqual(scoped_url(BASE, 'search.php?q=hello#x'), BASE + 'search.php?q=hello')
        for url in ('http://external.test/', 'https://lab.test:8080/', 'http://lab.test/',
                    'http://user:secret@lab.test:8080/', 'javascript:alert(1)', '//evil.test/'):
            self.assertIsNone(scoped_url(BASE, url))

    def test_login_post_and_hidden_token_are_preserved(self):
        html = '''<form method=POST action="login.php"><input name=user>
        <input type=password name=password><input type=hidden name=csrf value=abc>
        <input disabled name=no><input name=submit type=submit></form>'''
        page = parse_page(BASE, html)
        form = page.forms[0]
        self.assertTrue(form['login'])
        request = form_request(form)
        self.assertEqual(request['url'], BASE + 'login.php')
        self.assertEqual(request['tokens'], ['csrf'])
        self.assertEqual(request['parameters'], ['user', 'password'])
        self.assertIn(('csrf', 'abc'), parse_qsl(request['data']))
        self.assertIn(('submit', ''), parse_qsl(request['data'], keep_blank_values=True))
        jobs, pending = plan_tests(BASE, [page])
        self.assertEqual([j['tool'] for j in jobs], ['sqlmap_url'])
        self.assertIn('BF', pending[0]['reason'])

    def test_textarea_select_checked_fields_and_duplicate_names(self):
        form = parse_page(BASE, '''<form><textarea name=message>Hello</textarea>
        <select name=category><option value=1>One</option><option selected value=2>Two</option></select>
        <input type=checkbox name=tag value=a checked><input type=checkbox name=tag value=b checked>
        <input type=checkbox name=absent value=x></form>''').forms[0]
        request = form_request(form)
        fields = parse_qsl(urlsplit(request['url']).query)
        self.assertIn(('message', 'Hello'), fields)
        self.assertIn(('category', '2'), fields)
        self.assertEqual([v for k, v in fields if k == 'tag'], ['a', 'b'])
        self.assertNotIn('absent', [k for k, v in fields])

    def test_external_upload_and_destructive_forms_are_pending(self):
        page = parse_page(BASE, '''<form action="http://evil.test/" method=post><input name=q></form>
        <form action="upload.php"><input type=file name=file></form>
        <form action="delete.php"><input name=id></form>''')
        jobs, pending = plan_tests(BASE, [page])
        self.assertEqual(jobs, [])
        self.assertEqual(len(pending), 3)

    def test_query_and_get_form_create_specific_tests(self):
        page = parse_page(BASE + 'search.php?q=abc', '<form action=search.php><input name=q></form>')
        jobs, pending = plan_tests(BASE, [page])
        self.assertEqual(len(jobs), 4)
        self.assertTrue(any(j['url'] == page.url for j in jobs))
        self.assertEqual(pending, [])

    def test_inline_fetch_urlsearchparams_becomes_post_injection_surface(self):
        page = parse_page(BASE, '''<script>
            const data = new URLSearchParams();
            data.append('d', 'example.test');
            fetch('ping.php', {method: 'POST', body: data});
        </script>''')
        self.assertEqual(len(page.script_requests), 1)
        request = page.script_requests[0]
        self.assertEqual(request['action'], BASE + 'ping.php')
        self.assertEqual(request['method'], 'POST')
        self.assertEqual([field['name'] for field in request['fields']], ['d'])
        jobs, pending = plan_tests(BASE, [page])
        self.assertEqual([job['tool'] for job in jobs], ['sqlmap_url', 'commix'])
        self.assertEqual(pending, [])

    def test_reverse_engineers_bundles_source_maps_and_architecture_without_external_fetch(self):
        page = parse_page(BASE, '''
            <script src="js/app.js"></script>
            <script src="https://cdn.example/vendor.js"></script>
            <script>fetch('/graphql', {method: 'POST'});</script>
        ''')
        fetched = []
        bundle = '''
            webpackChunkapp.push([]);
            api.patch(`/api/organizations/${organizationId}/members/${memberId}`, data);
            const accessToken = sessionStorage.getItem('token');
            mutation InviteUser { inviteUser }
            new WebSocket('wss://events.example/ws');
            //# sourceMappingURL=app.js.map
        '''
        source_map = json.dumps({'sourceRoot': 'webpack://app/', 'sources': [
            'src/components/UserPanel.tsx', 'src/services/UserService.ts',
            'src/models/User.ts']})
        def fetch(url):
            fetched.append(url)
            if url.endswith('app.js'):
                return {'status': 200, 'body': bundle, 'content_type': 'application/javascript'}
            if url.endswith('app.js.map'):
                return {'status': 200, 'body': source_map, 'content_type': 'application/json'}
            raise AssertionError(f'fetch externo inesperado: {url}')

        report = reverse_engineer(BASE, [page], fetch)
        self.assertEqual(fetched, [BASE + 'js/app.js', BASE + 'js/app.js.map'])
        self.assertEqual(report['external_scripts'], ['https://cdn.example/vendor.js'])
        patch = next(e for e in report['endpoints'] if e['method'] == 'PATCH')
        self.assertEqual(patch['url'],
                         'http://lab.test:8080/api/organizations/{organizationId}/members/{memberId}')
        self.assertTrue(patch['in_scope'])
        self.assertIn('Webpack', report['frameworks'])
        self.assertIn('organizationId', report['signals']['authorization'])
        self.assertIn('accessToken', report['signals']['authentication'])
        self.assertEqual(report['graphql_operations'], [{'type': 'mutation', 'name': 'InviteUser'}])
        self.assertIn('src/services/UserService.ts', report['source_maps'][0]['sources'])
        self.assertTrue(any(edge['operation'] == 'PATCH' for edge in report['architecture_edges']))

    def test_vendor_script_is_inventoried_without_business_signal_noise(self):
        page = parse_page(BASE, '<script src="js/vendor/library.js"></script>')
        source = "function createElement(){}; const role='presentation'; api.post('/telemetry', {})"
        report = reverse_engineer(BASE, [page], lambda url: {
            'status': 200, 'body': source, 'content_type': 'application/javascript'})
        self.assertEqual(report['scripts'][0]['provenance'], 'vendor')
        self.assertEqual(report['endpoints'], [])
        self.assertEqual(report['signals']['authorization'], [])

    def test_crawler_follows_local_links_and_preserves_queries(self):
        fetched = []
        def fetch(url):
            fetched.append(url)
            return self.response('<a href="search.php?q=hello">s</a><a href="http://evil.test/">e</a>'
                                 '<a href="logout.php">logout</a><a href="image.png">image</a>')
        pages, errors, truncated = discover(BASE, fetch, max_pages=5)
        self.assertEqual(fetched, [BASE, BASE + 'search.php?q=hello'])
        self.assertEqual(len(pages), 2)
        self.assertEqual(errors, [])

    def test_external_redirect_is_never_fetched(self):
        fetch = MagicMock(return_value={'status': 302, 'location': 'http://evil.test/'})
        pages, errors, _ = discover(BASE, fetch)
        self.assertEqual(len(errors), 1)
        fetch.assert_called_once_with(BASE)

    def test_crawl_job_limits_and_cancellation(self):
        fetch = MagicMock(return_value=self.response('<a href=next.php>next</a>'))
        pages, _, truncated = discover(BASE, fetch, max_pages=1)
        self.assertTrue(truncated)
        self.assertEqual(fetch.call_count, 1)
        page = parse_page(BASE, '<form><input name=q></form>')
        jobs, pending = plan_tests(BASE, [page], max_jobs=1)
        self.assertEqual(len(jobs), 1)
        self.assertEqual(len(pending), 1)
        fetch.reset_mock()
        discover(BASE, fetch, cancelled=lambda: True)
        fetch.assert_not_called()

    def test_form_context_generates_post_cookie_and_csrf_arguments(self):
        ns = load_helpers()
        context = {'data': 'username=test&csrf=abc', 'cookie': 'PHPSESSID=session',
                   'parameters': ['username'], 'tokens': ['csrf'], 'page': BASE}
        cmd, _ = ns['build_cmd']('sqlmap_url', BASE + 'login.php', request_context=context)
        for flag, value in (('--data', context['data']), ('--cookie', context['cookie']),
                            ('--csrf-token', 'csrf'), ('--csrf-url', BASE), ('-p', 'username')):
            self.assertEqual(cmd[cmd.index(flag) + 1], value)
        self.assertIn('--ignore-redirects', cmd)

    def test_commix_receives_post_body_cookie_and_parameter(self):
        ns = load_helpers()
        context = {'data': 'd=example.test', 'cookie': 'PHPSESSID=session',
                   'parameters': ['d'], 'tokens': [], 'page': BASE}
        cmd, _ = ns['build_cmd']('commix', BASE + 'ping.php', request_context=context)
        self.assertIn('--data=d=example.test', cmd)
        self.assertIn('--cookie=PHPSESSID=session', cmd)
        self.assertEqual(cmd[cmd.index('-p') + 1], 'd')
        self.assertEqual(cmd.count('--ignore-redirects'), 1)

    def test_tools_keep_path_and_query(self):
        ns = load_helpers()
        target = BASE + 'search.php?q=abc'
        for tool in ('sqlmap', 'dalfox', 'katana', 'arjun'):
            cmd, _ = ns['build_cmd'](tool, target)
            self.assertIn(target, cmd)
        self.assertIn('--url=' + target, ns['build_cmd']('commix', target)[0])

    def test_adaptive_stage_added_only_to_full_web_pipeline(self):
        ns = load_helpers()
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_pipeline')
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'app.py', 'exec'), ns)
        run_stage = MagicMock(return_value=({}, []))
        ns.update(run_stage=run_stage, _finish=MagicMock())
        pipeline = {'label': 'Web App Pentest', 'stages': [
            {'id': 'recon', 'phase': 'recon', 'tools': []},
            {'id': 'test', 'phase': 'test', 'tools': []}]}
        ns['run_pipeline']('scan', pipeline, BASE, None, 'sid')
        self.assertEqual(run_stage.call_args_list[1].args[1]['tools'], ['adaptive_web'])
        self.assertEqual(len(pipeline['stages']), 2)
        run_stage.reset_mock()
        ns['run_pipeline']('scan', pipeline, BASE, None, 'sid', 'stealth')
        self.assertEqual(run_stage.call_count, 2)

    def test_sqlmap_noise_does_not_hide_positive_messages(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.Assign) and
                    any(isinstance(t, ast.Name) and t.id == '_TOOL_NOISE' for t in n.targets))
        import re
        ns = {'re': re}
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
        noise = ns['_TOOL_NOISE']['sqli']
        self.assertIsNone(noise.search("[INFO] POST parameter 'username' is vulnerable"))
        self.assertIsNotNone(noise.search('[INFO] testing connection to target'))
        self.assertIsNotNone(noise.search('[INFO] parameter is not injectable'))
        self.assertIsNotNone(noise.search("[WARNING] heuristic test shows parameter 'q' might not be injectable"))
        self.assertIsNotNone(noise.search("[WARNING] parameter 'q' does not seem to be injectable"))

    def test_dalfox_v3_uses_plural_cookies_option(self):
        ns = load_helpers()
        context = {'data': None, 'cookie': 'PHPSESSID=session',
                   'parameters': ['q'], 'tokens': [], 'page': BASE}
        cmd, _ = ns['build_cmd']('dalfox_url', BASE + '?q=x', request_context=context)
        self.assertEqual(cmd[cmd.index('--url') + 1], BASE + '?q=x')
        self.assertIn('--cookies', cmd)
        self.assertNotIn('--cookie', cmd)

    def test_positive_finding_after_120_operational_lines_is_retained(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        names = {'_TOOL_NOISE', '_NOISE_RE', '_HI_RE', '_MED_RE', '_LOW_RE',
                 '_SQLI_POSITIVE_RE', '_CMDI_POSITIVE_RE'}
        nodes = [n for n in tree.body if (isinstance(n, ast.Assign) and
                 any(isinstance(t, ast.Name) and t.id in names for t in n.targets)) or
                 (isinstance(n, ast.FunctionDef) and n.name == '_text_findings')]
        import re
        ns = {'re': re, '_finding': lambda *args: args}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), 'app.py', 'exec'), ns)
        lines = ['[INFO] testing connection'] * 200 + ["[INFO] parameter 'q' is vulnerable"]
        findings = ns['_text_findings']('sqlmap_url', 'sqli', lines)
        self.assertEqual(len(findings), 1)
        self.assertIn('vulnerable', findings[0][2])

    def test_adaptive_runner_discovers_refreshes_and_dispatches_post(self):
        ns = load_helpers()
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_adaptive_web')
        ns.update(tempfile=tempfile, http=http, urllib=urllib, json=json, os=os,
                  discover=discover, plan_tests=plan_tests, parse_page=parse_page,
                  form_request=form_request, scoped_url=scoped_url,
                  reverse_engineer=reverse_engineer)
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
        ns['active_scans']['scan']['target'] = BASE
        html = '<form method=POST action=search.php><input name=q><button name=go value=Search>Search</button></form>'
        def curl(cmd, **kwargs):
            Path(cmd[cmd.index('--dump-header') + 1]).write_text('HTTP/1.1 200 OK\nContent-Type: text/html\n\n')
            Path(cmd[cmd.index('--output') + 1]).write_text(html)
            return MagicMock(returncode=0)
        dispatched = []
        def run_tool(scan_id, tool, target, sid, context, outcome):
            dispatched.append((tool, target, context))
            outcome.update(status='completed', exit_code=0)
            return 'ok', []
        ns['run_tool_sequential'] = run_tool
        with tempfile.TemporaryDirectory() as output:
            ns['_scan_output_dir'] = lambda s: Path(output)
            with patch.object(subprocess, 'run', side_effect=curl):
                results, _ = ns['run_adaptive_web']('scan', [BASE], 'sid')
            report = json.loads((Path(output) / 'adaptive_report.json').read_text(encoding='utf-8'))
        self.assertEqual([t[0] for t in dispatched], ['sqlmap_url', 'dalfox_url'])
        self.assertIn(('go', 'Search'), parse_qsl(dispatched[0][2]['data']))
        self.assertEqual(report['forms'][0]['method'], 'POST')
        self.assertEqual([t['status'] for t in report['tasks']], ['completed', 'completed'])
        self.assertEqual(len(results), 3)

    def test_login_has_priority_when_job_budget_is_small(self):
        page = parse_page(BASE + 'search.php?q=x',
                          '<form action=login.php method=POST><input name=user><input type=password name=pwd></form>')
        jobs, pending = plan_tests(BASE, [page], max_jobs=1)
        self.assertTrue(jobs[0]['form']['login'])
        self.assertTrue(any(p['reason'] == 'Limite de tarefas atingido' for p in pending))

    def test_adaptive_custom_login_stores_credentials_separately(self):
        ns = load_helpers()
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_adaptive_web')
        ns.update(tempfile=tempfile, http=http, urllib=urllib, json=json, os=os,
                  discover=discover, plan_tests=plan_tests, parse_page=parse_page,
                  form_request=form_request, scoped_url=scoped_url,
                  reverse_engineer=reverse_engineer,
                  candidate_sources=candidate_sources, eligible_login_forms=eligible_login_forms,
                  run_login_tests=run_login_tests, _finding=lambda *args: {})
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
        html = '<h1>MeOwna</h1><form method=POST action=login.php><input name=user><input type=password name=pass></form>'
        submitted = []
        def curl(cmd, **kwargs):
            body = html
            if '--data-binary' in cmd:
                data = Path(cmd[cmd.index('--data-binary') + 1][1:]).read_text()
                from urllib.parse import parse_qsl
                fields = dict(parse_qsl(data))
                submitted.append(fields)
                body = 'Authenticated' if fields['user'] == 'student' and fields['pass'] == 'labpass' else 'Invalid'
            Path(cmd[cmd.index('--dump-header') + 1]).write_text('HTTP/1.1 200 OK\nContent-Type: text/html\n\n')
            Path(cmd[cmd.index('--output') + 1]).write_text(body)
            return MagicMock(returncode=0)
        ns['run_tool_sequential'] = lambda *args: ('ok', [])
        with tempfile.TemporaryDirectory() as output:
            output = Path(output)
            (output / 'users.txt').write_text('student\n')
            (output / 'passwords.txt').write_text('labpass\n')
            ns['active_scans']['scan'].update(target=BASE, login_testing=validate_config({
                'enabled': True, 'mode': 'custom', 'users_path': str(output / 'users.txt'),
                'passwords_path': str(output / 'passwords.txt'), 'success_text': 'Authenticated'}))
            ns['_scan_output_dir'] = lambda s: output
            with patch.object(subprocess, 'run', side_effect=curl), patch('login_testing.time.sleep'):
                # The wait callback is bound at definition; replace it in this fixture.
                ns['run_login_tests'] = lambda *a, **kw: run_login_tests(*a, **kw, wait=lambda seconds: None)
                ns['run_adaptive_web']('scan', [BASE], 'sid')
            public = (output / 'adaptive_report.json').read_text(encoding='utf-8')
            private = json.loads((output / 'login_credentials.json').read_text(encoding='utf-8'))
            self.assertNotIn('labpass', public)
            self.assertEqual(private[0]['password'], 'labpass')
            self.assertEqual(json.loads(public)['login_testing']['status'], 'matched')
        self.assertEqual(len(submitted), 3)


if __name__ == '__main__':
    unittest.main()
