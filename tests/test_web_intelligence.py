import ast
from pathlib import Path
import sys
import tempfile
import json
import http.cookiejar
import urllib.request
import subprocess
import os
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from web_intelligence import scoped_url, parse_page, discover, plan_tests, form_request
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

    def test_positive_finding_after_120_operational_lines_is_retained(self):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
        names = {'_TOOL_NOISE', '_NOISE_RE', '_HI_RE', '_MED_RE', '_LOW_RE'}
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
                  form_request=form_request, scoped_url=scoped_url)
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


if __name__ == '__main__':
    unittest.main()
