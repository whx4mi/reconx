"""Regression checks without importing Flask or starting a scan/database.

Load the real catalog and execution helpers from app.py through its AST, and
replace only external effects (tools, sockets, database and Socket.IO).
Run: python -m unittest discover -s tests -v
"""
import ast
from pathlib import Path
import random
import re
import shutil
import socket
import subprocess
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit


def load_helpers():
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'app.py').read_text(encoding='utf-8'))
    functions = {'check_proxy_alive', '_proxy_url_if_alive', '_tool_proxy_url',
                 'proxy_status', 'inject_proxy', 'proxy_env', 'to_host', 'to_domain',
                 'to_url', 'to_http_url', 'build_cmd', 'run_tool_sequential',
                 'run_verification', 'api_retest'}
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            node.decorator_list = []
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in {'TOOLS', 'PROXY_PROFILES', 'USER_AGENTS'}
                for t in node.targets):
            nodes.append(node)
    ns = dict(Path=Path, re=re, socket=socket, urlsplit=urlsplit, random=random,
              subprocess=subprocess, shutil=shutil, threading=threading, time=time,
              WL_COMMON=None, WL_SMALL=None, WL_DNS=None, SCREENS_DIR=Path('/tmp/screens'),
              DEFAULT_TOOL_TIMEOUT=10, VERIFY_TIMEOUT=10, VERIFY_MAX_OUTPUT=4000,
              EXEC_ENV={'PATH': '/bin', 'HTTP_PROXY': 'http://inherited:80',
                        'all_proxy': 'socks5://inherited:90', 'NO_PROXY': '*',
                        'no_proxy': 'localhost'},
              active_proxy={'profile': 'none', 'http': None, 'socks': None},
              active_scans={'scan': {'processes': {}}}, socketio=MagicMock(),
              check_binary=MagicMock(return_value=True),
              strip_ansi=lambda s: s, _is_stream_noise=lambda s: False,
              _save_tool_output=MagicMock(), _scan_output_dir=lambda s: Path('/tmp'),
              parse_output=lambda *a: ([], []), persist_and_emit_findings=MagicMock(),
              jsonify=lambda x: x)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'app.py', 'exec'), ns)
    return ns


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_helpers()
        self.ns['check_proxy_alive'] = MagicMock(return_value=True)
        self.direct = {'profile': 'none', 'http': None, 'socks': None}
        self.http = {'profile': 'burp', 'http': 'http://127.0.0.1:8080', 'socks': None}

    def test_unavailable_proxy_blocks_before_popen(self):
        self.ns['active_proxy'] = self.http
        self.ns['check_proxy_alive'].return_value = False
        with patch.object(subprocess, 'Popen') as launch:
            self.assertEqual(self.ns['run_tool_sequential']('scan', 'sqlmap', 'http://lab.test', 'sid'), ('', []))
            launch.assert_not_called()
        event, data = self.ns['socketio'].emit.call_args.args
        self.assertEqual(event, 'tool_skip')
        self.assertIn('bloqueada', data['reason'])

    def test_malformed_and_empty_custom_proxy_never_become_direct(self):
        for address in (None, 'localhost:8080', 'http://lab', 'http://lab:0',
                        'http://lab:65536', 'http://lab:8080/path', 'http://lab:8080?x=1',
                        'http://lab:8080\n', 'socks5://lab:9050'):
            with self.subTest(address=address):
                proxy = {'profile': 'custom', 'http': address, 'socks': None}
                self.assertIsNone(self.ns['build_cmd']('sqlmap', 'http://lab.test', proxy)[0])

    def test_authenticated_ipv6_and_socks_status(self):
        proxy = {'profile': 'custom', 'http': None, 'socks': 'socks5h://user:pass@[::1]:9050'}
        self.ns['active_proxy'] = proxy
        self.assertTrue(self.ns['proxy_status']()['reachable'])
        self.ns['check_proxy_alive'].assert_called_with('::1', 9050)
        cmd, _ = self.ns['build_cmd']('sqlmap', 'http://lab.test', proxy)
        self.assertEqual(cmd[cmd.index('--proxy') + 1], proxy['socks'])

    def test_tor_checks_both_endpoints(self):
        proxy = {'profile': 'tor', 'http': 'http://localhost:8118', 'socks': 'socks5://localhost:9050'}
        self.ns['check_proxy_alive'].side_effect = [True, False]
        self.assertIsNone(self.ns['build_cmd']('sqlmap', 'http://lab.test', proxy)[0])

    def test_unsupported_tools_and_nmap_are_blocked(self):
        for key in ('subfinder', 'naabu', 'nmap_quick', 'nmap_full', 'nmap_vuln'):
            with self.subTest(tool=key):
                self.assertIsNone(self.ns['build_cmd'](key, 'lab.test', self.http)[0])

    def test_http_only_tool_rejects_socks(self):
        proxy = {'profile': 'custom', 'http': None, 'socks': 'socks5://localhost:9050'}
        with self.assertRaises(ValueError):
            self.ns['inject_proxy'](['arjun'], 'arjun', proxy)

    def test_environment_removes_inherited_proxies_and_bypass(self):
        env = self.ns['proxy_env']('sqlmap', self.http)
        self.assertEqual(env['HTTP_PROXY'], self.http['http'])
        self.assertEqual(env['https_proxy'], self.http['http'])
        for key in ('NO_PROXY', 'no_proxy', 'all_proxy', 'ALL_PROXY'):
            self.assertNotIn(key, env)
        env = self.ns['proxy_env']('sqlmap', self.direct)
        self.assertFalse(any(k.lower().endswith('_proxy') for k in env))

    def test_explicit_direct_mode_preserves_scan_commands(self):
        for key in ('sqlmap', 'nmap_quick', 'subfinder'):
            with self.subTest(tool=key):
                cmd, _ = self.ns['build_cmd'](key, 'http://lab.test', self.direct)
                self.assertIsNotNone(cmd)
                self.assertNotIn('--proxy', cmd)
                self.assertNotIn('--proxies', cmd)
        self.ns['check_proxy_alive'].assert_not_called()

    def run_fake_tool(self, proxy):
        self.ns['active_proxy'] = proxy
        proc = MagicMock(returncode=0)
        proc.stdout.readline.side_effect = ['result\n', '']
        # A profile change while preparing the command must not alter its env.
        original = self.ns['build_cmd']
        def build(*args):
            result = original(*args)
            self.ns['active_proxy'] = self.direct
            return result
        self.ns['build_cmd'] = build
        with patch.object(subprocess, 'Popen', return_value=proc) as launch, \
                patch.object(threading, 'Timer'):
            self.ns['run_tool_sequential']('scan', 'sqlmap', 'http://lab.test', 'sid')
            return launch.call_args

    def test_reachable_proxy_launches_with_consistent_snapshot(self):
        call = self.run_fake_tool(self.http)
        self.assertIn(self.http['http'], call.args[0])
        self.assertEqual(call.kwargs['env']['HTTP_PROXY'], self.http['http'])

    def test_direct_runner_launches_without_proxy(self):
        call = self.run_fake_tool(self.direct)
        self.assertNotIn('--proxy', call.args[0])
        self.assertNotIn('HTTP_PROXY', call.kwargs['env'])

    def test_verification_cannot_bypass_selected_proxy(self):
        self.ns['active_proxy'] = self.http
        with patch.object(subprocess, 'run') as launch:
            result = self.ns['run_verification']({})
            self.assertFalse(result['ok'])
            self.assertIn('bloqueada', result['error'])
            launch.assert_not_called()

    def test_direct_verification_still_launches(self):
        self.ns.update(match_verifier=lambda f: {'tool': 'curl', 'cmd': ['curl', '{url}'],
                       'needs': ['url'], 'success': 'ok', 'id': 'http'},
                       _verify_params=lambda *a: {'url': 'http://lab.test'})
        with patch.object(shutil, 'which', return_value='/bin/curl'), \
                patch.object(subprocess, 'run', return_value=MagicMock(stdout='ok', stderr='', returncode=0)) as launch:
            self.assertTrue(self.ns['run_verification']({})['ok'])
            self.assertNotIn('HTTP_PROXY', launch.call_args.kwargs['env'])

    def setup_retest(self):
        db = MagicMock()
        db.__enter__.return_value.execute.return_value.fetchone.return_value = {
            'tool': 'sqlmap', 'ftype': 'sqli', 'target': 'http://lab.test'}
        self.ns.update(_db_lock=threading.Lock(), _db=lambda: db)

    def test_retest_blocks_down_proxy(self):
        self.setup_retest()
        self.ns['active_proxy'] = self.http
        self.ns['check_proxy_alive'].return_value = False
        with patch.object(subprocess, 'run') as launch:
            self.assertEqual(self.ns['api_retest']('scan', 1)[1], 400)
            launch.assert_not_called()

    def test_retest_unpacks_command_and_supplies_proxy_env(self):
        self.setup_retest()
        self.ns['active_proxy'] = self.http
        with patch.object(subprocess, 'run', return_value=MagicMock(stdout='ok', returncode=0)) as launch:
            self.ns['api_retest']('scan', 1)
            self.assertIsInstance(launch.call_args.args[0], list)
            self.assertEqual(launch.call_args.kwargs['env']['HTTP_PROXY'], self.http['http'])

    def test_socket_check_closes_connection(self):
        ns = load_helpers()
        with socket.socket() as server:
            server.bind(('127.0.0.1', 0))
            server.listen()
            self.assertTrue(ns['check_proxy_alive'](*server.getsockname()))


if __name__ == '__main__':
    unittest.main()
