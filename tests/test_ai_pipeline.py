import ast
import json
import os
from pathlib import Path
import subprocess
import threading
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

import ai_pipeline as ai
from test_proxy import load_helpers

BASE = 'http://lab.test:8080/'


def decision(tool='ai_headers', target='t0', action='run'):
    return dict(action=action, tool=tool, target_id=target, summary='Indício, não confirmação',
                reason='Revisar a configuração observada', evidence='Server: lab')


class AiPipelineTests(unittest.TestCase):
    def config(self, **kw):
        return ai.validate_config(dict(consent=True, **kw), BASE)

    def run_scan(self, answers, approve=True, execute=None, cancelled=lambda: False, config=None):
        self.decide = MagicMock(side_effect=answers)
        self.execute = execute or MagicMock(return_value=('Server: lab', {'status': 'completed'}))
        self.approve = MagicMock(return_value=approve)
        self.emit, self.save = MagicMock(), MagicMock()
        return ai.run(config or self.config(), self.decide, self.execute, self.approve,
                      self.emit, self.save, cancelled)

    def test_consent_required(self):
        for raw in ({}, {'consent': 'true'}, {'consent': True, 'mode': 'invalid'}):
            with self.assertRaises(ValueError):
                ai.validate_config(raw, BASE)

    def test_whitebox_origin_locked_and_blackbox_ignores_hints(self):
        c = self.config(mode='whitebox', endpoints='/login\n/user?id=1', context='PHP')
        self.assertEqual(c['seeds'], [BASE, BASE + 'login', BASE + 'user?id=1'])
        for endpoint in ('https://lab.test:8080/', '//evil.test/', 'http://lab.test/', 'http://u:p@lab.test:8080/'):
            with self.assertRaises(ValueError):
                self.config(mode='whitebox', endpoints=endpoint)
        c = self.config(mode='blackbox', endpoints='/login', context='ignored')
        self.assertEqual(c['seeds'], [BASE])
        self.assertEqual(c['context'], '')

    def test_invalid_targets_and_budgets(self):
        for target in ('--help', 'http://user:pw@lab.test', 'file:///tmp/x', 'http://lab.test:bad', 'lab.test\n-x'):
            with self.assertRaises(ValueError):
                ai.canonical_target(target)
        for n in (0, 21, 'bad'):
            with self.assertRaises(ValueError):
                self.config(max_steps=n)

    def test_no_commands_extra_keys_external_targets_or_exploit_tools(self):
        for d in (dict(decision(), command='id'), decision('sqlmap'), decision(target='http://evil.test'),
                  decision(action='shell'), dict(decision(), reason='')):
            with self.assertRaises(ValueError):
                ai.validate_decision(d, {('ai_headers', 't0')})

    def test_every_action_needs_approval(self):
        result = self.run_scan([decision(), decision('ai_ports'), decision('', '', 'stop')])
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(self.execute.call_count, 2)
        self.assertEqual(self.approve.call_count, 2)
        self.assertEqual(self.approve.call_args_list[0].args[0]['target'], BASE)
        self.assertIn('Server: lab', self.decide.call_args_list[1].args[0]['observations'][0]['output'])

    def test_rejection_never_executes_or_reoffers_pair(self):
        result = self.run_scan([decision('ai_page'), decision('ai_page')], approve=False)
        self.execute.assert_not_called()
        self.assertEqual(result['status'], 'failed')
        allowed = self.decide.call_args_list[1].args[0]['available_actions']
        self.assertNotIn({'tool': 'ai_page', 'target_id': 't0', **ai.CATALOG['ai_page']}, allowed)

    def test_invalid_provider_response_fail_closed(self):
        result = self.run_scan([{'tool': 'ai_headers'}])
        self.execute.assert_not_called()
        self.assertEqual(result['status'], 'failed')

    def test_cancel_during_approval_does_not_execute(self):
        state = {'cancelled': False}
        execute = MagicMock()
        def approve(action):
            state['cancelled'] = True
            return True
        result = ai.run(self.config(), lambda c: decision('ai_page'), execute, approve,
                        MagicMock(), MagicMock(), lambda: state['cancelled'])
        execute.assert_not_called()
        self.assertEqual(result['status'], 'cancelled')

    def test_budget_and_last_output_analysis(self):
        result = self.run_scan([decision(), decision('', '', 'stop')], config=self.config(max_steps=1))
        self.assertEqual(result['status'], 'limit_reached')
        self.assertEqual(self.execute.call_count, 1)
        self.assertEqual(self.decide.call_count, 2)
        self.assertEqual(self.decide.call_args.args[0]['available_actions'], [])

    def test_page_discovery_same_origin_and_input_values_excluded(self):
        raw = ('HTTP/1.1 200 OK\n\n<h1>Lab</h1><a href="/next">Next</a><a href="http://evil.test/">Bad</a>'
               '<form><input name=csrf value=PRIVATE><input name=password value=SECRET type=password></form>')
        result = self.run_scan([decision('ai_page'), decision('', '', 'stop')],
                               execute=MagicMock(return_value=(raw, {'status': 'completed'})))
        context = self.decide.call_args.args[0]
        self.assertIn(BASE + 'next', context['targets'].values())
        self.assertNotIn('http://evil.test/', context['targets'].values())
        encoded = json.dumps(context)
        self.assertNotIn('PRIVATE', encoded)
        self.assertNotIn('SECRET', encoded)
        self.assertIn('password', encoded)
        self.assertEqual(result['status'], 'stopped')

    def test_manual_step_requires_operator_observation_and_retriages_it(self):
        result = self.run_scan([decision('ai_manual'), decision('', '', 'stop')],
                               approve='Identifiquei um formulário sem CSRF. Cookie: secret')
        self.execute.assert_not_called()
        self.assertEqual(result['status'], 'stopped')
        obs = self.decide.call_args_list[1].args[0]['observations'][0]
        self.assertEqual(obs['tool'], 'ai_manual')
        self.assertIn('formulário sem CSRF', obs['output'])
        self.assertNotIn('secret', obs['output'])
        self.assertEqual(result['decisions'][0]['authorization'], 'operator_approved')

    def test_manual_without_observation_does_not_advance(self):
        result = self.run_scan([decision('ai_manual'), decision('', '', 'stop')], approve=True)
        self.execute.assert_not_called()
        self.assertEqual(result['decisions'][0]['outcome'], 'rejected_or_expired')
        self.assertEqual(result['observations'], [])

    def test_distinct_manual_phases_can_recur_within_step_limit(self):
        notes = iter(['Autenticação: sessão expira', 'Autorização: perfil limitado'])
        result = ai.run(self.config(max_steps=3),
                        MagicMock(side_effect=[decision('ai_manual'), decision('ai_manual'), decision('', '', 'stop')]),
                        MagicMock(), lambda action: next(notes), MagicMock(), MagicMock(), lambda: False)
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual([x['tool'] for x in result['observations']], ['ai_manual', 'ai_manual'])

    def test_redaction(self):
        text = ai.redact('Set-Cookie: session=ABC\nAuthorization: Bearer KEY\npassword=PWD\nhttps://lab.test/?token=XYZ')
        for secret in ('ABC', 'KEY', 'PWD', 'XYZ'):
            self.assertNotIn(secret, text)

    def test_approval_owner_expiry_replay_and_boolean(self):
        gate = ai.Approval('owner', {'tool': 'ai_page'})
        self.assertFalse(gate.resolve('other', gate.id, True))
        self.assertFalse(gate.resolve('owner', 'other-id', True))
        self.assertFalse(gate.resolve('owner', gate.id, 'true'))
        self.assertTrue(gate.resolve('owner', gate.id, True))
        self.assertFalse(gate.resolve('owner', gate.id, True))
        self.assertTrue(gate.wait(lambda: False))
        self.assertFalse(ai.Approval('owner', {}, timeout=0).resolve('owner', gate.id, True))
        self.assertFalse(ai.Approval('owner', {}).wait(lambda: True))

    def test_manual_gate_requires_note_and_nonmanual_gate_rejects_note(self):
        manual = ai.Approval('owner', {'tool': 'ai_manual'})
        self.assertFalse(manual.resolve('owner', manual.id, True))
        self.assertFalse(manual.resolve('owner', manual.id, True, ''))
        self.assertTrue(manual.resolve('owner', manual.id, True, 'Revisão visual concluída'))
        self.assertEqual(manual.observation, 'Revisão visual concluída')
        self.assertFalse(manual.resolve('owner', manual.id, True, 'segunda'))
        tool = ai.Approval('owner', {'tool': 'ai_headers'})
        self.assertFalse(tool.resolve('owner', tool.id, True, 'texto indevido'))
        self.assertTrue(tool.resolve('owner', tool.id, True))

    def test_concurrent_replies_only_one_consumed(self):
        gate = ai.Approval('owner', {})
        results = []
        threads = [threading.Thread(target=lambda: results.append(gate.resolve('owner', gate.id, True))) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(True), 1)

    def test_api_transport_schema_refusal_and_secret_not_argv(self):
        def transport(cmd, **kw):
            self.assertNotIn('SECRETKEY', ' '.join(cmd))
            self.assertEqual(cmd[:2], ['curl', '-q'])
            data = json.loads(Path(cmd[cmd.index('--data-binary') + 1][1:]).read_text())
            self.assertEqual(data['generationConfig']['responseFormat']['text']['mimeType'], 'application/json')
            self.assertEqual(data['generationConfig']['responseFormat']['text']['schema']['properties']['tool']['enum'][1], 'ai_headers')
            self.assertIn('x-goog-api-key: SECRETKEY', Path(cmd[cmd.index('--header') + 1][1:]).read_text())
            Path(cmd[cmd.index('--output') + 1]).write_text(json.dumps({'candidates': [
                {'finishReason': 'STOP', 'content': {'parts': [{'text': json.dumps(decision())}]}}]}))
            return subprocess.CompletedProcess(cmd, 0, '200', '')
        env = {'GEMINI_API_KEY': 'SECRETKEY', 'GEMINI_MODEL': 'gemini-model'}
        with patch.object(subprocess, 'run', side_effect=transport):
            self.assertEqual(ai.request_decision({}, environ=env), decision())
        with self.assertRaises(ValueError):
            ai.request_decision({}, environ={})

    def test_api_refusal_and_invalid_model_blocked(self):
        env = {'GEMINI_API_KEY': 'key', 'GEMINI_MODEL': 'gemini-model'}
        def transport(cmd, **kw):
            Path(cmd[cmd.index('--output') + 1]).write_text(json.dumps({'candidates': []}))
            return subprocess.CompletedProcess(cmd, 0, '200', '')
        with patch.object(subprocess, 'run', side_effect=transport):
            with self.assertRaises(ValueError):
                ai.request_decision({}, environ=env)
        with patch.object(subprocess, 'run') as launch:
            with self.assertRaises(ValueError):
                ai.request_decision({}, environ={**env, 'GEMINI_MODEL': 'http://remote.test/'})
            launch.assert_not_called()

    def test_socket_approval_and_old_checkpoint_cannot_bypass_gate(self):
        tree = ast.parse(Path('app.py').read_text(encoding='utf-8'))
        functions = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in ('on_ai_action_response', 'on_approve'):
                node.decorator_list = []
                functions.append(node)
        gate = ai.Approval('owner', {'tool': 'ai_ports', 'target': BASE})
        scan = {'sid': 'owner', 'ai_config': self.config(), 'ai_approval': gate}
        ns = {'active_scans': {'scan': scan}, 'request': SimpleNamespace(sid='other'),
              'emit': MagicMock(), 'threading': MagicMock()}
        exec(compile(ast.Module(body=functions, type_ignores=[]), 'app.py', 'exec'), ns)
        answer = {'scan_id': 'scan', 'proposal_id': gate.id, 'approved': True,
                  'tool': 'sqlmap', 'target': 'http://evil.test/'}
        ns['on_ai_action_response'](answer)
        self.assertFalse(gate.event.is_set())
        ns['request'].sid = 'owner'
        ns['on_approve']({'scan_id': 'scan', 'approved_targets': [BASE]})
        ns['threading'].Thread.assert_not_called()
        self.assertFalse(gate.event.is_set())
        ns['on_ai_action_response'](answer)
        self.assertTrue(gate.event.is_set())
        self.assertEqual(gate.action, {'tool': 'ai_ports', 'target': BASE})
        ns['emit'].reset_mock()
        ns['on_ai_action_response'](answer)
        ns['emit'].assert_called_once()

    def test_app_worker_gates_executes_and_persists_report(self):
        tree = ast.parse(Path('app.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'run_ai_pipeline')
        scan = {'ai_config': self.config(), 'target': BASE, 'sid': 'owner', 'cancelled': False}
        with tempfile.TemporaryDirectory() as work:
            ns = {'active_scans': {'scan': scan}, 'ai_pipeline': ai, 'json': json,
                  'active_proxy': {'profile': 'none'}, '_proxy_url_if_alive': MagicMock(),
                  '_scan_output_dir': lambda s: Path(work), 'scoped_url': ai.scoped_url,
                  '_finish': MagicMock(), 'db_finish_scan': MagicMock()}
            def socket_emit(event, data, room):
                self.assertEqual(room, 'owner')
                if event == 'ai_approval_required':
                    self.assertIn(data['tool'], ('ai_headers', 'ai_ports'))
                    self.assertTrue(scan['ai_approval'].resolve('owner', data['proposal_id'], True))
            ns['socketio'] = SimpleNamespace(emit=MagicMock(side_effect=socket_emit))
            def execute(scan_id, tool, target, sid, outcome):
                outcome.update(status='completed')
                return 'Server: lab', []
            ns['run_tool_sequential'] = MagicMock(side_effect=execute)
            exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
            with patch.object(ai, 'request_decision', side_effect=[decision(), decision('ai_ports'), decision('', '', 'stop')]):
                ns['run_ai_pipeline']('scan', 'owner')
            self.assertEqual(ns['run_tool_sequential'].call_count, 2)
            self.assertNotIn('ai_approval', scan)
            report = json.loads(Path(work, 'ai_report.json').read_text(encoding='utf-8'))
            self.assertEqual(report['status'], 'stopped')
            self.assertEqual(report['decisions'][1]['authorization'], 'operator_approved')
            self.assertEqual(scan['status'], 'done')
            ns['_finish'].assert_called_once()

    def test_real_templates_no_redirects_no_nse_and_proxy_flags(self):
        ns = load_helpers()
        tree = ast.parse(Path('app.py').read_text(encoding='utf-8'))
        node = next(n for n in tree.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                    and isinstance(n.value.func, ast.Attribute) and isinstance(n.value.func.value, ast.Name)
                    and n.value.func.value.id == 'TOOLS' and n.value.func.attr == 'update')
        ns['ai_pipeline'] = ai
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'app.py', 'exec'), ns)
        ns['check_proxy_alive'] = MagicMock(return_value=True)
        for key in ('ai_headers', 'ai_page'):
            cmd, target = ns['build_cmd'](key, BASE + 'login', {'profile': 'burp', 'http': 'http://127.0.0.1:8080'})
            self.assertNotIn('-L', cmd)
            self.assertEqual(cmd[:2], ['curl', '-q'])
            self.assertNotIn('--', cmd)
            self.assertIn('-x', cmd)
            self.assertEqual(target, BASE + 'login')
        cmd, target = ns['build_cmd']('ai_ports', BASE, {'profile': 'none'})
        self.assertEqual(target, 'lab.test')
        self.assertNotIn('-sC', cmd)
        self.assertNotIn('-sV', cmd)
        self.assertEqual(ns['build_cmd']('ai_ports', BASE, {'profile': 'burp', 'http': 'http://127.0.0.1:8080'})[0], None)


if __name__ == '__main__':
    unittest.main()
