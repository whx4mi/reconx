import sqlite3
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_RESULTS = tempfile.TemporaryDirectory()
os.environ['RECONX_RESULTS'] = _RESULTS.name
import app as reconx


class PipelineResilienceTests(unittest.TestCase):
    def test_dalfox_verified_poc_exit_one_is_success_but_usage_error_is_not(self):
        self.assertTrue(reconx.tool_execution_succeeded(
            'dalfox_url', 1, '[POC][V][GET][inHTML] http://lab.test/?q=x'))
        self.assertFalse(reconx.tool_execution_succeeded(
            'dalfox_url', 2, 'Usage: dalfox url --url <URL>'))
        self.assertFalse(reconx.tool_execution_succeeded(
            'dalfox_url', 1, '[POC][R][GET][inHTML] reflected only'))

    def test_dalfox_parser_keeps_verified_candidate_only(self):
        raw = ('[POC][V][GET][inHTML] http://lab.test/?q=verified\n'
               '  Issue: XSS payload DOM object identified\n'
               '[POC][R][GET][inHTML] http://lab.test/?q=reflection')
        _, findings = reconx.parse_output('dalfox_url', raw)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'high')
        self.assertEqual(findings[0]['confidence'], 'likely')
        self.assertIn('verified', findings[0]['target'])

    def test_browser_execution_promotes_dalfox_candidate_to_confirmed(self):
        finding = {'ftype': 'xss', 'target': 'http://lab.test/?q=payload',
                   'name': 'candidate', 'confidence': 'likely', 'evidence': 'dalfox'}
        working = 'http://lab.test/?q=working'
        with patch.object(reconx, 'browser_validate_xss', return_value=working):
            result = reconx.validate_dalfox_findings([finding])[0]
        self.assertEqual(result['confidence'], 'confirmed')
        self.assertEqual(result['target'], working)
        self.assertIn('Chromium', result['name'])

    def test_paths_are_resolved_below_app_and_host_changes_require_review(self):
        base = 'http://lab.test/app/'
        pivots = reconx.normalize_pivots(base, [
            {'type': 'path', 'value': '/ping.php', 'label': '/ping.php'},
            {'type': 'url', 'value': 'http://other.test/', 'label': 'other'},
        ])
        self.assertEqual(pivots[0]['value'], 'http://lab.test/app/ping.php')
        self.assertFalse(reconx.pivot_expands_host(base, pivots[:1]))
        self.assertTrue(reconx.pivot_expands_host(base, pivots))

    def test_web_tools_keep_application_path_while_port_tools_receive_host(self):
        targets = ['http://lab.test/app/', 'lab.test']
        self.assertEqual(
            reconx.targets_for_tool('nikto', targets),
            ['http://lab.test/app/'])
        self.assertEqual(reconx.targets_for_tool('nmap_quick', targets), ['lab.test'])
        self.assertEqual(reconx.targets_for_tool('gau', ['http://192.0.2.10/app/']), [])
        cmd, effective = reconx.build_cmd('curl_headers', 'http://lab.test/app/')
        self.assertEqual(effective, 'http://lab.test/app/')
        self.assertIn('http://lab.test/app/', cmd)
        ffuf, _ = reconx.build_cmd('ffuf_dirs', 'http://lab.test/app/')
        self.assertIn('http://lab.test/app/FUZZ', ffuf)

    def test_full_pentest_includes_parameter_aware_dast(self):
        tools = next(stage['tools'] for stage in reconx.PIPELINES['full_pentest']['stages']
                     if stage['id'] == 's4')
        self.assertIn('nuclei_dast', tools)

    def test_pipeline_keeps_seed_and_rejects_documented_filesystem_paths(self):
        base = 'http://lab.test/app/'
        pivots = reconx.normalize_pivots(base, [
            {'type': 'url', 'value': 'http://lab.test/var/www/html/index.html', 'label': 'bad'},
            {'type': 'path', 'value': '/ping.php', 'label': 'good'},
        ])
        self.assertEqual([p['value'] for p in pivots], ['http://lab.test/app/ping.php'])
        merged = reconx.merge_pipeline_targets(base, [base, 'lab.test'], pivots)
        self.assertEqual(merged, [base, 'lab.test', 'http://lab.test/app/ping.php'])

    def test_python_httpx_cli_is_not_accepted_as_projectdiscovery_httpx(self):
        with patch.object(reconx.shutil, 'which', return_value='/usr/bin/httpx'), \
                patch.object(reconx.os.path, 'isfile', return_value=True), \
                patch.object(reconx.os, 'access', return_value=True), \
                patch.object(reconx, '_projectdiscovery_httpx', return_value=False):
            self.assertIsNone(reconx.resolve_binary('httpx'))

    def test_readonly_database_returns_socket_error_without_ghost_scan(self):
        client = reconx.socketio.test_client(reconx.app)
        before = set(reconx.active_scans)
        payload = {
            'target': 'http://lab.test/',
            'pipeline_key': 'custom',
            'intensity': 'full',
            'custom_stages': [{'id': 'one', 'name': 'one', 'phase': 'recon', 'tools': []}],
        }
        with patch.object(reconx, 'db_create_scan', side_effect=sqlite3.OperationalError('readonly')):
            client.emit('start_pipeline', payload)
        events = client.get_received()
        errors = [item['args'][0] for item in events if item['name'] == 'error']
        self.assertEqual(set(reconx.active_scans), before)
        self.assertEqual(len(errors), 1)
        self.assertIn('RECONX_RESULTS', errors[0]['message'])
        client.disconnect()

    def test_worker_exception_emits_error_and_terminal_completion(self):
        scan_id = 'guarded-test'
        reconx.active_scans[scan_id] = {'processes': {}, 'status': 'running'}
        emitter = MagicMock()
        try:
            with patch.object(reconx, 'run_pipeline', side_effect=RuntimeError('boom')), \
                    patch.object(reconx, 'db_finish_scan') as finish, \
                    patch.object(reconx.socketio, 'emit', emitter):
                reconx.run_pipeline_guarded(scan_id, {}, 'http://lab.test/', None, 'sid')
            self.assertEqual(reconx.active_scans[scan_id]['status'], 'failed')
            finish.assert_called_once_with(scan_id, 'failed')
            events = [call.args[0] for call in emitter.call_args_list]
            self.assertEqual(events, ['pipeline_error', 'pipeline_complete'])
            self.assertEqual(emitter.call_args_list[-1].args[1]['status'], 'failed')
        finally:
            reconx.active_scans.pop(scan_id, None)


if __name__ == '__main__':
    unittest.main()
