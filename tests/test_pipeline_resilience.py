import sqlite3
import os
import tempfile
import unittest
import uuid
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

    def test_active_scanners_receive_only_compatible_web_targets(self):
        targets = [
            'http://lab.test/app/',
            'http://lab.test/app/ping.php',
            'http://lab.test/app/main.js',
            'http://lab.test/app/redirect.php?r=https://example.test',
        ]
        self.assertEqual(reconx.targets_for_tool('nikto', targets), [targets[0]])
        self.assertEqual(reconx.targets_for_tool('sqlmap', targets), [targets[0]])
        self.assertEqual(reconx.targets_for_tool('commix', targets), [targets[3]])
        self.assertEqual(reconx.targets_for_tool('nuclei_dast', targets), [targets[3]])
        self.assertNotIn(targets[2], reconx.targets_for_tool('nuclei_cves', targets))

    def test_commix_operational_critical_is_not_a_finding(self):
        raw = "[critical] No parameter(s) found for testing in the provided data"
        _, findings = reconx.parse_output('commix', raw, 'http://lab.test/app/')
        self.assertEqual(findings, [])

    def test_injection_parsers_require_explicit_positive_evidence(self):
        sqlmap_noise = '''sqlmap identified the target form\n[INFO] testing SQL injection
[CRITICAL] there were no forms found at the given target URL'''
        commix_noise = '''Automated All-in-One OS Command Injection Exploitation Tool
[info] Performing heuristic (passive) tests on the target URL.'''
        self.assertEqual(reconx.parse_output('sqlmap', sqlmap_noise, 'http://lab.test/')[1], [])
        self.assertEqual(reconx.parse_output('commix', commix_noise, 'http://lab.test/')[1], [])

        sqlmap_positive = "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable"
        commix_positive = "[info] The POST parameter 'd' appears to be injectable via classic injection"
        self.assertEqual(len(reconx.parse_output('sqlmap_url', sqlmap_positive, 'http://lab.test/')[1]), 1)
        self.assertEqual(len(reconx.parse_output('commix', commix_positive, 'http://lab.test/')[1]), 1)

    def test_nikto_keeps_checks_but_not_metadata_or_false_positive_warning(self):
        raw = '''+ Platform: Linux/Unix
+ Server: Apache/2.4.66 (Ubuntu)
+ [999967] /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ [750510] /phpinfo.php: Output from the phpinfo() function was found.'''
        _, findings = reconx.parse_output('nikto', raw, 'http://lab.test/')
        self.assertEqual(len(findings), 1)
        self.assertIn('phpinfo.php', findings[0]['name'])

    def test_nuclei_redirect_and_phpinfo_use_response_evidence(self):
        redirect = {
            'template-id': 'open-redirect',
            'info': {'name': 'Open Redirect Detection', 'severity': 'medium'},
            'matched-at': 'http://lab.test/app/go.php?r=https://oast.me',
            'response': 'HTTP/1.1 302 Found\r\nLocation: https://oast.me\r\n\r\n',
        }
        _, findings = reconx.parse_output('nuclei_dast', __import__('json').dumps(redirect))
        self.assertEqual(findings[0]['confidence'], 'confirmed')
        self.assertEqual(findings[0]['ftype'], 'open_redirect')
        self.assertTrue(findings[0]['target'].startswith('http://lab.test/app/'))

        phpinfo = {
            'template-id': 'phpinfo-files',
            'info': {'name': 'PHPinfo Page - Detect', 'severity': 'low'},
            'matched-at': 'http://lab.test/app/phpinfo.php',
            'response': 'HTTP/1.1 200 OK\r\n\r\n<h1>PHP Version 8.4</h1>',
        }
        _, findings = reconx.parse_output('nuclei_misconfig', __import__('json').dumps(phpinfo))
        self.assertEqual(findings[0]['confidence'], 'confirmed')
        self.assertEqual(findings[0]['name'], 'PHPInfo exposto publicamente')

    def test_product_specific_cve_without_fingerprint_stays_generic_candidate(self):
        record = {
            'template-id': 'CVE-2022-3766',
            'info': {'name': 'phpMyFAQ Cross-Site Scripting', 'severity': 'medium'},
            'matched-at': 'http://lab.test/app/?q=%3Csvg%20onload=alert(1)%3E',
            'response': 'HTTP/1.1 200 OK\r\n\r\n<div><svg onload=alert(1)></div>',
        }
        _, findings = reconx.parse_output('nuclei_dast', __import__('json').dumps(record))
        self.assertEqual(findings[0]['confidence'], 'possible')
        self.assertEqual(findings[0]['ftype'], 'xss')
        self.assertNotIn('phpMyFAQ Cross-Site Scripting', findings[0]['name'])
        self.assertIn('Fingerprint phpMyFAQ ausente', findings[0]['evidence'])

    def test_duplicate_xss_is_upgraded_instead_of_counted_twice(self):
        scan_id = f'dedup-{uuid.uuid4().hex}'
        reconx.db_create_scan(scan_id, 'http://lab.test/app/', 'full_pentest', '')
        first = reconx.db_add_finding(
            scan_id, 'nuclei_dast', 'xss', 'XSS candidate', 'medium',
            'http://lab.test/app/index.php?search=%3Csvg%20onload%3Dalert(1)%3E',
            'reflection', 'possible')
        upgraded = reconx.db_add_finding(
            scan_id, 'dalfox_url', 'xss', 'XSS confirmado no Chromium', 'high',
            'http://lab.test/app/?search=%3Csvg%20onload%3Dalert(1)%3E',
            'browser marker', 'confirmed')
        findings = reconx.db_findings(scan_id)
        self.assertTrue(first[0])
        self.assertTrue(upgraded[0])
        self.assertEqual(first[1], upgraded[1])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['confidence'], 'confirmed')
        self.assertEqual(findings[0]['tool'], 'dalfox_url')

    def test_xss_manual_verifier_requires_browser_execution(self):
        finding = {'name': 'XSS candidate', 'ftype': 'xss', 'tool': 'dalfox',
                   'target': 'http://lab.test/?q=x', 'evidence': '', 'confidence': 'likely'}
        output = '[POC][V][GET][inHTML] http://lab.test/?q=%3Csvg%20onload=alert(1)%3E'
        completed = MagicMock(stdout=output, stderr='', returncode=1)
        with patch.object(reconx.shutil, 'which', return_value='/usr/bin/dalfox'), \
                patch.object(reconx.subprocess, 'run', return_value=completed), \
                patch.object(reconx, 'browser_validate_xss', return_value=None):
            result = reconx.run_verification(finding)
        self.assertFalse(result['verified'])
        self.assertEqual(result['confidence'], 'likely')

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
