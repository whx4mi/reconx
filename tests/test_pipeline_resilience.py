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
    def test_operator_phase_model_separates_recon_discovery_and_assessment(self):
        prepared = reconx.pipelines_for_ui()['full_pentest']['stages']
        self.assertEqual(prepared[0]['operational_phase'], 'recon')
        self.assertEqual(prepared[1]['operational_phase'], 'discovery')
        self.assertEqual(prepared[-1]['operational_phase'], 'assessment')
        self.assertEqual(reconx.operational_phase_for_stage(
            {'phase': 'recon', 'operational_phase': 'discovery'}, 0), 'discovery')
        self.assertEqual(
            [reconx.OPERATIONAL_PHASES[key]['order'] for key in
             ('recon', 'discovery', 'assessment', 'validation', 'reporting')],
            [1, 2, 3, 4, 5],
        )

    def test_database_context_closes_connection(self):
        with reconx._db() as connection:
            connection.execute('SELECT 1').fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute('SELECT 1')

    def test_stage_ledger_schema_adds_finding_count_to_existing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'legacy.db')
            connection = sqlite3.connect(path)
            connection.executescript('''
                CREATE TABLE scans (
                    scan_id TEXT PRIMARY KEY, target TEXT, pipeline TEXT, proxy TEXT,
                    status TEXT, started_at TEXT, finished_at TEXT,
                    scope_json TEXT DEFAULT '{}', profile TEXT DEFAULT 'standard'
                );
                CREATE TABLE stage_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
                    stage_id TEXT NOT NULL, stage_name TEXT NOT NULL,
                    operational_phase TEXT NOT NULL, status TEXT NOT NULL,
                    input_count INTEGER DEFAULT 0, output_count INTEGER DEFAULT 0,
                    detail TEXT, started_at TEXT, finished_at TEXT,
                    UNIQUE(scan_id, stage_id)
                );
            ''')
            connection.close()
            original = reconx.DB_PATH
            try:
                reconx.DB_PATH = __import__('pathlib').Path(path)
                reconx.db_init()
                with reconx._db() as migrated:
                    columns = {row['name'] for row in
                               migrated.execute('PRAGMA table_info(stage_runs)')}
                self.assertIn('finding_count', columns)
            finally:
                reconx.DB_PATH = original

    def test_startup_reconciles_orphaned_running_scans(self):
        orphan = f'orphan-{uuid.uuid4().hex}'
        completed = f'done-{uuid.uuid4().hex}'
        try:
            reconx.db_reconcile_orphaned_scans()
            reconx.db_create_scan(orphan, 'http://lab.test/app/', 'test', 'none')
            reconx.db_create_scan(completed, 'http://lab.test/app/', 'test', 'none')
            reconx.db_finish_scan(completed, 'done')

            self.assertEqual(reconx.db_reconcile_orphaned_scans(), 1)
            with reconx._db() as connection:
                rows = {
                    row['scan_id']: dict(row)
                    for row in connection.execute(
                        'SELECT scan_id,status,finished_at FROM scans '
                        'WHERE scan_id IN (?,?)', (orphan, completed))
                }
            self.assertEqual(rows[orphan]['status'], 'failed')
            self.assertIsNotNone(rows[orphan]['finished_at'])
            self.assertEqual(rows[completed]['status'], 'done')
        finally:
            with reconx._db() as connection:
                connection.execute(
                    'DELETE FROM scans WHERE scan_id IN (?,?)',
                    (orphan, completed),
                )

    def test_operational_ledger_accounts_for_skipped_tool_and_discovery(self):
        scan_id = f'ledger-{uuid.uuid4().hex}'
        reconx.db_create_scan(scan_id, 'http://lab.test/app/', 'custom', 'none')
        reconx.active_scans[scan_id] = {
            'target': 'http://lab.test/app/', 'processes': {}, 'cancelled': False,
        }
        stage = {'id': 'inventory', 'name': 'Inventário', 'phase': 'recon',
                 'operational_phase': 'recon', 'tools': ['tool_that_does_not_exist']}
        try:
            with patch.object(reconx.time, 'sleep'):
                reconx.run_stage(scan_id, stage, ['http://lab.test/app/'], 'sid')
            reconx.db_record_discoveries(scan_id, 'inventory', [
                {'type': 'url', 'value': 'http://lab.test/app/admin'},
            ])
            reconx.db_dispose_discoveries(
                scan_id, ['http://lab.test/app/admin'], 'consumed', 'teste')
            ledger = reconx.db_operational_ledger(scan_id)
            self.assertEqual(ledger['stages'][0]['status'], 'failed')
            self.assertEqual(ledger['tool_runs'][0]['status'], 'skipped')
            self.assertIn('não existe', ledger['tool_runs'][0]['reason'].lower())
            self.assertEqual(ledger['discoveries'][0]['disposition'], 'consumed')
            self.assertEqual(ledger['summary']['tools']['skipped'], 1)
        finally:
            reconx.active_scans.pop(scan_id, None)
            with reconx._db_lock, reconx._db() as connection:
                for table in ('coverage_items', 'discovery_items', 'tool_runs',
                              'stage_runs', 'scans'):
                    connection.execute(f'DELETE FROM {table} WHERE scan_id=?', (scan_id,))

    def test_stage_ledger_separates_new_findings_from_extracted_targets(self):
        scan_id = f'stage-findings-{uuid.uuid4().hex}'
        reconx.db_create_scan(scan_id, 'http://lab.test/app/', 'custom', 'none',
                              {'in_scope': ['lab.test'], 'out_of_scope': []})
        reconx.active_scans[scan_id] = {
            'target': 'http://lab.test/app/',
            'scope_policy': {'in_scope': ['lab.test'], 'out_of_scope': []},
            'processes': {}, 'cancelled': False,
        }
        tool_key = f'test_finding_{uuid.uuid4().hex}'
        reconx.TOOLS[tool_key] = {
            'label': 'Test finding', 'phase': 'test', 'input': 'url',
            'output': 'raw', 'manual_followup': [],
        }
        stage = {'id': 'assessment', 'name': 'Assessment', 'phase': 'test',
                 'operational_phase': 'assessment', 'tools': [tool_key]}
        finding = reconx._finding(tool_key, 'vuln', 'Candidate', 'medium',
                                  'http://lab.test/app/', 'local fixture', 'possible')

        def fake_run(scan, tool, target, sid, outcome=None):
            outcome.update(status='completed', exit_code=0, timed_out=False)
            reconx.persist_and_emit_findings(scan, [], [finding], sid)
            return 'raw', []

        try:
            with patch.object(reconx.time, 'sleep'), \
                    patch.object(reconx, 'run_tool_sequential', side_effect=fake_run):
                reconx.run_stage(scan_id, stage, ['http://lab.test/app/'], 'sid')
            row = reconx.db_operational_ledger(scan_id)['stages'][0]
            self.assertEqual(row['output_count'], 0)
            self.assertEqual(row['finding_count'], 1)
        finally:
            reconx.TOOLS.pop(tool_key, None)
            reconx.active_scans.pop(scan_id, None)
            with reconx._db_lock, reconx._db() as connection:
                for table in ('findings', 'coverage_items', 'discovery_items',
                              'tool_runs', 'stage_runs', 'scans'):
                    connection.execute(f'DELETE FROM {table} WHERE scan_id=?', (scan_id,))

    def test_validation_queue_excludes_informational_inventory(self):
        self.assertEqual(reconx.validation_candidate_count({'severity': {
            'critical': 0, 'high': 0, 'medium': 1, 'low': 0,
            'info': 10, 'unknown': 2,
        }}), 3)

    def test_web_scanner_presets_are_http_only_and_do_not_try_default_logins(self):
        for key in ('nuclei_cves', 'nuclei_misconfig'):
            command, _ = reconx.build_cmd(key, 'http://lab.test/app/')
            self.assertIn('-pt', command, key)
            self.assertEqual(command[command.index('-pt') + 1], 'http')
        misconfig, _ = reconx.build_cmd('nuclei_misconfig', 'http://lab.test/app/')
        self.assertEqual(misconfig[misconfig.index('-tags') + 1], 'misconfig,exposure')
        self.assertNotIn('default-login', misconfig)
        self.assertFalse(any('brute force' in tip.lower() or
                             'credential stuffing' in tip.lower()
                             for tip in reconx.TOOLS['nuclei_misconfig']['manual_followup']))

    def test_ffuf_extension_scan_uses_a_bounded_curated_wordlist(self):
        command, _ = reconx.build_cmd('ffuf_ext', 'http://lab.test/app/')
        wordlist = command[command.index('-w') + 1]
        with open(wordlist, encoding='utf-8') as stream:
            words = [line.strip() for line in stream if line.strip() and not line.startswith('#')]
        extensions = command[command.index('-e') + 1].split(',')
        self.assertLessEqual(len(words) * len(extensions), 1000)
        self.assertEqual(command[command.index('-rate') + 1], '5')

    def test_ledger_api_returns_all_five_operator_phases(self):
        scan_id = f'ledger-api-{uuid.uuid4().hex}'
        reconx.db_create_scan(scan_id, 'http://lab.test/app/', 'custom', 'none')
        try:
            response = reconx.app.test_client().get(f'/api/scan/{scan_id}/ledger')
            self.assertEqual(response.status_code, 200)
            self.assertEqual([item['phase'] for item in response.get_json()['coverage']],
                             ['recon', 'discovery', 'assessment', 'validation', 'reporting'])
        finally:
            with reconx._db_lock, reconx._db() as connection:
                connection.execute('DELETE FROM coverage_items WHERE scan_id=?', (scan_id,))
                connection.execute('DELETE FROM scans WHERE scan_id=?', (scan_id,))

    def test_runtime_temp_directory_lives_beside_results(self):
        self.assertEqual(reconx.RUNTIME_TMP_DIR, reconx.RESULTS_DIR / '.tmp')
        self.assertEqual(tempfile.gettempdir(), str(reconx.RUNTIME_TMP_DIR))
        self.assertEqual(reconx.proxy_env('curl', {})['TMPDIR'],
                         str(reconx.RUNTIME_TMP_DIR))

    def test_reports_render_reverse_engineering_map_and_escape_html(self):
        data = {
            'target': 'http://lab.test/app/', 'scan_id': 'map-test',
            'results': {}, 'adaptive_report': {
                'page_details': [{'url': 'http://lab.test/app/',
                                  'content_type': '', 'content_type_inferred': True}],
                'scope': {'base_path': '/app/', 'allowed_path_prefixes': ['/api/'],
                          'outside_base_behavior': 'inventory_only'},
                'resources': [{'url': 'http://lab.test/app/manual.pdf',
                               'kind': 'document', 'scope': 'in_scope',
                               'navigable': True, 'sources': ['http://lab.test/app/']}],
                'reverse_engineering': {
                'summary': {'scripts_analyzed': 2, 'source_maps': 1,
                            'endpoints': 1, 'in_scope_endpoints': 1},
                'frameworks': ['React<script>'],
                'graphql_operations': [{'type': 'query', 'name': 'Viewer'}],
                'signals': {'authorization': ['tenantId']},
                'endpoints': [{'method': 'POST', 'url': 'http://lab.test/api?a=<x>',
                               'kind': 'http', 'in_scope': True,
                               'sources': ['http://lab.test/app.js']}],
                'source_maps': [{'url': 'http://lab.test/app.js.map', 'source_count': 4,
                                 'sources': ['src/services/User.ts']}],
                'external_scripts': ['https://cdn.example/vendor.js'],
                'limitations': ['Analise estatica < runtime'],
            }}
        }
        markdown = reconx.build_markdown_report(data)
        html = reconx.build_html_report(data)
        self.assertIn('Mapa estático da aplicação', markdown)
        self.assertIn('Inventário da superfície HTML', markdown)
        self.assertIn('manual.pdf', markdown)
        self.assertIn('Escopo de aplicação: `/app/`', markdown)
        self.assertIn('POST', markdown)
        self.assertIn('app.js.map', markdown)
        self.assertIn('query Viewer', markdown)
        self.assertIn('tenantId', markdown)
        self.assertIn('Mapa estatico da aplicacao', html)
        self.assertIn('Inventario da superficie HTML', html)
        self.assertIn('manual.pdf', html)
        self.assertIn('Base autorizada: <b>/app/</b>', html)
        self.assertIn('http://lab.test/api?a=&lt;x&gt;', html)
        self.assertIn('React&lt;script&gt;', html)
        self.assertIn('src/services/User.ts', html)
        self.assertIn('https://cdn.example/vendor.js', html)
        self.assertNotIn('React<script>', html)

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
        self.assertTrue(reconx.pivot_expands_host(base, [
            {'type': 'url', 'value': 'http://lab.test/admin', 'label': 'admin'}]))

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
        self.assertEqual(ffuf[ffuf.index('-rate') + 1], '5')
        self.assertEqual(ffuf[ffuf.index('-t') + 1], '5')
        self.assertNotIn('-recursion', ffuf)

    def test_uncover_uses_precise_shodan_query_and_parses_plain_or_json_hosts(self):
        command, effective = reconx.build_cmd('uncover', 'https://example.test/app/')
        self.assertEqual(effective, 'example.test')
        self.assertEqual(command[command.index('-e') + 1], 'shodan')
        self.assertEqual(command[command.index('-q') + 1], 'domain:example.test')
        self.assertNotIn('SHODAN_API_KEY', ' '.join(command))
        plain = reconx.extract_targets('uncover', '192.0.2.10:443\nhost.example.test:8443')
        structured = reconx.extract_targets(
            'uncover', '{"ip":"192.0.2.20","ports":[80,443]}')
        self.assertEqual([item['value'] for item in plain],
                         ['192.0.2.10:443', 'host.example.test:8443'])
        self.assertEqual([item['value'] for item in structured],
                         ['192.0.2.20:80', '192.0.2.20:443'])

    def test_web_scanners_do_not_follow_redirects_and_gobuster_flag_is_current(self):
        for tool in ('sqlmap', 'sqlmap_url', 'commix'):
            cmd, _ = reconx.build_cmd(tool, 'http://lab.test/app/?next=https://outside.test')
            self.assertEqual(cmd.count('--ignore-redirects'), 1, tool)

        commix, _ = reconx.build_cmd('commix', 'http://lab.test/app/?d=x')
        self.assertIn('--ignore-stdin', commix)
        self.assertIn('--ignore-session', commix)
        self.assertIn('--answers=follow=N,spawn=N', commix)

        dalfox, _ = reconx.build_cmd('dalfox', 'http://lab.test/app/?q=x')
        self.assertNotIn('--follow-redirects', dalfox)

        headers, _ = reconx.build_cmd('curl_headers', 'http://lab.test/app/')
        self.assertNotIn('-L', headers)
        self.assertEqual(headers[headers.index('--max-redirs') + 1], '0')

        whatweb, _ = reconx.build_cmd('whatweb', 'http://lab.test/app/')
        self.assertIn('--max-redirects=0', whatweb)

        gobuster, _ = reconx.build_cmd('gobuster_dir', 'http://lab.test/app/')
        self.assertIn('--useragent', gobuster)
        self.assertNotIn('--user-agent', gobuster)

        for tool in ('nuclei_cves', 'nuclei_misconfig', 'nuclei_tech',
                     'nuclei_takeover', 'nuclei_dast', 'nuclei_secrets'):
            cmd, _ = reconx.build_cmd(tool, 'http://lab.test/app/?q=x')
            self.assertIn('-dr', cmd, tool)

    def test_out_of_scope_scanner_finding_is_not_persisted(self):
        scan_id = f'scope-{uuid.uuid4().hex}'
        reconx.active_scans[scan_id] = {'target': 'http://lab.test/app/'}
        finding = reconx._finding('nuclei_misconfig', 'vuln', 'External match',
                                  'info', 'https://outside.test/', 'redirected')
        try:
            count = reconx.persist_and_emit_findings(scan_id, [], [finding], 'sid')
            self.assertEqual(count, 0)
            self.assertEqual(reconx.db_findings(scan_id), [])
        finally:
            reconx.active_scans.pop(scan_id, None)

    def test_same_origin_finding_outside_base_requires_approved_pivot(self):
        scan_id = f'scope-{uuid.uuid4().hex}'
        base = 'http://lab.test/app/'
        target = 'http://lab.test/admin?q=x'
        reconx.active_scans[scan_id] = {
            'target': base, 'approved_scope_targets': [base]}
        finding = reconx._finding('nuclei_misconfig', 'vuln', 'Outside base',
                                  'info', target, 'same origin')
        try:
            self.assertEqual(
                reconx.persist_and_emit_findings(scan_id, [], [finding], 'sid'), 0)
            reconx.active_scans[scan_id]['approved_scope_targets'].append(
                'http://lab.test/admin')
            self.assertEqual(
                reconx.persist_and_emit_findings(scan_id, [], [finding], 'sid'), 1)
        finally:
            with reconx._db() as connection:
                connection.execute('DELETE FROM findings WHERE scan_id=?', (scan_id,))
            reconx.active_scans.pop(scan_id, None)

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

    def test_dalfox_only_receives_parameterized_urls(self):
        targets = ['http://lab.test/', 'http://lab.test/fra.php?',
                   'http://lab.test/search.php?q=term', 'http://lab.test/view.php?id=']
        expected = ['http://lab.test/search.php?q=term', 'http://lab.test/view.php?id=']
        self.assertEqual(reconx.targets_for_tool('dalfox', targets), expected)
        self.assertEqual(reconx.targets_for_tool('dalfox_url', targets), expected)

    def test_commix_operational_critical_is_not_a_finding(self):
        raw = "[critical] No parameter(s) found for testing in the provided data"
        _, findings = reconx.parse_output('commix', raw, 'http://lab.test/app/')
        self.assertEqual(findings, [])

    def test_command_injection_is_not_misrouted_to_sqlmap_verifier(self):
        finding = reconx._finding('commix', 'cmdi',
            "POST parameter 'd' appears to be injectable", 'high',
            'http://lab.test/ping.php', 'time-based command injection', 'likely')
        self.assertIsNone(reconx.match_verifier(finding))

    def test_injection_parsers_require_explicit_positive_evidence(self):
        sqlmap_noise = '''sqlmap identified the target form\n[INFO] testing SQL injection
[CRITICAL] there were no forms found at the given target URL'''
        commix_noise = '''Automated All-in-One OS Command Injection Exploitation Tool
[info] Performing heuristic (passive) tests on the target URL.'''
        self.assertEqual(reconx.parse_output('sqlmap', sqlmap_noise, 'http://lab.test/')[1], [])
        self.assertEqual(reconx.parse_output('commix', commix_noise, 'http://lab.test/')[1], [])

        sqlmap_positive = "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable"
        commix_positive = "[info] The POST parameter 'd' appears to be injectable via classic injection"
        sqlmap_finding = reconx.parse_output('sqlmap_url', sqlmap_positive, 'http://lab.test/')[1]
        commix_finding = reconx.parse_output('commix', commix_positive, 'http://lab.test/')[1]
        self.assertEqual(len(sqlmap_finding), 1)
        self.assertEqual(len(commix_finding), 1)
        self.assertEqual(sqlmap_finding[0]['confidence'], 'likely')
        self.assertEqual(commix_finding[0]['confidence'], 'likely')

    def test_sqlmap_no_forms_is_a_coverage_gap_not_an_execution_failure(self):
        raw = '[CRITICAL] there were no forms found at the given target URL'
        issue = reconx.tool_output_quality_issue('sqlmap', raw)
        self.assertIn('sem encontrar formulários', issue)
        self.assertEqual(reconx.parse_output('sqlmap', raw, 'http://lab.test/'), ([], []))

    def test_root_cause_dedup_preserves_strongest_severity_and_confidence(self):
        scan_id = f'dedup-{uuid.uuid4().hex}'
        reconx.db_create_scan(scan_id, 'http://lab.test/app/', 'test', 'none')
        first = reconx._finding('curl_headers', 'headers',
            'Security headers ausentes: Content-Security-Policy', 'low',
            'http://lab.test/app/', 'curl', 'possible')
        second = reconx._finding('nuclei_misconfig', 'vuln',
            'HTTP Missing Security Headers', 'info',
            'http://lab.test/app/login.php', 'nuclei', 'likely')
        phpinfo_a = reconx._finding('nikto', 'nikto',
            '+ [002989] /app/phpinfo.php: phpinfo() was found', 'info',
            'http://lab.test/app', 'nikto', 'possible')
        phpinfo_b = reconx._finding('nuclei_misconfig', 'info',
            'PHPInfo exposto publicamente', 'low',
            'http://lab.test/app//phpinfo.php', 'nuclei', 'confirmed')
        try:
            reconx.persist_and_emit_findings(scan_id, [], [first, second, phpinfo_a, phpinfo_b], 'sid')
            findings = reconx.db_findings(scan_id)
            self.assertEqual(len(findings), 2)
            headers = next(item for item in findings if 'Headers' in item['name'])
            phpinfo = next(item for item in findings if 'PHPInfo' in item['name'])
            self.assertEqual((headers['severity'], headers['confidence']), ('low', 'likely'))
            self.assertEqual((phpinfo['severity'], phpinfo['confidence']), ('low', 'confirmed'))
        finally:
            with reconx._db_lock, reconx._db() as connection:
                connection.execute('DELETE FROM findings WHERE scan_id=?', (scan_id,))
                connection.execute('DELETE FROM scans WHERE scan_id=?', (scan_id,))

    def test_finding_identity_normalizes_trailing_and_repeated_slashes(self):
        a = reconx._finding_identity('nikto', 'nikto', 'same', 'http://LAB.test/app/')
        b = reconx._finding_identity('nikto', 'nikto', 'same', 'http://lab.test/app')
        self.assertEqual(a, b)
        a = reconx._finding_identity('nuclei', 'info', 'PHPInfo exposed',
                                     'http://lab.test/app//phpinfo.php')
        b = reconx._finding_identity('nikto', 'nikto',
                                     '/app/phpinfo.php: phpinfo() was found',
                                     'http://lab.test/app/')
        self.assertEqual(a, b)

    def test_nikto_keeps_checks_but_not_metadata_or_false_positive_warning(self):
        raw = '''+ Platform: Linux/Unix
+ Server: Apache/2.4.66 (Ubuntu)
+ [999967] /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ [001631] /css/: This might be interesting.
+ [750510] /phpinfo.php: Output from the phpinfo() function was found.'''
        _, findings = reconx.parse_output('nikto', raw, 'http://lab.test/')
        self.assertEqual(len(findings), 1)
        self.assertIn('phpinfo.php', findings[0]['name'])

    def test_nmap_footer_is_not_a_finding(self):
        raw = '''PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.66
Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 7.19 seconds'''
        _, findings = reconx.parse_output('nmap_quick', raw, '192.0.2.10')
        self.assertEqual([f['name'] for f in findings],
                         ['80/tcp open  http    Apache httpd 2.4.66'])

    def test_nmap_permission_and_host_down_output_is_not_trusted(self):
        for raw in (
            "socket: Operation not permitted (1)\nHost seems down.",
            "You requested a scan type which requires root privileges.",
        ):
            self.assertTrue(reconx.tool_output_quality_issue('nmap_quick', raw))
            self.assertEqual(reconx.parse_output('nmap_quick', raw, '192.0.2.10'),
                             ([], []))

    def test_ffuf_silent_paths_are_normalized_and_recovered(self):
        raw = 'app\ncgi-bin/\n.env\nbackup.zip\n../outside\n'
        assets, findings = reconx.parse_output(
            'ffuf_dirs', raw, 'http://lab.test/')
        self.assertEqual([item['value'] for item in assets],
                         ['/app', '/cgi-bin/', '/.env', '/backup.zip'])
        self.assertEqual(len(findings), 4)

    def test_naabu_rejects_duplicate_or_mass_port_results(self):
        duplicate = '{"ip":"192.0.2.10","port":443}\n' * 20
        issue = reconx.tool_output_quality_issue('naabu', duplicate)
        self.assertIn('duplicados', issue)

        mass_result = '\n'.join(
            __import__('json').dumps({'ip': '192.0.2.10', 'port': port})
            for port in range(1, 102)
        )
        mass_issue = reconx.tool_output_quality_issue('naabu', mass_result)
        self.assertIn('101 portas únicas', mass_issue)
        self.assertEqual(reconx.parse_output('naabu', mass_result, '192.0.2.10'),
                         ([], []))

        small_duplicate = '{"ip":"192.0.2.10","port":443}\n' * 2
        _, findings = reconx.parse_output('naabu', small_duplicate, '192.0.2.10')
        self.assertEqual(len(findings), 1)

    def test_nuclei_technology_info_becomes_asset_not_finding(self):
        record = {
            'template-id': 'apache-detect',
            'info': {'name': 'Apache Detection', 'severity': 'info'},
            'matched-at': 'http://lab.test/app/',
            'extracted-results': ['Apache/2.4.66'],
        }
        assets, findings = reconx.parse_output('nuclei_tech', __import__('json').dumps(record))
        self.assertEqual(findings, [])
        self.assertEqual(assets[0]['type'], 'technology')
        self.assertIn('Apache/2.4.66', assets[0]['value'])

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
