import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from host_profiles import Store, canonical_host


class HostProfilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / 'test.db'
        with closing(sqlite3.connect(path)) as con:
            with con:
                con.execute('''CREATE TABLE scans(scan_id TEXT PRIMARY KEY,target TEXT,pipeline TEXT,
                               proxy TEXT,status TEXT,started_at TEXT,finished_at TEXT)''')
                con.execute('''CREATE TABLE findings(id INTEGER PRIMARY KEY,scan_id TEXT,tool TEXT,
                    ftype TEXT,name TEXT,severity TEXT,target TEXT,evidence TEXT,
                    confidence TEXT,created_at TEXT)''')
        self.store = Store(path)
        self.store.init()

    def test_canonical_host_and_bad_targets(self):
        self.assertEqual(canonical_host('HTTPS://Lab.Example:8443/login?q=1'), 'lab.example')
        self.assertEqual(canonical_host('10.10.10.5:8080'), '10.10.10.5')
        self.assertEqual(canonical_host('http://[2001:db8::1]:8080/a'), '2001:db8::1')
        for value in ('', 'https://user:pass@lab.example/', 'ftp://lab.example',
                      'bad host', 'http://lab.example:bad', 'http://-bad.example'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_host(value)

    def test_backfill_and_checklist_persist(self):
        with closing(sqlite3.connect(self.store.path)) as con:
            with con:
                con.execute("INSERT INTO scans(scan_id,target) VALUES('old','https://LAB.example:443/login')")
        self.store.init()
        hosts = self.store.list_hosts()
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['scan_count'], 1)
        host_id = hosts[0]['id']
        with self.assertRaises(ValueError):
            self.store.update_check(host_id, 'authn', 'tested', '', '')
        self.assertTrue(self.store.update_check(host_id, 'authn', 'tested', 'Login revisado', 'old / request 12'))
        reopened = Store(self.store.path)
        reopened.init()
        check = next(c for c in reopened.get(host_id)['checks'] if c['check_key'] == 'authn')
        self.assertEqual(check['status'], 'tested')
        self.assertEqual(check['evidence'], 'old / request 12')

    def test_assets_and_runs_are_isolated_by_host(self):
        first = self.store.ensure('https://one.example')
        second = self.store.ensure('https://two.example')
        self.store.record_run('s1', 'httpx', 'https://one.example', 'completed', 0, '/tmp/s1.txt')
        self.store.record_assets('s1', 'https://one.example', [
            {'type': 'path', 'value': '/api/v1'},
            {'type': 'url', 'value': 'https://two.example/login'},
        ])
        one = self.store.get(first)
        two = self.store.get(second)
        self.assertEqual([a['value'] for a in one['assets']], ['/api/v1'])
        self.assertEqual([a['value'] for a in two['assets']], ['https://two.example/login'])
        self.assertEqual(one['runs'][0]['output_path'], '/tmp/s1.txt')
        self.assertFalse(two['runs'])
        self.assertIsNone(self.store.get_run(second, one['runs'][0]['id']))
        self.assertEqual(self.store.get_run(first, one['runs'][0]['id'])['tool'], 'httpx')
        self.assertTrue(next(s for s in one['suggestions'] if s['key'] == 'api_recon')['ready'])
        self.assertFalse(next(s for s in two['suggestions'] if s['key'] == 'api_recon')['ready'])

    def test_inconclusive_run_does_not_complete_checklist(self):
        host_id = self.store.ensure('host.example')
        self.store.record_run('s1', 'nmap_quick', 'host.example', 'failed', 1)
        profile = self.store.get(host_id)
        self.assertEqual(profile['runs'][0]['status'], 'failed')
        self.assertTrue(all(c['status'] == 'pending' for c in profile['checks']))
        self.assertFalse(next(s for s in profile['suggestions'] if s['key'] == 'web_recon')['ready'])

    def test_http_service_unlocks_web_recon_only_after_successful_recon(self):
        host_id = self.store.ensure('lab.example')
        self.store.record_run('s1', 'nmap_quick', 'lab.example', 'completed', 0)
        self.store.record_services('s1', 'lab.example', 'nmap_quick',
                                   '8080/tcp open  http-proxy\n22/tcp open ssh')
        profile = self.store.get(host_id)
        self.assertEqual([s['port'] for s in profile['services']], [22, 8080])
        self.assertTrue(next(s for s in profile['suggestions'] if s['key'] == 'web_recon')['ready'])
        self.assertFalse(next(s for s in profile['suggestions'] if s['key'] == 'api_recon')['ready'])

    def test_httpx_observation_is_attributed_to_observed_host(self):
        first = self.store.ensure('first.example')
        second = self.store.ensure('second.example')
        self.store.record_run('s1', 'httpx', 'first.example', 'completed', 0)
        self.store.record_services('s1', 'first.example', 'httpx',
                                   '{"url":"https://second.example:8443/login"}')
        self.assertFalse(self.store.get(first)['services'])
        self.assertEqual(self.store.get(second)['services'][0]['port'], 8443)

    def test_scanned_list_and_findings_do_not_leak_between_hosts(self):
        first = self.store.ensure('first.example', 'scan-1')
        second = self.store.ensure('second.example', 'scan-1')
        unscanned = self.store.ensure('unscanned.example')
        with closing(sqlite3.connect(self.store.path)) as con:
            with con:
                con.execute("INSERT INTO scans(scan_id,target) VALUES('scan-1','first.example')")
                con.execute("""INSERT INTO findings
                    (scan_id,tool,ftype,name,severity,target,evidence,confidence,created_at)
                    VALUES('scan-1','httpx','http','first','info','https://first.example/a','','possible','now'),
                    ('scan-1','httpx','http','second','high','https://second.example/b','','possible','now'),
                    ('scan-1','nmap','port','unknown','info','','','possible','now')""")
        self.assertEqual({h['id'] for h in self.store.list_hosts(scanned_only=True)}, {first, second})
        self.assertNotIn(unscanned, {h['id'] for h in self.store.list_hosts(scanned_only=True)})
        self.assertEqual([f['name'] for f in self.store.get(first)['findings']], ['first'])
        self.assertEqual([f['name'] for f in self.store.get(second)['findings']], ['second'])


if __name__ == '__main__':
    unittest.main()
