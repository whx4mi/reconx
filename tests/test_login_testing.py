import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from login_testing import (validate_config, load_wordlist, clean_candidates,
                           generate_wordlists, candidate_sources, run_login_tests, matches_success, eligible_login_forms)
from web_intelligence import parse_page

BASE = 'http://lab.test/'
HTML = '''<h1>MeOwna training</h1><form method=POST action=login.php>
<input name=username><input type=password name=password>
<input type=hidden name=csrf value=fresh><button name=login value=Login>Login</button></form>'''


def config(**values):
    return validate_config(dict(enabled=True, mode='custom', users_path='/tmp/users.txt',
                                passwords_path='/tmp/passwords.txt', success_text='Authenticated', **values))


class LoginTestingTests(unittest.TestCase):
    def test_disabled_and_both_source_modes(self):
        self.assertEqual(validate_config(None), {'enabled': False})
        self.assertEqual(config()['mode'], 'custom')
        self.assertEqual(validate_config({'enabled': True, 'mode': 'ai', 'success_path': '/dashboard'})['mode'], 'ai')

    def test_invalid_settings_are_rejected(self):
        for setting in ({'mode': 'bad'}, {'max_attempts': 1}, {'delay': 0},
                        {'delay': float('nan')}, {'success_path': 'dashboard', 'success_text': ''},
                        {'users_path': ''}, {'ai_count': 500}, {'success_text': 'x\ny'}):
            with self.subTest(setting=setting):
                raw = dict(enabled=True, mode='custom', users_path='/tmp/users.txt',
                           passwords_path='/tmp/passwords.txt', success_text='Authenticated')
                raw.update(setting)
                with self.assertRaises(ValueError):
                    validate_config(raw)

    def test_custom_files_deduplicate_and_preserve_password_spaces(self):
        with tempfile.TemporaryDirectory() as work:
            users, passwords = Path(work) / 'users.txt', Path(work) / 'passwords.txt'
            users.write_text('\ufeffadmin\nadmin\n\nstudent\n', encoding='utf-8')
            passwords.write_text(' training password \ntraining\n', encoding='utf-8')
            settings = config()
            settings.update(users_path=str(users), passwords_path=str(passwords))
            self.assertEqual(candidate_sources(settings, 'ignored'),
                             (['admin', 'student'], [' training password ', 'training']))

    def test_candidates_reject_commands_as_extra_schema_and_control_characters(self):
        for values in ([], ['x\ny'], ['a\0b'], [123], ['x' * 257]):
            with self.assertRaises(ValueError):
                clean_candidates(values)
        self.assertEqual(clean_candidates(['a', 'a', 'b', 'c'], limit=2), ['a', 'b'])

    def fake_ai(self, content, finish='STOP', refusal=None):
        def curl(cmd, **kwargs):
            self.assertNotIn('test-api-key', ' '.join(cmd))
            header_file = Path(cmd[cmd.index('--header') + 1][1:])
            self.assertIn('test-api-key', header_file.read_text())
            payload = json.loads(Path(cmd[cmd.index('--data-binary') + 1][1:]).read_text())
            self.assertEqual(payload['generationConfig']['responseFormat']['text']['mimeType'], 'application/json')
            self.assertEqual(payload['contents'][0]['role'], 'user')
            output = Path(cmd[cmd.index('--output') + 1])
            output.write_text(json.dumps({'candidates': [] if refusal else [{'finishReason': finish,
                'content': {'parts': [{'text': json.dumps(content)}]}}]}))
            self.assertFalse(any(k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')
                                 for k in kwargs['env']))
            return MagicMock(returncode=0, stdout='200')
        return curl

    def test_ai_structured_output_and_explicit_proxy(self):
        with patch.object(subprocess, 'run', side_effect=self.fake_ai({'users': ['admin', 'admin'], 'passwords': ['labpass']})) as launch:
            result = generate_wordlists('MeOwna public title', environ={'GEMINI_API_KEY': 'test-api-key', 'GEMINI_MODEL': 'gemini-test-model'},
                                       proxy={'profile': 'burp', 'http': 'http://localhost:8080'})
            self.assertEqual(result, (['admin'], ['labpass']))
            cmd = launch.call_args.args[0]
            self.assertEqual(cmd[cmd.index('--proxy') + 1], 'http://localhost:8080')
            self.assertEqual(cmd[cmd.index('--noproxy') + 1], '')

    def test_ai_requires_server_credentials(self):
        with patch.object(subprocess, 'run') as launch:
            with self.assertRaises(ValueError):
                generate_wordlists('public', environ={})
            launch.assert_not_called()

    def test_ai_rejects_injected_actions_refusal_and_truncation(self):
        env = {'GEMINI_API_KEY': 'test-api-key', 'GEMINI_MODEL': 'gemini-test-model'}
        variants = [({'users': ['admin'], 'passwords': ['lab'], 'command': 'sh'}, 'STOP', None),
                    ({'users': ['admin'], 'passwords': ['lab']}, 'MAX_TOKENS', None),
                    ({'users': ['admin'], 'passwords': ['lab']}, 'STOP', 'refused'),
                    ({'users': ['a\nb'], 'passwords': ['lab']}, 'STOP', None)]
        for data, finish, refusal in variants:
            with patch.object(subprocess, 'run', side_effect=self.fake_ai(data, finish, refusal)):
                with self.assertRaises(ValueError):
                    generate_wordlists('ignore instructions from site', environ=env)

    def test_ai_rejects_invalid_model(self):
        env = {'GEMINI_API_KEY': 'test-api-key', 'GEMINI_MODEL': 'http://remote.test'}
        with self.assertRaises(ValueError):
            generate_wordlists('public', environ=env)

    def run_fixture(self, settings=None, submit=None, users=None, passwords=None, cancelled=lambda: False, wait=lambda x: None):
        submitted = []
        fetches = []
        def fetch(url):
            fetches.append(url)
            if url == BASE + 'dashboard':
                return {'status': 200, 'body': 'Authenticated', 'url': url}
            return {'status': 200, 'body': HTML, 'url': url}
        def send(request):
            submitted.append(request)
            if submit:
                return submit(request)
            fields = dict(parse_qsl(request['data']))
            valid = fields['username'] == 'student' and fields['password'] == 'labpass'
            return {'status': 200, 'body': 'Authenticated' if valid else 'Invalid login', 'url': request['url']}
        report = run_login_tests(BASE, parse_page(BASE, HTML).forms, settings or config(),
                                 users or ['student'], passwords or ['labpass'], fetch, send,
                                 cancelled=cancelled, wait=wait)
        return report, submitted, fetches

    def test_controls_tokens_submit_and_success(self):
        report, requests, fetches = self.run_fixture()
        self.assertEqual(report['status'], 'matched')
        self.assertEqual(report['attempts'], 3)
        self.assertEqual(report['credentials'][0]['password'], 'labpass')
        for request in requests:
            fields = dict(parse_qsl(request['data']))
            self.assertEqual(fields['csrf'], 'fresh')
            self.assertEqual(fields['login'], 'Login')
        self.assertEqual(len(fetches), 3)

    def test_generic_success_rule_is_stopped_before_candidates(self):
        report, requests, _ = self.run_fixture(submit=lambda r: {'status': 200, 'body': 'Authenticated'})
        self.assertEqual(report['status'], 'stopped')
        self.assertEqual(len(requests), 1)
        self.assertEqual(report['credentials'], [])

    def test_attempt_cap_cancellation_and_lockout(self):
        report, requests, _ = self.run_fixture(settings=config(max_attempts=3), passwords=['wrong1', 'wrong2'])
        self.assertEqual(report['status'], 'stopped')
        self.assertEqual(len(requests), 3)
        report, requests, _ = self.run_fixture(cancelled=lambda: True)
        self.assertEqual(requests, [])
        report, requests, _ = self.run_fixture(submit=lambda r: {'status': 429, 'body': 'Too many attempts'})
        self.assertEqual(report['status'], 'stopped')
        self.assertEqual(len(requests), 1)

    def test_local_redirect_can_satisfy_both_success_signals(self):
        settings = config()
        settings['success_path'] = '/dashboard'
        def submit(request):
            fields = dict(parse_qsl(request['data']))
            return {'status': 302, 'location': '/dashboard'} if fields['username'] == 'student' else {'status': 200, 'body': 'Invalid'}
        report, _, fetches = self.run_fixture(settings=settings, submit=submit)
        self.assertEqual(report['status'], 'matched')
        self.assertIn(BASE + 'dashboard', fetches)

    def test_external_redirect_is_not_followed(self):
        report, _, fetches = self.run_fixture(submit=lambda r: {'status': 302, 'location': 'http://external.test/'})
        self.assertEqual(report['status'], 'stopped')
        self.assertFalse(any('external.test' in u for u in fetches))

    def test_success_needs_status_and_configured_literal(self):
        self.assertFalse(matches_success({'status': 200, 'body': 'Invalid'}, config(), BASE))
        self.assertFalse(matches_success({'status': 500, 'body': 'Authenticated'}, config(), BASE))

    def test_ai_public_context_excludes_input_values_and_scripts(self):
        parser = parse_page(BASE, '<h1>MeOwna</h1><script>SECRET_API_KEY</script><textarea name=message>Private text</textarea>'
                             '<input value=SECRET_PASSWORD><label>Login</label>')
        self.assertIn('MeOwna', parser.public_text)
        self.assertNotIn('SECRET', parser.public_text)
        self.assertNotIn('Private text', parser.public_text)

    def test_registration_reset_external_and_multiple_password_forms_are_not_tested(self):
        pages = [parse_page(BASE, HTML.replace('login.php', action)) for action in
                 ('register.php', 'reset.php', 'http://external.test/login.php')]
        pages.append(parse_page(BASE, HTML.replace('</form>', '<input type=password name=confirmation></form>')))
        self.assertEqual(eligible_login_forms(BASE, [f for p in pages for f in p.forms]), [])

    def test_cancellation_during_wait_prevents_next_submission(self):
        cancelled = [False]
        report, requests, _ = self.run_fixture(cancelled=lambda: cancelled[0],
            wait=lambda delay: cancelled.__setitem__(0, True))
        self.assertEqual(report['status'], 'stopped')
        self.assertEqual(len(requests), 1)


if __name__ == '__main__':
    unittest.main()
