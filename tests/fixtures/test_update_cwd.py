"""Ensure the updater validates in its freshly cloned repository, not cwd."""
from pathlib import Path
import unittest

from update_test_probe import MARKER


class UpdaterWorkingDirectoryTests(unittest.TestCase):
    def test_new_checkout_is_import_root_and_working_directory(self):
        self.assertEqual(MARKER, 'new checkout')
        self.assertIn('new version', Path('app.py').read_text(encoding='utf-8'))
