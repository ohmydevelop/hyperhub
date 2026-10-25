"""The CI permission helper must refuse local hosts and restore exact policy.

All commands use private sysctl/sudo doubles. No kernel setting is modified.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/ci-linux-gum-environment.sh'


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'POSIX helper')
class GumEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hyperhub-ci-policy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.value = self.root / 'fake-policy'
        self.value.write_text('1')
        self.calls = self.root / 'calls'
        self.env = {
            'PATH': str(self.root) + os.pathsep + os.defpath,
            'RUNNER_TEMP': str(self.root),
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'RUNNER_OS': 'Linux',
        }
        stub = self.root / 'sysctl'
        stub.write_text(
            '#!/bin/bash\nset -euo pipefail\n'
            'printf "%s\\n" "$*" >> "$RUNNER_TEMP/calls"\n'
            'case "$*" in\n'
            '  "-n kernel.yama.ptrace_scope") cat "$RUNNER_TEMP/fake-policy";;\n'
            '  "-w kernel.yama.ptrace_scope="[0-3]) '
            'printf "%s" "${2##*=}" > "$RUNNER_TEMP/fake-policy";;\n'
            '  *) exit 90;;\nesac\n'
        )
        stub.chmod(0o700)
        sudo = self.root / 'sudo'
        sudo.write_text('#!/bin/bash\nexec "$@"\n')
        sudo.chmod(0o700)

    def run_helper(self, action, **updates):
        return subprocess.run(['bash', str(SCRIPT), action],
                              env={**self.env, **updates}, capture_output=True, text=True)

    def test_local_and_self_hosted_refuse_before_any_sysctl(self):
        for updates in ({'GITHUB_ACTIONS': ''}, {'RUNNER_ENVIRONMENT': 'self-hosted'},
                        {'RUNNER_OS': 'Windows'}):
            self.assertEqual(self.run_helper('prepare', **updates).returncode, 2)
        self.assertFalse(self.calls.exists())
        self.assertEqual(self.value.read_text(), '1')

    def test_prepare_restores_exact_original_value(self):
        for original in ('0', '1', '2', '3'):
            self.value.write_text(original)
            self.assertEqual(self.run_helper('prepare').returncode, 0)
            self.assertEqual(self.value.read_text(), '0')
            self.assertEqual(self.run_helper('restore').returncode, 0)
            self.assertEqual(self.value.read_text(), original)
            self.assertFalse((self.root / 'hyperhub-yama-before').exists())

    def test_unknown_policy_refuses_without_write(self):
        self.value.write_text('99')
        self.assertEqual(self.run_helper('prepare').returncode, 2)
        self.assertNotIn('-w', self.calls.read_text())


if __name__ == '__main__':
    unittest.main()
