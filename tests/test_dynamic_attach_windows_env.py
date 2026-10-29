"""Pure environment checks also run on the native Windows Suite entry point."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from windows_test_env import compiler_environment, isolated_environment

class FixtureEnvironmentTests(unittest.TestCase):
    def test_case_insensitive_os_allowlist_and_private_paths(self):
        source = {'systemroot': 'test-system', 'wInDiR': 'test-windows',
                  'pAtH': 'test-path', 'pathext': '.EXE', 'comspec': 'test-shell',
                  'USERPROFILE': 'real-profile', 'TMP': 'real-temp',
                  'OPENAI_API_KEY': 'dummy-must-not-escape', 'mixed_Token': 'dummy',
                  'HYPERHUB_API_KEY': 'dummy', 'HYPERHUB_FRIDA_GUM_ROOT': 'build-only',
                  'RUSTUP_HOME': 'build-toolchain', 'unrelated': 'dummy'}
        with tempfile.TemporaryDirectory() as directory:
            env = isolated_environment(source, directory)
            self.assertEqual(env['SystemRoot'], 'test-system')
            self.assertEqual(env['WINDIR'], 'test-windows')
            self.assertEqual(env['PATH'], 'test-path')
            self.assertEqual(env['USERPROFILE'], str(Path(directory) / 'home'))
            self.assertEqual(env['TMP'], str(Path(directory) / 'tmp'))
            self.assertEqual(set(env) & {'OPENAI_API_KEY', 'mixed_Token', 'HYPERHUB_API_KEY',
                                        'HYPERHUB_FRIDA_GUM_ROOT', 'RUSTUP_HOME', 'unrelated'}, set())
            self.assertNotIn('dummy', '\n'.join(env.values()))
            build = compiler_environment(source)
            self.assertEqual(build['RUSTUP_HOME'], 'build-toolchain')
            self.assertNotIn('OPENAI_API_KEY', build)
            self.assertNotIn('mixed_Token', build)

    def test_native_child_does_not_receive_injected_dummy_secrets(self):
        source = dict(os.environ, OPENAI_API_KEY='dummy-native-secret',
                      TYPESAFE_API_KEY='dummy-native-secret', GITHUB_TOKEN='dummy-native-secret',
                      arbitrary_secret='dummy-native-secret', HYPERHUB_FRIDA_GUM_ROOT='dummy-build-only')
        with tempfile.TemporaryDirectory() as directory:
            env = isolated_environment(source, directory)
            for key in ['HOME', 'USERPROFILE', 'HYPERHUB_HOME', 'TMP', 'TEMP', 'APPDATA', 'LOCALAPPDATA']:
                Path(env[key]).mkdir(parents=True, exist_ok=True)
            result = subprocess.run([sys.executable, '-c', 'import os,json;print(json.dumps(dict(os.environ)))'],
                                    env=env, capture_output=True, check=True, text=True, timeout=20)
            child = json.loads(result.stdout)
            self.assertNotIn('dummy-native-secret', child.values())
            self.assertNotIn('dummy-build-only', child.values())
            self.assertFalse(any(key.upper().endswith(('_KEY', '_TOKEN', '_SECRET')) for key in child))
            self.assertEqual(child['USERPROFILE'], env['USERPROFILE'])

if __name__ == '__main__':
    unittest.main()
