import importlib.util
import json
from pathlib import Path
import tempfile
import os
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cleanup', Path(__file__).with_name('cleanup-deployment.py'))
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class CleanupTests(unittest.TestCase):
    def run_cleanup(self, running=True):
        calls = []
        def docker(*args):
            calls.append(args)
            if args == ('container', 'inspect', 'demo'):
                return json.dumps([{'Image': 'new', 'State': {'Running': running}}])
            if args == ('ps', '-aq'):
                return 'active old unrelated'
            if args[:2] == ('container', 'inspect'):
                return json.dumps([
                    {'Id': 'active', 'Name': '/demo.before-live', 'Image': 'live', 'State': {'Status': 'running'}},
                    {'Id': 'old', 'Name': '/demo.before-ci-1-1', 'Image': 'old', 'State': {'Status': 'exited'}},
                    {'Id': 'unrelated', 'Name': '/other.before-ci-1-1', 'Image': 'other', 'State': {'Status': 'exited'}},
                ])
            if args[:2] == ('image', 'ls'):
                return '\n'.join(json.dumps(dict(Repository=repo, Tag=tag, ID=image)) for repo, tag, image in [
                    ('demo', 'latest', 'new'), ('demo', 'candidate', 'new'),
                    ('demo', 'previous', 'old'), ('other', 'previous', 'other')])
            return ''
        with patch.object(cleanup, 'docker', side_effect=docker):
            cleanup.cleanup('demo', 'demo')
        return calls

    def test_only_obsolete_service_resources_removed_and_runtime_files_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            before = Path.cwd()
            os.chdir(directory)
            try:
                for name in ('.env', '.env.previous', 'image.tar'):
                    Path(name).write_text('private')
                Path('node_modules').mkdir()
                Path('node_modules/old').write_text('dependency')
                calls = self.run_cleanup()
                self.assertTrue(Path('.env').exists())
                self.assertFalse(Path('.env.previous').exists())
                self.assertFalse(Path('image.tar').exists())
                self.assertFalse(Path('node_modules').exists())
            finally:
                os.chdir(before)
        self.assertIn(('rm', 'old'), calls)
        self.assertIn(('image', 'rm', 'demo:previous'), calls)
        self.assertNotIn(('rm', 'active'), calls)
        self.assertNotIn(('rm', 'unrelated'), calls)
        self.assertFalse(any('volume' in call or '-f' in call or '--force' in call for call in calls if call[:2] != ('builder', 'prune')))
        self.assertFalse(any(call[:2] == ('image', 'rm') and call[2] in ('new', 'live', 'other', 'demo:latest', 'demo:candidate') for call in calls))
        self.assertIn(('builder', 'prune', '--force', '--all', '--filter', 'until=24h', '--keep-storage', '1GB'), calls)

    def test_stopped_replacement_rejects_cleanup(self):
        with self.assertRaises(RuntimeError):
            self.run_cleanup(running=False)

    def test_invalid_service_identity_rejected_before_docker(self):
        with patch.object(cleanup, 'docker') as docker:
            with self.assertRaises(ValueError):
                cleanup.cleanup('../other', 'demo')
            docker.assert_not_called()


if __name__ == '__main__':
    unittest.main()
