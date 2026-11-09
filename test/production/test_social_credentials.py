import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / 'production' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stage = load('stage-social-credentials')
install = load('install-social-credentials')


class SocialCredentialTransfer(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.transfer = self.root / 'transfer.json'
        self.destination = self.root / 'persistent' / 'social.env'
        self.values = {name: 'example-$value`literal`"=#' for name in stage.NAMES}

    def test_transfer_and_install_preserve_literal_values_with_private_permissions(self):
        stage.stage(self.transfer, self.values)
        self.assertEqual(stat.S_IMODE(self.transfer.stat().st_mode), 0o600)
        install.install(self.transfer, self.destination)
        self.assertFalse(self.transfer.exists())
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o600)
        actual = dict(line.split('=', 1) for line in self.destination.read_text().splitlines())
        self.assertEqual(actual, {**self.values, 'SOCIAL_APPLE_CLIENT_ID': ''})
        self.assertEqual(stat.S_IMODE(self.destination.parent.stat().st_mode), 0o700)

    def test_missing_or_multiline_secrets_fail_before_staging(self):
        for values in [{}, {**self.values, stage.NAMES[0]: 'bad\nSOCIAL_APPLE_CLIENT_ID=enabled'}]:
            with self.assertRaises(ValueError):
                stage.stage(self.transfer, values)
            self.assertFalse(self.transfer.exists())

    def test_failed_install_cleans_transfer_and_preserves_existing_configuration(self):
        self.destination.parent.mkdir()
        self.destination.write_text('previous configuration')
        for values in [{}, {**self.values, 'UNEXPECTED': 'value'}, {**self.values, stage.NAMES[0]: 'bad\rvalue'}]:
            self.transfer.write_text(json.dumps(values))
            with self.assertRaises(ValueError):
                install.install(self.transfer, self.destination)
            self.assertFalse(self.transfer.exists())
            self.assertEqual(self.destination.read_text(), 'previous configuration')

    def test_staging_never_overwrites_an_existing_transfer(self):
        self.transfer.write_text('existing')
        with self.assertRaises(FileExistsError):
            stage.stage(self.transfer, self.values)
        self.assertEqual(self.transfer.read_text(), 'existing')


if __name__ == '__main__':
    unittest.main()
