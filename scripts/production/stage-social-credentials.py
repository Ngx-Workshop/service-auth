"""Stage Google/GitHub Actions secrets as a private transfer file; never print values."""
import json
import os
from pathlib import Path
import sys

NAMES = (
    'SOCIAL_GOOGLE_CLIENT_ID', 'SOCIAL_GOOGLE_CLIENT_SECRET',
    'SOCIAL_GITHUB_CLIENT_ID', 'SOCIAL_GITHUB_CLIENT_SECRET',
)


def stage(destination, environment):
    values = {}
    for name in NAMES:
        value = environment.get(name, '')
        if not value or any(c in value for c in '\r\n\x00'):
            raise ValueError(f'Missing or invalid deployment secret: {name}')
        values[name] = value
    path = Path(destination)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(values, output)


if __name__ == '__main__':
    stage(sys.argv[1], os.environ)
