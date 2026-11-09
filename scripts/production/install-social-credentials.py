"""Install the staged provider configuration on the application host before promotion."""
import json
import os
from pathlib import Path
import sys
import tempfile

NAMES = {
    'SOCIAL_GOOGLE_CLIENT_ID', 'SOCIAL_GOOGLE_CLIENT_SECRET',
    'SOCIAL_GITHUB_CLIENT_ID', 'SOCIAL_GITHUB_CLIENT_SECRET',
}


def install(source, destination):
    source, destination = Path(source), Path(destination)
    try:
        values = json.loads(source.read_text())
        if set(values) != NAMES:
            raise ValueError('Unexpected social credential fields')
        for name, value in values.items():
            if not isinstance(value, str) or not value or any(c in value for c in '\r\n\x00'):
                raise ValueError(f'Missing or invalid social credential: {name}')
        # docker --env-file reads literal values; no shell or dotenv interpolation.
        content = ''.join(f'{name}={values[name]}\n' for name in sorted(NAMES))
        # Override any historical Apple settings in runtime.env until enabled deliberately.
        content += 'SOCIAL_APPLE_CLIENT_ID=\n'
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.social-', dir=destination.parent)
        try:
            with os.fdopen(descriptor, 'w') as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    finally:
        source.unlink(missing_ok=True)


if __name__ == '__main__':
    install(sys.argv[1], '/etc/ngx-workshop/oauth/auth/social.env')
