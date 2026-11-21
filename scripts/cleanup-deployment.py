#!/usr/bin/env python3
"""Run only after readiness succeeds. Never force-remove images or touch volumes."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True, stderr=subprocess.PIPE).strip()


def cleanup(name, repository):
    if not all(re.fullmatch(r'[a-z0-9][a-z0-9-]*', value) for value in (name, repository)):
        raise ValueError('Invalid service identity')
    active = json.loads(docker('container', 'inspect', name))[0]
    if not active['State']['Running']:
        raise RuntimeError('Refusing cleanup without a running replacement')
    current = active['Image']
    obsolete = set()
    ids = docker('ps', '-aq').split()
    containers = json.loads(docker('container', 'inspect', *ids)) if ids else []
    for container in containers:
        old_name = container['Name'].lstrip('/')
        owned = old_name.startswith((name + '.before-', name + '-previous-',
                                     name + '.previous-', name + '-before-', name + '-pre-'))
        if owned and container['State']['Status'] in ('exited', 'created', 'dead'):
            docker('rm', container['Id'])
            obsolete.add(container['Image'])
    # Limit removals to this image repository; retain all tags for the active ID.
    for line in docker('image', 'ls', '--no-trunc', '--format', '{{json .}}').splitlines():
        image = json.loads(line)
        if image['Repository'] == repository and image['ID'] != current:
            obsolete.add(image['ID'])
            docker('image', 'rm', repository + ':' + image['Tag'])
    for image_id in obsolete - {current}:
        try:
            # No --force: Docker retains images referenced by another container/tag.
            docker('image', 'rm', image_id)
        except subprocess.CalledProcessError:
            pass  # Already removed with its last tag, or still referenced elsewhere.
    # Shared builder: only unused entries older than a day, keeping 1 GiB of cache.
    docker('builder', 'prune', '--force', '--all', '--filter', 'until=24h',
           '--keep-storage', '1GB')
    # This is the deployment working directory, never the runtime data directory.
    for filename in ('image.tar', 'image.tar.sha256', 'image-id.txt',
                     'deploy-source.tar', '.env.next', '.env.previous'):
        Path(filename).unlink(missing_ok=True)
    for filename in ('node_modules', 'dist'):
        path = Path(filename)
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
    print('Removed obsolete deployment resources for ' + name)


if __name__ == '__main__':
    try:
        cleanup(*sys.argv[1:])
    except Exception:
        # Docker error messages may contain private runtime configuration.
        print('Deployment cleanup failed; service remains deployed. Inspect host privately.', file=sys.stderr)
        sys.exit(1)
