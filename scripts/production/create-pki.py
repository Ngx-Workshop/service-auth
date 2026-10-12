"""Generate operator-owned private CA and two server certs outside the checkout."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--directory', required=True)
args = parser.parse_args()
root = Path(args.directory).expanduser().resolve()
os.umask(0o077)
root.mkdir(parents=True, exist_ok=True, mode=0o700)
root.chmod(0o700)
if any(root.iterdir()):
    raise SystemExit('Refusing to replace persistent PKI files')

def run(*args):
    subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

run('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(root / 'ca.key'))
run('req', '-new', '-x509', '-key', str(root / 'ca.key'), '-sha256', '-days', '3650',
    '-subj', '/CN=Ngx Workshop private service CA', '-addext', 'basicConstraints=critical,CA:TRUE',
    '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-out', str(root / 'ca.pem'))
for name, cn, san in [
    ('mongodb', 'mongodb.ngx-workshop.internal', 'DNS:mongodb.ngx-workshop.internal,DNS:localhost,IP:10.116.0.2,IP:127.0.0.1'),
    ('backhaul', 'app.ngx-workshop.internal', 'DNS:app.ngx-workshop.internal,IP:10.116.0.4'),
]:
    run('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(root / (name + '.key')))
    run('req', '-new', '-key', str(root / (name + '.key')), '-subj', '/CN=' + cn, '-out', str(root / (name + '.csr')))
    ext = root / (name + '.ext')
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=' + san + '\n')
    run('x509', '-req', '-in', str(root / (name + '.csr')), '-CA', str(root / 'ca.pem'),
        '-CAkey', str(root / 'ca.key'), '-CAcreateserial', '-days', '365', '-sha256', '-extfile', str(ext), '-out', str(root / (name + '.crt')))
    (root / (name + '.pem')).write_bytes((root / (name + '.key')).read_bytes() + (root / (name + '.crt')).read_bytes() + (root / 'ca.pem').read_bytes())
    run('verify', '-CAfile', str(root / 'ca.pem'), str(root / (name + '.crt')))
print('Private CA and verified MongoDB/backhaul certificates generated; no key values printed')
