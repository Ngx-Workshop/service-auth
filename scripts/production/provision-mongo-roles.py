"""Run as the MongoDB host operator after verified TLS is enabled.
Creates additive, collection-scoped credentials; existing users are untouched.
"""
import json, os, pathlib, secrets, subprocess
os.umask(0o077)
root = pathlib.Path('/etc/ngx-workshop/oauth')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
file = root / 'mongo-credentials.json'
if file.exists():
    credentials = json.loads(file.read_text())
else:
    credentials = {name: secrets.token_urlsafe(36) for name in ['runtime', 'provisioner', 'backup']}
    file.write_text(json.dumps(credentials))
    file.chmod(0o600)
code = r"""
const fs=require('fs');const c=db.getMongo();
const key=fs.readFileSync('/etc/mongodb-keyfile','utf8').replace(/\s/g,'');
assert(c.getDB('local').auth({user:'__system',pwd:key,mechanism:'SCRAM-SHA-256'}));
const d=c.getDB('workshop-viewer');
const pw=JSON.parse(fs.readFileSync('/etc/ngx-workshop/oauth/mongo-credentials.json','utf8'));
const names=['oauth_state','oauth_forms','oauth_revoked'];
const runtime=names.concat(['users']).map(collection=>({resource:{db:d.getName(),collection},actions:['find','insert','update','remove','listIndexes']}));
runtime.push({resource:{db:d.getName(),collection:''},actions:['listCollections']});
const provision=names.map(collection=>({resource:{db:d.getName(),collection},actions:['createCollection','createIndex','collMod','listIndexes']}));
provision.push({resource:{db:d.getName(),collection:''},actions:['listCollections']});
for(const [role,privileges] of [['ngx_oauth_runtime',runtime],['ngx_oauth_provisioner',provision]]) {
 if(!d.getRole(role)) d.createRole({role,privileges,roles:[]});
 else assert.eq(JSON.stringify(d.getRole(role).privileges),JSON.stringify(privileges),'Existing role differs; operator review required');
}
for(const [user,secret,role] of [['ngx_oauth_auth',pw.runtime,'ngx_oauth_runtime'],['ngx_oauth_provisioner',pw.provisioner,'ngx_oauth_provisioner']]) {
 if(!d.getUser(user)) d.createUser({user,pwd:secret,roles:[role]});
}
const a=c.getDB('admin');if(!a.getUser('ngx_oauth_backup')) a.createUser({user:'ngx_oauth_backup',pwd:pw.backup,roles:[{role:'backup',db:'admin'}]});
print('Scoped runtime, separate provisioner, and backup principals present; existing credentials unchanged.');
"""
r = subprocess.run(['mongosh','mongodb://127.0.0.1:27017/?directConnection=true','--quiet','--tls','--tlsCAFile','/etc/ngx-workshop/pki/ca.pem','--eval',code], capture_output=True,text=True)
if r.returncode:
    raise RuntimeError('MongoDB principal provisioning failed: '+r.stderr[:1000])
print(r.stdout)
