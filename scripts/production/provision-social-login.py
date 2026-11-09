"""Explicit MongoDB-host operator migration; adds social indexes and scoped privileges.
Run on the database host using the same TLS/keyfile operator boundary as
provision-mongo-roles.py. Does not edit users, credentials, or existing indexes.
"""
import subprocess

CODE = r"""
const fs=require('fs'); const c=db.getMongo();
const key=fs.readFileSync('/etc/mongodb-keyfile','utf8').replace(/\s/g,'');
assert(c.getDB('local').auth({user:'__system',pwd:key,mechanism:'SCRAM-SHA-256'}));
const d=c.getDB('workshop-viewer');
assert(d.getRole('ngx_oauth_runtime'), 'Existing runtime role required');
assert(d.getRole('ngx_oauth_provisioner'), 'Existing provisioner role required');
if (!d.getCollectionNames().includes('social_login_transactions'))
  d.createCollection('social_login_transactions');
d.social_login_transactions.createIndex({expiresAt:1},{expireAfterSeconds:0});
d.users.createIndex({externalIdentities:1},{unique:true,sparse:true});
const resource={db:d.getName(),collection:'social_login_transactions'};
d.grantPrivilegesToRole('ngx_oauth_runtime',[
 {resource,actions:['find','insert','update','remove','listIndexes']}
]);
d.grantPrivilegesToRole('ngx_oauth_provisioner',[
 {resource,actions:['createCollection','createIndex','collMod','listIndexes']},
 {resource:{db:d.getName(),collection:'users'},actions:['createIndex','listIndexes']}
]);
print('Social indexes and additive scoped privileges ready; existing users unchanged.');
"""

if __name__ == '__main__':
    result = subprocess.run([
        'mongosh', 'mongodb://127.0.0.1:27017/?directConnection=true', '--quiet',
        '--tls', '--tlsCAFile', '/etc/ngx-workshop/pki/ca.pem', '--eval', CODE,
    ], capture_output=True, text=True)
    if result.returncode:
        raise SystemExit('Social login migration failed. Review database indexes and operator access; no deployment should proceed.')
    print('Social indexes and additive scoped privileges ready; existing users unchanged.')
