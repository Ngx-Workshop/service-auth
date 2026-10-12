"""Application-host operator step. Preserve legacy JWT identity; stage scoped TLS env."""
import json,os,pathlib,subprocess,urllib.parse
os.umask(0o077)
root=pathlib.Path('/etc/ngx-workshop/oauth')
old=json.loads(subprocess.check_output(['docker','inspect','ngx-auth-service']))[0]
oldenv=dict(x.split('=',1) for x in old['Config']['Env'] if '=' in x)
pw=json.loads((root/'mongo-credentials.json').read_text())
def uri(user,password,db='workshop-viewer'):
 return 'mongodb://'+user+':'+urllib.parse.quote(password,safe='')+'@10.116.0.2:27017/'+db+'?replicaSet=rs0&authSource='+db+'&tls=true'
common={'NODE_ENV':'production','RUNTIME_PROFILE':'production','LISTEN_HOST':'0.0.0.0','TRUSTED_PROXY_IPS':'172.18.0.240','ALLOWED_ORIGINS':'https://chatgpt.com'}
auth={key:oldenv[key] for key in ['JWT_SECRET','JWT_ISSUER','JWT_AUDIENCE','JWT_ACCESS_TOKEN_TTL','JWT_REFRESH_TOKEN_TTL','USER_METADATA_URL','DOMAIN']}
auth.update(common,PORT='3000',OAUTH_ENABLED='true',OAUTH_CONFIG_FILE='/run/secrets/oauth.json',MONGODB_URI=uri('ngx_oauth_auth',pw['runtime']),MONGODB_ALLOWED_HOSTS='10.116.0.2',MONGODB_REPLICA_SET='rs0',MONGODB_TLS_CA_FILE='/run/secrets/mongo-ca.pem')
provision=dict(auth);provision['MONGODB_URI']=uri('ngx_oauth_provisioner',pw['provisioner'])
gateway=dict(common,PORT='3011',MCP_AUTH_MODE='oauth',DOCUMENT_BASE_URL='http://document:3007',CODING_LABS_BASE_URL='http://coding-labs:3009',MCP_RESOURCE_URL='https://mcp.ngx-workshop.io/mcp',AUTH_ISSUER_URL='https://auth.ngx-workshop.io',AUTH_INTROSPECTION_URL='https://auth.ngx-workshop.io/oauth/introspect',AUTH_INTROSPECTION_CLIENT_ID='ngx-workshop-gateway-prod',AUTH_INTROSPECTION_SECRET_FILE='/run/secrets/introspection')
for name,env in [('auth/runtime.env',auth),('gateway/runtime.env',gateway),('provision.env',provision)]:
 p=root/name
 if p.exists():raise RuntimeError('Refusing to overwrite staged configuration')
 assert all(not any(c in str(v) for c in ['\n','\r','\x00']) for v in env.values())
 p.write_text(''.join(k+'='+v+'\n' for k,v in env.items()));p.chmod(0o600)
for name in ['auth','gateway']:os.chown(root/name,1000,1000)
print('Staged scoped TLS auth and database-free gateway configuration; legacy JWT settings preserved.')
