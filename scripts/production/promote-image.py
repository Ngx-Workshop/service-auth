"""Application-host operator: promote a checksum-verified, CI-validated image.
Args: service(auth/gateway), artifact directory, exact CI revision label.
The operator must verify the CI tree matches the authorized merged release.
"""
import json,os,pathlib,subprocess,sys,time
os.umask(0o077)
service,directory,revision=sys.argv[1:];r=pathlib.Path(directory)
assert service in ['auth','gateway']
image='service-auth' if service=='auth' else 'service-mcp-gateway'
name='ngx-auth-service' if service=='auth' else image
port=3000 if service=='auth' else 3011
subprocess.run(['sha256sum','--check','image.tar.sha256'],cwd=r,check=True)
subprocess.run(['docker','load','--input',str(r/'image.tar')],check=True)
d=json.loads(subprocess.check_output(['docker','image','inspect',image+':candidate']))[0]
assert d['Architecture']=='amd64' and d['Config']['User']=='node'
assert d['Config']['Labels']['org.opencontainers.image.revision']==revision
subprocess.run(['docker','tag',d['Id'],image+':'+revision[:12]],check=True)
old=json.loads(subprocess.check_output(['docker','inspect',name]))[0]
(r/'previous-container.json').write_text(json.dumps(old));(r/'previous-container.json').chmod(0o600)
previous=name+'-previous-'+old['Id'][:12]
subprocess.run(['docker','stop',name],check=True);subprocess.run(['docker','rename',name,previous],check=True)
cmd=['docker','run','-d','--name',name,'--restart','unless-stopped','--user','1000:1000','--read-only','--tmpfs','/tmp:size=16m,noexec,nosuid','--cap-drop','ALL','--security-opt','no-new-privileges','--network','ngx-net','--env-file','/etc/ngx-workshop/oauth/'+service+'/runtime.env']
mounts=[('/etc/ngx-workshop/oauth/auth/config.json','/run/secrets/oauth.json'),('/etc/ngx-workshop/pki/ca.pem','/run/secrets/mongo-ca.pem')] if service=='auth' else [('/etc/ngx-workshop/oauth/gateway/introspection','/run/secrets/introspection')]
for source,target in mounts:cmd+=['-v',source+':'+target+':ro']
cmd+=[image+':'+revision[:12]]
try:
 subprocess.run(cmd,check=True)
 for i in range(30):
  check=subprocess.run(['docker','exec',name,'node','-e',"const n=require('net').connect("+str(port)+",'127.0.0.1');n.on('connect',()=>process.exit(0));n.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),1000)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  if check.returncode==0:break
  time.sleep(1)
 else:raise RuntimeError('Service did not become ready')
 print('Validated '+service+' image active as UID1000 with persistent secrets and no public port binding.')
except:
 subprocess.run(['docker','rm','-f',name]);subprocess.run(['docker','rename',previous,name]);subprocess.run(['docker','start',name]);raise
