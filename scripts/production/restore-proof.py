"""Restore a logical recovery bundle into an owned isolated loopback replica set.
Never restores the production database. OAuth state is invalidated before reuse.
"""
import json,pathlib,socket,subprocess,tempfile,time
root=pathlib.Path('/var/backups/ngx-oauth')
archives=sorted(root.glob('*/mongodb-recovery.tar.gz.gpg'));assert archives
archive=archives[-1]
with tempfile.TemporaryDirectory(prefix='ngx-recovery-proof-',dir='/var/tmp') as temp:
 p=pathlib.Path(temp);p.chmod(0o700)
 decrypted=subprocess.Popen(['gpg','--batch','--pinentry-mode','loopback','--passphrase-file','/etc/ngx-workshop/recovery/backup-passphrase','--decrypt',str(archive)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
 extract=subprocess.run(['tar','-xzf','-','-C',str(p),'mongodb.archive.gz'],stdin=decrypted.stdout);decrypted.stdout.close();assert extract.returncode==0 and decrypted.wait()==0
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 data=p/'data';data.mkdir(mode=0o700)
 log=open(p/'server.log','w');started=time.monotonic()
 server=subprocess.Popen(['mongod','--dbpath',str(data),'--port',str(port),'--bind_ip','127.0.0.1','--replSet','recoveryProof'],stdout=log,stderr=log)
 uri='mongodb://127.0.0.1:'+str(port)+'/?directConnection=true'
 def shell(code):return subprocess.run(['mongosh',uri,'--quiet','--eval',code],capture_output=True,text=True)
 try:
  for i in range(30):
   if shell('db.runCommand({ping:1})').returncode==0:break
   time.sleep(.3)
  assert shell("rs.initiate({_id:'recoveryProof',members:[{_id:0,host:'127.0.0.1:"+str(port)+"'}]})").returncode==0
  for i in range(30):
   if shell('assert(db.hello().isWritablePrimary)').returncode==0:break
   time.sleep(.3)
  restore=subprocess.run(['mongorestore','--uri',uri,'--archive='+str(p/'mongodb.archive.gz'),'--gzip','--oplogReplay','--quiet'],capture_output=True,text=True)
  assert restore.returncode==0,'Isolated restore failed: '+restore.stderr[-1500:]
  result=shell("const d=db.getSiblingDB('workshop-viewer');assert(d.users.countDocuments({})===21);assert(d.getCollectionInfos({name:'oauth_state'})[0].options.validationLevel==='strict');for(const n of ['oauth_state','oauth_forms','oauth_revoked']){d.getCollection(n).deleteMany({});assert(d.getCollection(n).countDocuments({})===0);}print(JSON.stringify({users:21,oauthSchemaRestored:true,restoredOAuthStateInvalidated:true}));")
  assert result.returncode==0,result.stderr[-1500:];print(result.stdout.strip());print('Isolated logical/oplog recovery proof PASS in '+str(round(time.monotonic()-started,2))+' seconds.')
 finally:
  server.terminate()
  try:server.wait(timeout=20)
  except subprocess.TimeoutExpired:server.kill();server.wait()
  log.close()
