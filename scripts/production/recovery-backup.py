"""DB-host daily consistent encrypted recovery backup, private object upload."""
import datetime,hashlib,json,os,pathlib,subprocess,tempfile,boto3
os.umask(0o077)
root=pathlib.Path('/etc/ngx-workshop/recovery')
spaces=json.loads((root/'backup-spaces.json').read_text())
endpoint=spaces['SPACES_ENDPOINT'];endpoint=endpoint if endpoint.startswith('https://') else 'https://'+endpoint
s3=boto3.client('s3',endpoint_url=endpoint,region_name='nyc3',aws_access_key_id=spaces['SPACES_ACCESS_KEY_ID'],aws_secret_access_key=spaces['SPACES_SECRET_ACCESS_KEY'])
def upload(path):
 key='ops-recovery/ngx-oauth/'+path.parent.name+'/'+path.name
 s3.upload_file(str(path),spaces['SPACES_BUCKET'],key,ExtraArgs={'ACL':'private','ContentType':'application/octet-stream','Metadata':{'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}})
 assert s3.head_object(Bucket=spaces['SPACES_BUCKET'],Key=key)['ContentLength']==path.stat().st_size
 print('Verified private encrypted recovery object:',key)
if '--baseline' in __import__('sys').argv:
 p=pathlib.Path((root/'latest-prechange-backup').read_text().strip())
 upload(p);raise SystemExit(0)
credentials=json.loads(pathlib.Path('/etc/ngx-workshop/oauth/mongo-credentials.json').read_text())
out=pathlib.Path('/var/backups/ngx-oauth')/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(mode=0o700)
with tempfile.TemporaryDirectory(prefix='ngx-recovery-',dir='/var/tmp') as temp:
 tmp=pathlib.Path(temp);tmp.chmod(0o700)
 cfg=tmp/'dump.yaml';cfg.write_text('uri: '+json.dumps('mongodb://ngx_oauth_backup@127.0.0.1:27017/?authSource=admin&replicaSet=rs0&tls=true')+'\npassword: '+json.dumps(credentials['backup'])+'\n');cfg.chmod(0o600)
 dump=tmp/'mongodb.archive.gz'
 subprocess.run(['mongodump','--config',str(cfg),'--sslCAFile','/etc/ngx-workshop/pki/ca.pem','--archive='+str(dump),'--gzip','--oplog','--quiet'],check=True)
 encrypted=out/'mongodb-recovery.tar.gz.gpg'
 tar=subprocess.Popen(['tar','-czf','-','-C',str(tmp),'mongodb.archive.gz','-C','/','etc/mongod.conf','etc/mongodb-keyfile','etc/ngx-workshop/pki','etc/ngx-workshop/oauth/mongo-credentials.json'],stdout=subprocess.PIPE)
 result=subprocess.run(['gpg','--batch','--yes','--pinentry-mode','loopback','--passphrase-file',str(root/'backup-passphrase'),'--symmetric','--cipher-algo','AES256','--output',str(encrypted)],stdin=tar.stdout);tar.stdout.close()
 assert result.returncode==0 and tar.wait()==0
 encrypted.chmod(0o600)
 (out/'SHA256SUMS').write_text(hashlib.sha256(encrypted.read_bytes()).hexdigest()+'  '+encrypted.name+'\n')
 upload(encrypted)
print('Consistent encrypted Mongo backup with oplog and private off-host upload PASS.')
