#!/usr/bin/env python3
"""Wrapper acceptance against a deliberately simulated OAuth server, never the Fluxzero IDP."""
import socket
import base64, concurrent.futures, hashlib, http.server, json, os, secrets, shutil, subprocess, sys, threading, time, urllib.parse, zipfile
from pathlib import Path
from fixture import HERE, OUT, GRADLE, build, write
REPO = HERE.parent
ROOT = OUT/'acceptance'
VERSION = next(line.split('=',1)[1] for line in (REPO/'gradle.properties').read_text().splitlines() if line.startswith('version='))

def pom(artifact, packaging='jar'):
    return f'<project><modelVersion>4.0.0</modelVersion><groupId>local.private</groupId><artifactId>{artifact}</artifactId><version>1</version><packaging>{packaging}</packaging></project>'

class Fixture:
    def __init__(self):
        self.lock = threading.Lock(); self.codes = {}; self.access = {}; self.refresh = None
        self.logins = 0; self.refreshes = 0; self.replays = 0; self.private_reads = 0
        self.revoked = False; self.delay = False; self.public_reads = 0
    def issue(self):
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.access[access] = time.time()+4; self.refresh = refresh
        return dict(access_token=access,refresh_token=refresh,expires_in=4,token_type='Bearer')

fixture = Fixture()
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_): pass
    def reply(self,status,data):
        data = json.dumps(data).encode(); self.send_response(status)
        self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        if self.path!='/token': self.reply(404,{}); return
        form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers['Content-Length'])).decode()))
        with fixture.lock:
            if form.get('client_id')!='packages-poc': self.reply(400,{'error':'invalid_client'}); return
            if form.get('grant_type')=='authorization_code':
                auth = fixture.codes.pop(form.get('code'),None)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(form.get('code_verifier','').encode()).digest()).decode().rstrip('=')
                if not auth or challenge!=auth['code_challenge'] or form.get('redirect_uri')!=auth['redirect_uri']:
                    self.reply(400,{'error':'invalid_grant'}); return
                fixture.logins += 1; fixture.revoked = False
            elif form.get('grant_type')=='refresh_token':
                if fixture.revoked or form.get('refresh_token')!=fixture.refresh:
                    fixture.replays += int(not fixture.revoked)
                    self.reply(400,{'error':'invalid_grant'}); return
                fixture.refreshes += 1
            else: self.reply(400,{'error':'unsupported_grant_type'}); return
            self.reply(200,fixture.issue())
    def do_HEAD(self): self.get(False)
    def do_GET(self): self.get(True)
    def get(self,body):
        route = urllib.parse.urlsplit(self.path)
        if route.path=='/.well-known/openid-configuration':
            self.reply(200,dict(issuer=origin,authorization_endpoint=origin+'/authorize',token_endpoint=origin+'/token')); return
        if route.path=='/authorize':
            form = dict(urllib.parse.parse_qsl(route.query))
            assert form['client_id']=='packages-poc' and form['code_challenge_method']=='S256'
            assert form['redirect_uri']=='http://127.0.0.1:18743/callback'
            code = secrets.token_urlsafe(32)
            fixture.codes[code] = form
            self.send_response(302); self.send_header('Location',form['redirect_uri']+'?'+urllib.parse.urlencode(dict(code=code,state=form['state']))); self.end_headers(); return
        private = route.path.startswith('/private/')
        if not private and not route.path.startswith('/public/'): self.reply(404,{}); return
        if private:
            token = self.headers.get('Authorization','').removeprefix('Bearer ')
            if fixture.revoked or fixture.access.get(token,0)<time.time(): self.reply(401,{}); return
        path = (ROOT if private else OUT)/route.path.lstrip('/')
        if '..' in route.path or not path.is_file(): self.reply(404,{}); return
        if private:
            fixture.private_reads += 1
            if fixture.delay and path.name=='dependency-1.pom': time.sleep(5)
        else: fixture.public_reads += 1
        data = path.read_bytes(); self.send_response(200); self.send_header('Content-Length',str(len(data))); self.end_headers()
        if body: self.wfile.write(data)

def setup(tool,label):
    bootstrap = os.environ.get('PUBLISHED_BOOTSTRAP',origin+'/public/')
    project = ROOT/label
    if project.exists(): shutil.rmtree(project)
    project.mkdir()
    if tool=='maven':
        shutil.copy2(REPO/'mvnw',project/'mvnw')
        write(project/'.mvn/wrapper/maven-wrapper.properties',(REPO/'.mvn/wrapper/maven-wrapper.properties').read_text())
        write(project/'.mvn/extensions.xml','<extensions><extension><groupId>io.fluxzero.buildtools</groupId><artifactId>maven-extension</artifactId><version>VERSION_PLACEHOLDER</version></extension></extensions>'.replace('VERSION_PLACEHOLDER',VERSION))
        write(project/'.mvn/maven.config','--settings\n.mvn/settings.xml\n')
        write(project/'.mvn/settings.xml',f'<settings><profiles><profile><id>bootstrap</id><pluginRepositories><pluginRepository><id>public-bootstrap</id><url>{bootstrap}</url></pluginRepository></pluginRepositories></profile></profiles><activeProfiles><activeProfile>bootstrap</activeProfile></activeProfiles></settings>')
        write(project/'pom.xml','''<project><modelVersion>4.0.0</modelVersion><parent><groupId>local.private</groupId><artifactId>parent</artifactId><version>1</version><relativePath/></parent><artifactId>consumer</artifactId><version>1</version><properties><maven.compiler.release>17</maven.compiler.release></properties><repositories><repository><id>packages-private</id><url>REPOSITORY_PLACEHOLDER</url></repository></repositories><dependencies><dependency><groupId>local.private</groupId><artifactId>dependency</artifactId><version>1</version></dependency></dependencies></project>'''.replace('REPOSITORY_PLACEHOLDER',origin+'/private/'))
        return project,['./mvnw','-ntp',f'-Dmaven.repo.local={project}/cache','verify']
    shutil.copy2(REPO/'gradlew',project/'gradlew')
    shutil.copytree(REPO/'gradle/wrapper',project/'gradle/wrapper')
    write(project/'settings.gradle',f'''pluginManagement {{ repositories {{ maven {{ url = uri('{bootstrap}'); allowInsecureProtocol = true }} }} }}
plugins {{ id 'io.fluxzero.packages' version '{VERSION}' }}
rootProject.name = 'consumer'
new File(settingsDir, 'proxy-url').text = dependencyResolutionManagement.repositories.getByName('packagesPrivate').url.toString()
new File(settingsDir, 'daemon-pid').text = ProcessHandle.current().pid().toString()
''')
    write(project/'build.gradle', '''plugins { id 'java' }
dependencies { implementation 'local.private:dependency:1' }
tasks.register('resolvePrivate') { doLast { assert configurations.compileClasspath.files.size() == 1 } }
tasks.named('build') { dependsOn 'resolvePrivate' }
''')
    return project,['./gradlew','--no-configuration-cache','build']

def execute(tool,label,ci=False,expected=0,prepared=None):
    project,args = prepared or setup(tool,label)
    env = os.environ | {'PACKAGES_ISSUER':origin,'PACKAGES_CLIENT_ID':'packages-poc','PACKAGES_SCOPE':'openid offline_access packages:read',
        'PACKAGES_REPOSITORY':origin+'/private/','PACKAGES_SESSION_DIR':str(ROOT/'sessions'),
        'PACKAGES_BROWSER':str(ROOT/'simulated-browser'),'GRADLE_USER_HOME':str(ROOT/'gradle-home'),'CI':str(ci).lower()}
    started = time.time(); before = (fixture.logins,fixture.refreshes,fixture.private_reads)
    p = subprocess.run(args,cwd=project,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=240)
    if tool=='gradle' and (project/'proxy-url').exists():
        port = urllib.parse.urlsplit((project/'proxy-url').read_text()).port
        try:
            connection = socket.create_connection(('127.0.0.1',port),timeout=1)
        except ConnectionRefusedError: pass
        else:
            connection.close(); raise AssertionError('Proxy survived build completion')
    result = dict(case=label,exit=p.returncode,seconds=round(time.time()-started,1),logins=fixture.logins-before[0],refreshes=fixture.refreshes-before[1],private_reads=fixture.private_reads-before[2])
    print(json.dumps(result),flush=True)
    if (p.returncode==0)!=(expected==0):
        print(p.stdout[-12000:]); raise AssertionError(label)
    return result

if __name__=='__main__':
    build();
    if ROOT.exists(): shutil.rmtree(ROOT)
    ROOT.mkdir(exist_ok=True)
    sessions = ROOT/'sessions'
    if sessions.exists(): shutil.rmtree(sessions)
    write(ROOT/'private/local/private/parent/1/parent-1.pom',pom('parent','pom'))
    write(ROOT/'private/local/private/dependency/1/dependency-1.pom',pom('dependency'))
    with zipfile.ZipFile(ROOT/'private/local/private/dependency/1/dependency-1.jar','w') as jar: jar.writestr('proof.txt','private simulation artifact')
    for path in list((ROOT/'private').rglob('*.pom'))+list((ROOT/'private').rglob('*.jar')):
        write(Path(str(path)+'.sha1'),hashlib.sha1(path.read_bytes()).hexdigest())
    # Explicit non-browser driver: this is protocol simulation, never browser-login evidence.
    write(ROOT/'simulated-browser',f'#!{sys.executable}\nimport urllib.request,sys\nurllib.request.urlopen(sys.argv[1]).read()\n')
    (ROOT/'simulated-browser').chmod(0o700)
    server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    origin = f'http://127.0.0.1:{server.server_port}'
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        results=[]
        results.append(execute('maven','maven-ci-empty',ci=True,expected=1)); assert fixture.logins==0
        results.append(execute('maven','maven-first')); assert fixture.logins==1
        results.append(execute('maven','maven-reuse')); assert fixture.logins==1
        fixture.delay=True
        results.append(execute('maven','maven-expiry')); assert results[-1]['refreshes']>=1
        fixture.delay=False
        results.append(execute('gradle','gradle-shared-session')); assert fixture.logins==1
        # Remove only the synthetic private module from Gradle cache; public bootstrap stays cached in this case.
        for p in (ROOT/'gradle-home/caches').glob('modules-*/files-*/local.private'): shutil.rmtree(p)
        fixture.delay=True
        results.append(execute('gradle','gradle-expiry')); assert results[-1]['refreshes']>=1
        assert (ROOT/'gradle-expiry/daemon-pid').read_text()==(ROOT/'gradle-shared-session/daemon-pid').read_text()
        fixture.delay=False
        a=setup('maven','parallel-maven'); b=setup('gradle','parallel-gradle')
        for p in (ROOT/'gradle-home/caches').glob('modules-*/files-*/local.private'): shutil.rmtree(p)
        time.sleep(5)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            jobs=[pool.submit(execute,'maven','parallel-maven',prepared=a),pool.submit(execute,'gradle','parallel-gradle',prepared=b)]
            results.extend(j.result() for j in jobs)
        assert fixture.replays==0 and fixture.logins==1
        configuration_cache=setup('gradle','gradle-configuration-cache')
        configuration_cache=(configuration_cache[0],['./gradlew','--configuration-cache','build'])
        results.append(execute('gradle','gradle-configuration-cache',expected=1,prepared=configuration_cache))
        fixture.revoked=True
        results.append(execute('maven','maven-revoked',ci=True,expected=1))
        shutil.rmtree(sessions)
        results.append(execute('gradle','gradle-ci-empty',ci=True,expected=1)); assert fixture.logins==1
        report=dict(kind='SIMULATION',results=results,logins=fixture.logins,refreshes=fixture.refreshes,replays=fixture.replays)
        write(ROOT/'results.json',json.dumps(report,indent=2)); print(json.dumps(report,indent=2))
    finally:
        subprocess.run([str(REPO/'gradlew'),'-g',str(ROOT/'gradle-home'),'--stop'],stdout=subprocess.DEVNULL)
        server.shutdown()
        if sessions.exists(): shutil.rmtree(sessions)
