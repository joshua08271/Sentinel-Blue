"""Install and activate real packaged controller/agent processes in a private fixture.

No synthetic telemetry or direct database baseline updates are used. An incomplete
native inventory blocks acceptance, just as it does in the competition opening.
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import ssl
import sqlite3
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen

from sentinel_blue import __version__
from sentinel_blue.collectors import integrity_watch_paths
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.launcher import deployment_plan, execute_plan
from sentinel_blue.opening import assess_defender
from sentinel_blue.state import write_private_json
from tools.measure_setup_acceptance import runtime_command
from tools.setup_native_inputs import free_port, manifest
from tools.smoke_release import _operator_headers, _stop_process


class NativeDefender:
    def __init__(self, root, runtime, inventory, *, started_at, budget=180):
        self.root, self.source, self.started_at = root, runtime, started_at
        self.deadline = time.monotonic() + budget - (time.time()-started_at)
        self.children, self.logs = [], []
        self.last_snapshot = {}
        self.audit_scope = None
        self.audit_state = None
        self.prepared = False
        self.preparation_attempted = False
        self.preparation_seconds = 0.0
        self.phase_seconds = {}
        self.root.mkdir(mode=0o700)
        self.runtime = self.root/'controller.pyz'
        shutil.copyfile(runtime,self.runtime)
        self.digest = hashlib.sha256(runtime.read_bytes()).hexdigest()
        if hashlib.sha256(self.runtime.read_bytes()).hexdigest()!=self.digest:
            raise RuntimeError('controller installation digest mismatch')
        self.token, self.operator = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        self.principal, self.epoch = 'native-opening-operator', 2
        self.cert, self.key = self.root/'controller.crt', self.root/'controller.key'
        self._certificate()
        self.origin = 'https://127.0.0.1:'+str(free_port())
        self.context = ssl.create_default_context(cafile=str(self.cert))
        profile = copy.deepcopy(inventory['event_profile'])
        profile['profile_id'] = 'native-complete-opening'
        profile['scope']['approved_deployment_paths'] = [str(self.root)]
        profile['release']['controller_ca_sha256'] = hashlib.sha256(self.cert.read_bytes()).hexdigest()
        # Native testing grants capture of the listed files, not a general claim
        # that the starting machine is clean. Independent persistence alerts remain.
        protected = integrity_watch_paths()
        extra = [str(row['path']) for task in inventory['setup']['tasks']
                 for row in task.get('options',{}).get('files',[])]
        protected = list(dict.fromkeys(protected+extra))
        if len(protected)>256:
            raise ValueError('native opening protected paths exceed the agent bound')
        host_manifest = manifest('native-host-baseline','https',int(self.origin.rsplit(':',1)[1]),
            [{'kind':'https','target':self.origin+'/api/v1/health','verify':True,
              'ca_file':str(self.cert),'ca_sha256':profile['release']['controller_ca_sha256']}])
        host_manifest['required_files'] = protected
        host_manifest['allowed_automatic_actions'] = ['capture_restore_point']
        profile['services'].append(host_manifest)
        self.profile = EventProfile.from_dict(profile)
        self.profile_path = self.root/'profile.json'
        write_private_json(self.profile_path,profile)
        self.probes = [spec for service in inventory['event_profile']['services']
                       for spec in service['expected_transactions']]
        self.probe_path = self.root/'probes.json'
        write_private_json(self.probe_path,{'probes':self.probes, 'protected_paths':extra})
        write_private_json(self.root/'enrollment.json',{'token':self.token})
        (self.root/'operator.txt').write_text(self.operator); (self.root/'operator.txt').chmod(0o600)
        (self.root/'recovery.key').write_bytes(secrets.token_bytes(48)); (self.root/'recovery.key').chmod(0o600)
        self.inventory = {'authorized_networks':['127.0.0.0/8'], 'hosts':[{
            'name':'target','agent_id':'target','address':'127.0.0.1',
            'platform':'windows' if os.name=='nt' else 'linux','transport':'local',
            'install_directory':str(self.root/'agent-install'), 'event_profile':str(self.profile_path),
            'controller_ca_file':str(self.cert), 'probe_config':str(self.probe_path),
            'range_deployment':True}]}
        self.plan = {'release_version':__version__,'profile_fingerprint':self.profile.fingerprint,
                     'controller':{'expected_mode':'range-autonomous'},'expected_agents':['target']}

    def remaining(self):
        value = self.deadline-time.monotonic()
        if value<=0:
            raise TimeoutError('original complete-opening deadline exhausted')
        return value

    def _certificate(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'127.0.0.1')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
                .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
                .sign(key,hashes.SHA256()))
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        self.key.chmod(0o600)

    def command(self, runtime, args, name, *, background=False):
        stream = (self.root/(name+'.log')).open('w')
        self.logs.append(stream)
        command = runtime_command(runtime,args)
        if background:
            process = subprocess.Popen(command,stdout=stream,stderr=subprocess.STDOUT)
            self.children.append(process)
            return process
        result = subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,timeout=self.remaining())
        if result.returncode:
            raise RuntimeError(name+' failed; private log retained')

    def request(self, target, payload=None):
        # Authenticated reads can be retried after transient load. A timed-out
        # mutation remains uncertain and is never silently submitted twice.
        while True:
            try:
                return self._request(target, payload)
            except (TimeoutError, ConnectionError):
                if payload is not None:
                    raise
                time.sleep(min(0.2, self.remaining()))

    def _request(self, target, payload=None):
        with urlopen(self.origin+'/api/v1/operator/auth-info',context=self.context,timeout=min(3,self.remaining())) as response:
            metadata=json.load(response)
        body=b'' if payload is None else json.dumps(payload).encode()
        method='GET' if payload is None else 'POST'
        headers=_operator_headers(self.operator,principal_id=self.principal,credential_epoch=self.epoch,
                                  method=method,target=target,body=body,
                                  request_timestamp=max(int(time.time()),int(metadata['request_not_before'])))
        headers['Content-Type']='application/json'
        request=Request(self.origin+target,data=body if payload is not None else None,headers=headers,method=method)
        with urlopen(request,context=self.context,timeout=min(10,self.remaining())) as response:
            return json.load(response)

    def prepare(self):
        """Prepare private controller/package state while service setup runs."""
        if self.prepared:
            return
        if self.preparation_attempted:
            raise RuntimeError('uncertain defender preparation cannot be replayed')
        self.preparation_attempted = True
        began = time.monotonic()
        if os.name == 'nt':
            from sentinel_blue.windows_audit import temporary_logon_auditing
            self.audit_scope = temporary_logon_auditing()
            self.audit_state = self.audit_scope.__enter__()
        common=['--database',str(self.root/'controller.db'),'--recovery-key-file',str(self.root/'recovery.key'),
                '--recovery-anchor',str(self.root/'recovery.anchor')]
        self.command(self.runtime,['recovery-init',*common],'recovery-init')
        controller=self.command(self.runtime,['controller','--bind','127.0.0.1','--port',self.origin.rsplit(':',1)[1],
            '--event-profile',str(self.profile_path),'--range-deployment','--token-file',str(self.root/'enrollment.json'),
            '--operator-token-file',str(self.root/'operator.txt'),'--operator-principal-id',self.principal,
            '--operator-credential-epoch',str(self.epoch),'--tls-cert',str(self.cert),'--tls-key',str(self.key),
            '--tls-ca-file',str(self.cert),'--auto-recover-services','--maintenance-interval','2',*common],
            'controller',background=True)
        while True:
            if controller.poll() is not None:
                raise RuntimeError('installed controller exited')
            try:
                self.request('/api/v1/dashboard')
                break
            except OSError:
                self.remaining(); time.sleep(0.1)
        deployments=execute_plan(deployment_plan(self.inventory,event_profile=self.profile),
            self.inventory,self.source,self.digest,self.origin,self.token,budget_seconds=self.remaining())
        if len(deployments)!=1 or deployments[0]['status']!='staged':
            raise RuntimeError('native agent installation failed')
        deployment=deployments[0]
        self.controller, self.deployment = controller, deployment
        self.preparation_seconds = round(time.monotonic()-began,3)
        self.prepared = True

    def start(self):
        self.prepare()
        controller, deployment = self.controller, self.deployment
        agent=self.command(Path(deployment['package']),['agent','--controller',self.origin,
            '--event-profile',deployment['event_profile'],'--range-deployment',
            '--token-file',deployment['token_file'],'--agent-id','target',
            '--ca-file',deployment['ca_file'],'--probe-config',deployment['probe_config'],
            '--state-dir',str(self.root/'agent-state'),'--expected-package-sha256',self.digest,
            '--allow-restoration','--allow-service-recovery','--interval','5'],'agent',background=True)
        self.phase_seconds['agent_launched'] = round(time.time()-self.started_at,3)
        approved=False
        while self.remaining()>0:
            if controller.poll() is not None or agent.poll() is not None:
                raise RuntimeError('installed defender process exited')
            snapshot=self.request('/api/v1/dashboard')
            self.last_snapshot = snapshot
            rows=[row for row in snapshot.get('agents',[]) if row['agent_id']=='target']
            if rows:
                self.phase_seconds.setdefault('agent_first_visible',round(time.time()-self.started_at,3))
            if rows and rows[0].get('baseline_readiness',{}).get('ready') is True and not approved:
                self.phase_seconds['baseline_ready'] = round(time.time()-self.started_at,3)
                self.request('/api/v1/governance/mode',{'mode':'range-autonomous'})
                self.request('/api/v1/governance/resume',{})
                self.request('/api/v1/agents/target/baseline/approve',{})
                self.phase_seconds['approval_requested'] = round(time.time()-self.started_at,3)
                approved=True
            result=assess_defender(snapshot,self.plan,time.time(),self.started_at)
            write_private_json(self.root/'readiness.json',{'readiness':result,'agents':rows,
                'controller':snapshot.get('controller',{})})
            if result['ready']:
                return {'ready':True,'seconds_from_original_start':round(time.time()-self.started_at,3),
                        'authenticated_readiness':result,'installation_verified':True,
                        'controller_and_agent_running':True,'baseline_approved_by_fixture':True,
                        'private_preparation_seconds':self.preparation_seconds,
                        'phase_seconds_from_original_start':self.phase_seconds}
            time.sleep(min(0.5,self.remaining()))

    def diagnostics(self):
        snapshot = self.last_snapshot
        errors = {}
        # Read only this fixture's private database. Diagnostic reads never
        # approve a baseline or alter the authenticated acceptance result.
        try:
            with sqlite3.connect((self.root/'controller.db').as_uri()+'?mode=ro',uri=True,timeout=1) as database:
                for agent_id, raw in database.execute('SELECT agent_id, latest_telemetry FROM agents'):
                    errors[agent_id] = json.loads(raw or '{}').get('collector_errors',[])
        except (OSError,sqlite3.Error,ValueError):
            errors['diagnostic'] = ['private telemetry diagnostics unavailable']
        return {'readiness': assess_defender(snapshot,self.plan,time.time(),self.started_at),
                'phase_seconds_from_original_start':self.phase_seconds,
                'agents': [{'agent_id': row.get('agent_id'),
                            'baseline_status': row.get('baseline_status'),
                            'baseline_readiness': row.get('baseline_readiness'),
                            'collector_errors': errors.get(row.get('agent_id'),[])}
                           for row in snapshot.get('agents',[])]}

    def inventory_section_seconds(self):
        """Return only the first collection's fixed-name performance counters."""
        from sentinel_blue.windows_queries import WINDOWS_QUERIES
        marker = 'Windows native inventory section seconds: '
        try:
            with (self.root/'agent.log').open(encoding='utf-8', errors='replace') as stream:
                contents = stream.read(1024 * 1024)
            for line in contents.splitlines():
                if marker not in line:
                    continue
                row = json.loads(line.split(marker, 1)[1])
                if (isinstance(row, dict) and set(row) == set(WINDOWS_QUERIES)
                        and all(type(value) in (int, float) and 0 <= value <= 1800 for value in row.values())):
                    return row
        except (OSError, ValueError):
            pass
        return {}

    def close(self):
        failures = []
        for child in reversed(self.children):
            try:
                _stop_process(child)
            except Exception as exc:
                failures.append(type(exc).__name__)
        for stream in self.logs:
            stream.close()
        if self.audit_scope is not None and self.audit_state is not None:
            try:
                self.audit_scope.__exit__(None,None,None)
            except Exception as exc:
                failures.append(type(exc).__name__)
        return {'verified':not failures and all(child.poll() is not None for child in self.children),
                'audit_policy':self.audit_state,'errors':failures}
