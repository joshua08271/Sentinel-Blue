"""Exercise the running agent's capture/telemetry ordering, including slow collection."""
import copy
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock,patch
from sentinel_blue.agent import _run_with_windows_state_guard
from sentinel_blue import __version__

class EndCycle(BaseException):
    pass

class AgentCaptureOrderTests(unittest.TestCase):
    def test_approved_capture_is_not_overtaken_by_next_telemetry(self):
        for arrival in ['between_cycles','during_collection']:
            with self.subTest(arrival=arrival),tempfile.TemporaryDirectory() as directory:
                state={'pending':False,'captured':False,'collections':0,'waits':0};sent=[]
                client=MagicMock();client.agent_token='a'*64;client.token=''
                profile=MagicMock();profile.release={'sha256':''};profile.authorized_networks=();profile.authorized_hosts=();profile.excluded_hosts=();profile.fingerprint='a'*64;profile.profile_id='profile-one';profile.allows.return_value=True;profile.assert_inventory_networks=MagicMock()
                lock=MagicMock();lock.acquire.return_value=lock;watcher=MagicMock()
                args=SimpleNamespace(log_level='WARNING',agent_id='agent-one',event_profile='profile.json',range_deployment=False,expected_package_sha256=None,authorized_network=[],allow_containment=False,allow_restoration=False,state_dir=directory,log_file=None,controller='https://127.0.0.1:8765',token='t'*64,token_file=None,reenroll=False,ca_file=None,spool_limit=16,probe_config=None,quarantine_ttl=300.0,change_watch_interval=1.0,once=False,interval=5)
                def collect(*a,**kw):
                    state['collections']+=1
                    if state['collections']==2 and arrival=='during_collection':state['pending']=True
                    return SimpleNamespace(as_dict=lambda:{'agent_id':'agent-one','agent_version':__version__,'hostname':'host','platform':'Linux','boot_id':'boot-one','observed_at':float(state['collections']),'collector_errors':[],'probes':[],'integrity':[]})
                def actions(_client,_outbox,_journal,_executor,telemetry,_health,_profile):
                    if state['pending']:
                        self.assertEqual(telemetry['sequence'],1)
                        state['pending']=False;state['captured']=True;return 1
                    return 0
                def receive(telemetry):
                    if sent:self.assertTrue(state['captured'],'new telemetry invalidated an approved capture')
                    sent.append(copy.deepcopy(telemetry))
                def wait(_seconds):
                    state['waits']+=1
                    if state['waits']==2:raise EndCycle
                    if arrival=='between_cycles':state['pending']=True
                    return False
                client.telemetry.side_effect=receive;watcher.wait.side_effect=wait
                with (
                    patch('sentinel_blue.agent.configure_agent_logging'),
                    patch('sentinel_blue.agent.load_event_profile',return_value=profile),
                    patch('sentinel_blue.agent.AgentProcessLock',return_value=lock),
                    patch('sentinel_blue.agent.AgentClient',return_value=client),
                    patch('sentinel_blue.agent.load_agent_credentials',return_value=('','a'*64,None)),
                    patch('sentinel_blue.agent.ActionExecutor',return_value=MagicMock()),
                    patch('sentinel_blue.agent.ChangeWatcher',return_value=watcher),
                    patch('sentinel_blue.agent.collect',side_effect=collect),
                    patch('sentinel_blue.agent.assess_agent_health',side_effect=lambda *a:{'healthy':True,'action_safe':True,'errors':[],'critical_errors':[]}),
                    patch('sentinel_blue.agent.refresh_windows_state_health'),
                    patch('sentinel_blue.agent.refresh_recovery_health'),
                    patch('sentinel_blue.agent.process_controller_actions',side_effect=actions),
                    patch('sentinel_blue.agent.systemd_notify'),
                    patch('sentinel_blue.agent.atexit.register'),
                ):
                    with self.assertRaises(EndCycle):_run_with_windows_state_guard(args,None)
                self.assertTrue(state['captured'])
                self.assertEqual([x['sequence'] for x in sent],[1,2])
                if arrival=='during_collection':self.assertEqual([x['observed_at'] for x in sent],[1.0,3.0])
