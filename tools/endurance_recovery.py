"""Exercise durable recovery over real loopback HTTP and owned subprocesses.

The service adapter controls only children created here. It is deliberately
separate from native systemd/SCM validation. Production cooldowns, manifests,
file preflight, signed requests, action journals, and result delivery are used
unchanged. The clock is never accelerated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError


def serve(path: str, port: int) -> None:
    secret = os.environ.get('SB_OWNED_ENDPOINT_TOKEN', '')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if secret and self.headers.get('Authorization') != 'Bearer ' + secret:
                self.send_response(403)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            body = Path(path).read_bytes()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()


class OwnedService:
    def __init__(self, path: Path, secret: str = ''):
        self.path, self.secret = path, secret
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        self.url = f'http://127.0.0.1:{self.port}/health'
        self.process = None
        self.starts = 0

    def healthy(self) -> bool:
        headers = {'Authorization': 'Bearer ' + self.secret} if self.secret else {}
        try:
            with urlopen(Request(self.url, headers=headers), timeout=1) as response:
                return response.status == 200 and response.read() == self.path.read_bytes()
        except OSError:
            return False

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError('owned service is already running')
        self.process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), '--serve', str(self.path), str(self.port)],
            env={**os.environ, 'SB_OWNED_ENDPOINT_TOKEN': self.secret},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.starts += 1
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.healthy():
                return
            if self.process.poll() is not None:
                raise RuntimeError('owned service exited during startup')
            time.sleep(.05)
        raise RuntimeError('owned service did not become healthy')

    def stop(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def campaign(duration: float, runtime: Path | None) -> dict:
    if runtime is not None:
        sys.path.insert(0, str(runtime.resolve(strict=True)))
    from sentinel_blue import __version__
    from sentinel_blue.actions import ActionExecutor
    from sentinel_blue.agent import (AgentClient, ActionResultOutbox, execute_queued_action,
                                      deliver_pending_action_results)
    from sentinel_blue.controller import ControllerApp, ControllerServer, make_handler
    from sentinel_blue.event_profile import EventProfile
    from sentinel_blue.health import assess_agent_health
    from sentinel_blue.probes import run_probes
    from sentinel_blue.protocol import Telemetry, Account, Service
    from sentinel_blue.state import ActionJournal, SequenceCounter
    from sentinel_blue.store import Store
    from smoke_release import _operator_headers

    started = time.monotonic()
    report = {'schema_version': 1, 'version': __version__, 'status': 'failed',
              'requested_duration_seconds': duration,
              'runtime_sha256': hashlib.sha256(runtime.read_bytes()).hexdigest() if runtime else None,
              'recoveries': [], 'holds_observed': [], 'scored_samples': 0, 'scored_healthy_samples': 0,
              'outage_held_samples': 0,
              'request_timings': {},
              'control_samples': 0, 'control_healthy_samples': 0,
              'limitations': ['owned process service adapter; not native systemd or SCM',
                              'fixture inventory; not a full native host agent',
                              'loopback signed HTTP; packaged TLS and process crashes are tested separately',
                              'bounded rehearsal; no full-event competition certification']}
    stop_sampler = threading.Event()
    sampler_thread = None
    server = thread = store = scored = control = None

    with tempfile.TemporaryDirectory(prefix='sentinel-blue-endurance-') as directory:
        root = Path(directory).resolve(strict=True)
        config = root / 'approved.conf'
        config.write_bytes(b'approved healthy transaction\n')
        config.chmod(0o600)
        state = root / 'agent'
        state.mkdir(mode=0o700)
        scored = OwnedService(config)
        control = OwnedService(config, secrets.token_urlsafe(32))
        bootstrap, operator = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        agent_id, service_id = 'endurance-agent', 'owned.service'
        controller_port = 0
        app = None

        def measured_request(label, operation):
            before = time.monotonic()
            row = report['request_timings'].setdefault(label, {'count': 0, 'errors': 0, 'maximum_seconds': 0})
            row['count'] += 1
            try:
                return operation()
            except Exception as exc:
                row['errors'] += 1
                report['failed_request'] = label
                report['failed_request_error_type'] = type(exc).__name__
                raise
            finally:
                row['maximum_seconds'] = round(max(row['maximum_seconds'], time.monotonic() - before), 3)

        class FixtureExecutor(ActionExecutor):
            def _service_state(self, service):
                if service != service_id:
                    raise ValueError('service is not the exact owned fixture')
                return 'running' if scored.process is not None and scored.process.poll() is None else 'stopped'

            def _set_service_state(self, service, desired):
                if service != service_id or desired not in ('running', 'stopped'):
                    raise ValueError('service mutation is outside the owned fixture')
                (scored.start if desired == 'running' else scored.stop)()

        try:
            scored.start()
            control.start()
            try:
                urlopen(control.url, timeout=2).close()
            except HTTPError as exc:
                if exc.code != 403:
                    raise
            else:
                raise RuntimeError('protected control endpoint accepted an unsigned request')
            report['control_endpoint_requires_credential'] = True
            probe = {'name': 'scored-health', 'kind': 'http', 'target': scored.url,
                     'expected_status': [200], 'expected_body': 'approved healthy transaction', 'timeout': 1}
            raw = EventProfile.testing().raw
            raw['profile_id'] = 'owned-endurance-recovery'
            raw['scope'].update(authorized_networks=['127.0.0.0/8'], authorized_hosts=['127.0.0.1'],
                                controller_ingress_hosts=['127.0.0.1'], approved_deployment_paths=[str(root)])
            raw['official_identities'] = [{'agent_id': agent_id, 'name': 'fixture-organizer',
                                           'class': 'organizer', 'source': 'owned fixture'}]
            raw['services_confirmed'] = True
            raw['services'] = [{
                'service_id': service_id, 'host': agent_id, 'protocol': 'http', 'port': scored.port,
                'implementation': 'owned subprocess fixture', 'dependencies': [],
                'required_accounts': ['fixture-organizer'], 'required_files': [str(config)],
                'required_data': [], 'credential_source': 'owned fixture', 'expected_transactions': [probe],
                'local_checks': ['owned process handle'],
                'allowed_automatic_actions': ['restart_service', 'capture_restore_point'],
                'approval_actions': ['capture_restore_point'], 'backup_method': 'real restore point',
                'recovery_method': 'start exact child', 'rollback_method': 'stop exact child',
            }]
            profile = EventProfile.from_dict(raw)

            def open_controller():
                nonlocal server, thread, store, app, controller_port
                store = Store(root / 'controller.db')
                app = ControllerApp(store, bootstrap, operator_token=operator,
                                    event_profile=profile, auto_recover_services=True)
                server = ControllerServer(('127.0.0.1', controller_port), make_handler(app))
                controller_port = server.server_port
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

            def close_controller():
                nonlocal server, thread, store
                if server is not None:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=5)
                    if thread.is_alive():
                        raise RuntimeError('controller fixture failed to drain')
                    server = None
                if store is not None:
                    store.close()
                    store = None

            open_controller()
            origin = f'http://127.0.0.1:{controller_port}'

            def operator_request(target, payload=None):
                body = b'' if payload is None else json.dumps(payload).encode()
                method = 'GET' if payload is None else 'POST'
                with urlopen(origin + '/api/v1/operator/auth-info', timeout=12) as response:
                    info = json.loads(response.read())
                headers = _operator_headers(operator, principal_id=info['principal_id'],
                                            credential_epoch=info['credential_epoch'], method=method,
                                            target=target, body=body,
                                            request_timestamp=max(int(time.time()), int(info['request_not_before'])))
                headers['Content-Type'] = 'application/json'
                with urlopen(Request(origin + target, data=body if payload is not None else None,
                                     method=method, headers=headers), timeout=12) as response:
                    return json.loads(response.read())

            client = AgentClient(origin, bootstrap, agent_id,
                                 profile_id=profile.profile_id, profile_fingerprint=profile.fingerprint)
            credential = client.enroll('owned-fixture', platform.system() + ' fixture')
            journal = ActionJournal(state)
            outbox = ActionResultOutbox(journal)
            sequence = SequenceCounter(state)

            def executor_for_state():
                return FixtureExecutor(state, allow_restoration=True, allow_service_recovery=True,
                                       authorized_networks=['127.0.0.0/8'], authorized_hosts=['127.0.0.1'])

            executor = executor_for_state()
            next_observation_at = 0.0

            def observe():
                nonlocal next_observation_at
                # Stay below the production one-observation-per-second limit;
                # repeated telemetry must not manufacture a burst exemption.
                time.sleep(max(0, next_observation_at - time.monotonic()))
                before = time.time()
                data, metadata = executor.restore_points._read_target(config)
                telemetry = Telemetry(agent_id, 'owned-fixture', platform.system() + ' fixture', before,
                                      accounts=[Account('fixture-organizer', '1000', enabled=True)],
                                      services=[Service(service_id, executor._service_state(service_id), 'enabled')],
                                      probes=run_probes([probe], ['127.0.0.0/8'], authorized_hosts=['127.0.0.1']),
                                      boot_id='owned-fixture-boot', sequence=sequence.next(),
                                      profile_id=profile.profile_id, profile_fingerprint=profile.fingerprint).as_dict()
                telemetry['integrity'] = [{'path': str(config), 'sha256': hashlib.sha256(data).hexdigest(),
                                          'size': len(data), 'modified_at': config.stat().st_mtime,
                                          'security_descriptor_sha256': executor.restore_points._metadata_security_descriptor_sha256(metadata)}]
                measured_request('telemetry', lambda: client.telemetry(telemetry))
                next_observation_at = time.monotonic() + 1.05
                return telemetry

            def execute(action, telemetry):
                health = assess_agent_health(state, report['runtime_sha256'], runtime)
                result = execute_queued_action(journal, executor, action, telemetry, health, profile)
                if result.get('success') is not True or result.get('dry_run') is True:
                    raise RuntimeError('owned action failed: ' + str(result.get('message', 'unknown')))
                outbox.enqueue(action['action_id'], result)
                return result

            baseline = observe()
            operator_request(f'/api/v1/agents/{agent_id}/baseline/approve', {})
            captures = client.actions()
            if len(captures) != 1 or captures[0]['action_type'] != 'capture_restore_point':
                raise RuntimeError('baseline did not require an exact real capture')
            execute(captures[0], baseline)
            deliver_pending_action_results(client, outbox)
            if outbox.has_unacknowledged() or store.baseline_status(agent_id) != 'approved':
                raise RuntimeError('authenticated capture did not promote the baseline')
            report['baseline_capture_verified'] = True

            def sampler():
                while not stop_sampler.is_set():
                    report['scored_samples'] += 1
                    report['scored_healthy_samples'] += int(scored.healthy())
                    report['control_samples'] += 1
                    report['control_healthy_samples'] += int(control.healthy())
                    stop_sampler.wait(.25)

            sampler_thread = threading.Thread(target=sampler, daemon=True)
            sampler_thread.start()
            outage_started = None
            end = time.monotonic() + duration
            disconnected = False
            while time.monotonic() < end:
                if outage_started is None and (not report['recoveries'] or end - time.monotonic() > 305):
                    scored.stop()
                    outage_started = time.monotonic()
                telemetry = observe()
                for action in measured_request('actions', client.actions):
                    if action['action_type'] == 'snapshot':
                        execute(action, telemetry)
                        deliver_pending_action_results(client, outbox)
                        continue
                    if action['action_type'] != 'restart_service' or not action['automated']:
                        raise RuntimeError('unexpected action in the owned recovery campaign: ' +
                                           str(action.get('action_type')) + ', automated=' + str(action.get('automated')))
                    execute(action, telemetry)
                    restored_at = time.monotonic()
                    if not disconnected:
                        # The action result is durable but has never reached the
                        # controller. Reopen both journals across a real outage.
                        close_controller()
                        if deliver_pending_action_results(client, outbox) != 0 or not outbox.has_unacknowledged():
                            raise RuntimeError('disconnected result was not retained')
                        journal = ActionJournal(state)
                        outbox = ActionResultOutbox(journal)
                        sequence = SequenceCounter(state)
                        executor = executor_for_state()
                        open_controller()
                        client = AgentClient(origin, '', agent_id, agent_token=credential,
                                             profile_id=profile.profile_id, profile_fingerprint=profile.fingerprint)
                        count_before = scored.starts
                        retry_deadline = time.monotonic() + 20
                        while outbox.has_unacknowledged() and time.monotonic() < retry_deadline:
                            deliver_pending_action_results(client, outbox)
                            time.sleep(.25)
                        if outbox.has_unacknowledged() or scored.starts != count_before:
                            raise RuntimeError('durable result did not reconcile without another start')
                        report['disconnected_result_reconciled_without_repeat'] = True
                        disconnected = True
                    else:
                        deliver_pending_action_results(client, outbox)
                    if not scored.healthy():
                        raise RuntimeError('successful recovery did not restore the real transaction')
                    report['recoveries'].append({'outage_seconds': round(restored_at - outage_started, 3),
                                                 'result_acknowledgement_seconds': round(time.monotonic() - restored_at, 3),
                                                 'attempt': len(report['recoveries']) + 1})
                    outage_started = None
                    observe()  # A genuinely healthy sample closes this outage episode.
                row = measured_request('dashboard', lambda: operator_request('/api/v1/dashboard'))['controller']['service_recovery_status'][0]
                if row['budget']['reason'] and row['budget']['reason'] not in report['holds_observed']:
                    report['holds_observed'].append(row['budget']['reason'])
                if outage_started is not None and not row['budget']['allowed']:
                    report['outage_held_samples'] += 1
                time.sleep(.5)
            report['unfinished_outage'] = outage_started is not None
            report['automatic_recoveries'] = len(report['recoveries'])
            report['real_service_starts'] = scored.starts
            report['duration_seconds'] = round(time.monotonic() - started, 3)
            expected_recoveries = 2 if duration >= 330 else 1
            report['status'] = 'passed' if (len(report['recoveries']) >= expected_recoveries and not outbox.has_unacknowledged()
                                          and scored.starts == 1 + len(report['recoveries'])
                                          and not report['unfinished_outage']
                                          and report['control_samples'] == report['control_healthy_samples']) else 'failed'
        except Exception as exc:
            report['error'] = str(exc)[:500]
        finally:
            stop_sampler.set()
            if sampler_thread is not None:
                sampler_thread.join(timeout=5)
            if server is not None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            if store is not None:
                store.close()
            for service in (scored, control):
                if service is not None:
                    service.stop()
            report['cleanup_verified'] = (all(service is None or service.process is None or service.process.poll() is not None
                                               for service in (scored, control))
                                           and (sampler_thread is None or not sampler_thread.is_alive())
                                           and (thread is None or not thread.is_alive()))
            if not report['cleanup_verified']:
                report['status'] = 'failed'
    for name in ('scored', 'control'):
        count = report[name + '_samples']
        report[name + '_sampled_uptime_percent'] = round(100 * report[name + '_healthy_samples'] / count, 3) if count else None
    report['full_competition_milestone_complete'] = False
    return report


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--serve':
        serve(sys.argv[2], int(sys.argv[3]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--duration-seconds', type=float, default=330)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 5 <= args.duration_seconds <= 28800:
        parser.error('duration must be 5..28800 real seconds')
    logging.basicConfig(level=logging.ERROR)
    report = campaign(args.duration_seconds, args.runtime)
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    args.output.write_text(encoded, encoding='utf-8')
    print(encoded, end='')
    raise SystemExit(0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
