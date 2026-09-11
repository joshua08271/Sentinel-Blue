"""Reproduce slow HTTP probe/readiness peers using only owned loopback sockets."""
from __future__ import annotations
import argparse
import http.server
import json
from pathlib import Path
import statistics
import sys
import tempfile
import threading
import time


class Peer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with self.server.guard:
            self.server.active += 1
        try:
            body=b'{"fixture":"ready"}'
            self.send_response(200)
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            delay=self.server.delay
            for byte in body:
                self.wfile.write(bytes([byte])); self.wfile.flush()
                if delay: time.sleep(delay)
        except OSError:
            pass
        finally:
            with self.server.guard:
                self.server.active -= 1

    def log_message(self,*_):
        pass


def rehearse(repeats=30,budget=.25):
    if type(repeats) is not int or not 1<=repeats<=100 or not .2<=budget<=2:
        raise ValueError('repeats must be 1..100 and budget .2..2 seconds')
    from sentinel_blue import __version__, opening, probes
    pools=tuple(pool for pool in (getattr(probes,'_PROBE_REQUESTS',None),
                                  getattr(opening,'_READINESS_REQUESTS',None)) if pool is not None)
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Peer)
    server.guard=threading.Lock(); server.active=0; server.delay=.06
    thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.02),daemon=True)
    thread.start()
    rows=[]; controls={}; removed=False
    started=time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='sentinel-probe-timing-') as directory:
            token=Path(directory)/'token';token.write_text('a'*64);token.chmod(0o600)
            origin='http://127.0.0.1:'+str(server.server_port)
            plan={'controller':{'origin':origin,'operator_token_file':str(token),
                                'operator_principal':'owned-test','operator_epoch':1}}
            spec={'kind':'http','target':origin,'timeout':budget,'expected_body':'ready'}
            for _ in range(repeats):
                for kind in ('http_probe','opening_readiness'):
                    before=time.monotonic(); rejected=False
                    try:
                        if kind=='http_probe':
                            result=probes.run_probe(spec,['127.0.0.0/8'])
                            rejected=not result.healthy and 'deadline' in result.detail
                        else:
                            opening.read_dashboard(plan,budget)
                    except TimeoutError:
                        rejected=True
                    elapsed=time.monotonic()-before
                    rows.append({'component':kind,'seconds':round(elapsed,4),
                                 'late_result_rejected':rejected,'bounded':elapsed<budget+.35})
            server.delay=0
            controls['healthy_http_after']=probes.run_probe(spec,['127.0.0.0/8']).healthy
            controls['healthy_readiness_after']=opening.read_dashboard(plan,1)=={'fixture':'ready'}
    finally:
        server.shutdown(); server.server_close(); thread.join(2)
        for pool in pools:
            for request in pool._requests:
                if request._worker is not None: request._worker.join(1)
        due=time.monotonic()+2
        while server.active and time.monotonic()<due: time.sleep(.01)
        removed=not thread.is_alive() and not server.active and all(not request.running
            for pool in pools for request in pool._requests)
    values=[row['seconds'] for row in rows]
    return {'version':__version__,'scope':'owned loopback HTTP service and opening-readiness peers',
            'budget_seconds':budget,'trials':rows,'controls':controls,'cleanup_verified':removed,
            'minimum_seconds':min(values),'median_seconds':statistics.median(values),'maximum_seconds':max(values),
            'seconds':round(time.monotonic()-started,3),
            'passed':all(row['late_result_rejected'] and row['bounded'] for row in rows)
                     and all(controls.values()) and removed}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repeats',type=int,default=30)
    args=parser.parse_args()
    sys.path.insert(0,str(args.runtime.resolve(strict=True)))
    report=rehearse(args.repeats)
    args.output.write_text(json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='trials'}))
    raise SystemExit(0 if report['passed'] else 1)
