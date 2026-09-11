"""Private, expiring Azure Blob staging for the operator's own lab payloads."""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse


def cli(*args):
    result = subprocess.run(['az', *args, '--only-show-errors', '-o', 'json'],
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError('Azure private staging command failed: '+args[0]+' '+args[1])
    return json.loads(result.stdout) if result.stdout.strip() else None


@contextlib.contextmanager
def private_payload(path: Path, *, account: str, group: str):
    """Never grant anonymous access or modify an existing container."""
    state = cli('storage', 'account', 'show', '--name', account, '--resource-group', group)
    if state.get('allowBlobPublicAccess') is not False:
        raise ValueError('The lab staging account must already disallow public blobs')
    endpoint = state['primaryEndpoints']['blob']
    if urlparse(endpoint).scheme != 'https' or urlparse(endpoint).hostname != account+'.blob.core.windows.net':
        raise ValueError('Unexpected storage endpoint')
    container = 'sentinel-test-'+secrets.token_hex(12)
    common = ['--account-name',account,'--auth-mode','key']
    started = time.monotonic()
    created = False
    try:
        result = cli('storage','container','create','--name',container,'--public-access','off',*common)
        if result.get('created') is not True:
            raise RuntimeError('Private test container already exists')
        created = True
        cli('storage','blob','upload','--container-name',container,'--name','payload.zip',
            '--file',str(path),'--overwrite','false',*common)
        expiry = (datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=45)).strftime('%Y-%m-%dT%H:%MZ')
        token = cli('storage','blob','generate-sas','--container-name',container,'--name','payload.zip',
                    '--permissions','r','--expiry',expiry,'--https-only',*common)
        if not isinstance(token,str) or not token:
            raise RuntimeError('Private download authorization unavailable')
        yield {'url':endpoint+container+'/payload.zip?'+token,
               'staging_seconds':round(time.monotonic()-started,3), 'container':container}
    finally:
        if created:
            cli('storage','container','delete','--name',container,*common)
            if cli('storage','container','exists','--name',container,*common).get('exists') is not False:
                raise RuntimeError('Private test container deletion was not verified')
