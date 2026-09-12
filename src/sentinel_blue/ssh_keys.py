"""Parse the key field, never key-looking text in options or comments."""
from __future__ import annotations

import base64
import hashlib
import re

KEY_TYPE = re.compile(rb'(?:ssh-|ecdsa-sha2-|sk-)[A-Za-z0-9@._+-]+\Z')
PIN_TYPES = {'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256',
             'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'}


def _field(line, offset):
    while offset < len(line) and line[offset] in b' \t':
        offset += 1
    start, quoted = offset, False
    while offset < len(line):
        byte = line[offset]
        if byte == 92 and quoted and offset + 1 < len(line) and line[offset+1] == 34:
            offset += 2
            continue
        if byte == 34:
            quoted = not quoted
        if byte in b' \t\r\n' and not quoted:
            break
        offset += 1
    if quoted or start == offset:
        raise ValueError('invalid authorized-key field')
    return line[start:offset], offset


def authorized_key(line: bytes):
    """Return (type, decoded blob); ignore comments after the actual key."""
    if len(line) > 8192 or not line.strip() or line.lstrip().startswith(b'#'):
        return None
    try:
        key_type, offset = _field(line, 0)
        if not KEY_TYPE.fullmatch(key_type):
            key_type, offset = _field(line, offset)  # one optional options field
        encoded, _ = _field(line, offset)
        if not KEY_TYPE.fullmatch(key_type) or not re.fullmatch(rb'[A-Za-z0-9+/]+={0,2}', encoded):
            return None
        blob = base64.b64decode(encoded + b'=' * (-len(encoded) % 4), validate=True)
        size = int.from_bytes(blob[:4], 'big')
        if len(blob) < 4 or not size or blob[4:4+size] != key_type or 4+size >= len(blob):
            return None
        return key_type, blob
    except ValueError:
        return None


def pinned_public_keys(value):
    """Canonical plain public keys; trust comes from the approved event profile."""
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise ValueError('ssh_public_keys requires one to eight approved public keys')
    result, seen = [], set()
    for line in value:
        if (not isinstance(line, str) or len(line) > 8192
                or any(ord(c) < 32 for c in line)):
            raise ValueError('invalid scorer public key')
        raw = line.encode('utf-8')
        parsed = authorized_key(raw)
        if parsed is None or not raw.startswith(parsed[0] + b' ') or parsed[0].decode() not in PIN_TYPES:
            raise ValueError('scorer pins require plain Ed25519, RSA or ECDSA public keys without options')
        kind, blob = parsed
        fields, offset = [], 0
        while offset < len(blob):
            if offset + 4 > len(blob):
                raise ValueError('truncated scorer public key')
            length = int.from_bytes(blob[offset:offset+4], 'big'); offset += 4
            if not length or offset + length > len(blob):
                raise ValueError('invalid scorer public-key field')
            fields.append(blob[offset:offset+length]); offset += length
        valid = False
        if kind == b'ssh-ed25519':
            valid = len(fields) == 2 and len(fields[1]) == 32
        elif kind == b'ssh-rsa' and len(fields) == 3:
            valid = (all(not x[0] & 128 for x in fields[1:])
                     and int.from_bytes(fields[1], 'big') >= 3
                     and int.from_bytes(fields[1], 'big') % 2 == 1
                     and 2048 <= int.from_bytes(fields[2], 'big').bit_length() <= 16384)
        elif kind.startswith(b'ecdsa-') and len(fields) == 3:
            size = {b'nistp256':65, b'nistp384':97, b'nistp521':133}.get(fields[1])
            valid = kind == b'ecdsa-sha2-' + fields[1] and len(fields[2]) == size and fields[2][0] == 4
        if not valid:
            raise ValueError('invalid or unsupported scorer public key structure')
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen:
            raise ValueError('duplicate scorer public key')
        seen.add(digest)
        result.append(kind.decode() + ' ' + base64.b64encode(blob).decode())
    return result
