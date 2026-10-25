#!/usr/bin/env python3
"""Recover the first message in a public mailbox by chosen-plaintext cryptanalysis.

Usage: python3 organizer/proof.py http://127.0.0.1:8080 QUEUE_UUID
Requires g++ on the attacker's machine and an unfiltered mailbox with a first message.
"""
import json
import base64
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def api(base, path, payload=None):
    request = urllib.request.Request(
        base + path,
        data=None if payload is None else json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json'},
        method='GET' if payload is None else 'POST',
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def journal_line(base, queue, day, line):
    source = ('int filter(int length) {\n'
              f'#line {line} "/var/log/lighthouse/{day}/{queue}.log"\n'
              '  int accepted = length > 0;\n'
              '  return accepted;\n'
              '}\n')
    for attempt in range(5):
        try:
            listing = api(base, f'/api/queues/{queue}/filter', {'source': source})['listing']
            match = re.search(r'queue=' + re.escape(queue) +
                              r' topic=[a-z0-9_.-]+ ciphertext=([0-9a-f]+)', listing)
            if not match:
                raise RuntimeError(f'journal line {line} not found in listing')
            return match.group(1)
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or attempt == 4:
                raise
            time.sleep(1.1)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    base, queue = sys.argv[1:]
    base = base.rstrip('/')
    day = api(base, f'/api/queues/{queue}')['created_at'][:10]
    target = journal_line(base, queue, day, 1)
    diffs = (0x8080000080800000, 0x0000000080800000, 0x0000000002000000)
    pairs = []
    for group, difference in enumerate(diffs):
        for _ in range(12):
            plain = secrets.randbits(64)
            pairs.extend(((group, plain), (group, plain ^ difference)))
    api(base, f'/api/queues/{queue}/messages', {
        'message': base64.b64encode(b''.join(p.to_bytes(8, 'big') for _, p in pairs)).decode(),
        'topic': 'calibration'
    })
    sample = journal_line(base, queue, day, 2)
    if len(sample) < len(pairs) * 16:
        raise RuntimeError('truncated chosen-plaintext ciphertext')
    rows = ''.join(f'{group} {plain:016x} {sample[16*i:16*i+16]}\n'
                   for i, (group, plain) in enumerate(pairs))
    with tempfile.TemporaryDirectory() as directory:
        executable = Path(directory) / 'solve'
        subprocess.run(['g++', '-std=c++17', '-O2', str(Path(__file__).with_name('feal_attack.cpp')),
                        '-o', str(executable)], check=True)
        result = subprocess.run([str(executable), target], input=rows, text=True,
                                capture_output=True, check=True)
    padded = bytes.fromhex(result.stdout.strip())
    padding = padded[-1]
    if not 1 <= padding <= 8 or padded[-padding:] != bytes([padding]) * padding:
        raise RuntimeError('invalid recovered padding')
    print(padded[:-padding].decode('utf-8', errors='replace'))


if __name__ == '__main__':
    main()
