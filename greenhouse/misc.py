#!/usr/bin/env python3
"""Reference exploit: invert the public atmospheric spectrum recurrence."""
import hashlib
import json
import sys
import urllib.parse
import urllib.request


def mask(id_, n):
    out = []
    counter = 0
    while len(out) < n:
        out.extend(hashlib.sha256(f"orbita-spectrum:{id_}:{counter}".encode()).digest())
        counter += 1
    return out[:n]


def exploit(host, target):
    query = urllib.parse.urlencode({"plot": target})
    with urllib.request.urlopen(f"http://{host}:8080/api/spectrum?{query}", timeout=5) as response:
        result = json.load(response)
    samples = result["samples"]
    previous = 0
    raw = bytearray()
    for sample, offset in zip(samples, mask(target, len(samples))):
        raw.append((sample - previous - offset) % 257)
        previous = sample
    print(raw.decode())


if __name__ == "__main__":
    exploit(sys.argv[1], sys.argv[2])
