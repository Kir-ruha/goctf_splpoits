# уязвимость 1.
## получение бесконечного заказа, в последующим неограниченый заказ товаров с флагами

При регистрации `role=buyer` создаётся промокод `SP10-<token>` на `amount=10`.


Код отдаётся в `GET /api/account` → `promo: {code, amount}`.

Два эндпоинта работают раздельно:

- `POST /api/promo/credit {code}` — `SELECT amount FROM promo_codes WHERE user_id=$1 AND code=$2`, затем `UPDATE users SET balance=balance+$amount`. **Ничего не удаляет и не помечает использованным.**
- `POST /api/promo/invalidate {code}` — единственный, кто делает `DELETE FROM promo_codes`.


### Итог

```
POST /api/promo/credit {"code":"SP10-..."}  →  {"credited":10}  (200)
POST /api/promo/credit {"code":"SP10-..."}  →  {"credited":10}  (200)  — ещё раз
... N раз → balance = 1000 + N*10, без ограничений
```

С этим балансом атакующий покупает любой товар (`POST /api/products/<id>/buy` или `/api/cart/checkout`). Флаг лежит в `products.cargo` и отдаётся в `GET /api/orders` когда `status=delivered` (`CASE WHEN status='delivered' THEN cargo ELSE NULL`).

[эксплоит](promo_balance.py)

### Патч

1. **Удалять при начислении** — в `credit_promo()` заменить `SELECT` на `DELETE ... RETURNING amount`:
   ```python
   cur.execute("DELETE FROM promo_codes WHERE user_id=%s AND code=%s RETURNING amount",
               (session["user_id"], code.strip()))
   promo = cur.fetchone()
   if not promo: return error("promo code is unavailable", 409)
   cur.execute("UPDATE users SET balance=balance+%s WHERE id=%s",
               (promo["amount"], session["user_id"]))
   ```

# или 

2. **Добавить флаг использования** — `ALTER TABLE promo_codes ADD COLUMN is_used BOOLEAN DEFAULT false` и в `credit` делать `UPDATE promo_codes SET is_used=true WHERE user_id=$1 AND code=$2 AND is_used=false RETURNING amount`.


# уязвимость 2.
## чтение скрытых отзывов на товары 

```python
def _parse_cursor(cur_token: str, lim_raw):
    try:
        lim = int(lim_raw) if lim_raw is not None else None
    except (TypeError, ValueError):
        lim = None
    if lim is not None and lim <= 3:
        # ← подпись вообще не проверяется
        return _json.loads(_b64d(cur_token.split(".")[0]).decode())
    # нормальная ветка: проверка HMAC
    if "." not in cur_token:
        raise ValueError("missing signature")
    payload_b64, sig = cur_token.rsplit(".", 1)
    if not hmac.compare_digest(_sign(payload_b64), sig):
        raise ValueError("bad cursor signature")
    return _json.loads(_b64d(payload_b64).decode())
```

При `limit <= 3` проверка подписи полностью пропускается. Курсор — base64url-кодированный JSON:

```json
{"seller_id": 42, "is_private": true, "last_id": 1000000000, "v": 2}
```

Поле `seller_id` определяет, чьи отзывы вернуть. После парсинга курсора никакой проверки что `seller_id == session["user_id"]` нет — запрос идёт прямо в БД:

```sql
SELECT ... FROM reviews r ...
WHERE r.seller_id = <seller_id из курсора> AND r.is_private = true AND r.id < <last_id>
```

## Как работает атака

1. Атакующий регистрируется как seller (нужна сессия с `role=seller`).
2. Для каждого `victim_id` собирает поддельный курсор:
   ```
   payload = base64url({"seller_id": victim_id, "is_private": true, "last_id": 1000000000, "v": 2})
   cursor  = payload + ".deadbeefdeadbeef"   ← любая подпись
   ```
3. `GET /api/seller/reviews?cursor=<forged>&limit=3` → 200, в `reviews` возвращаются приватные отзывы жертвы, в `body` лежит флаг.

Флаг кладёт `review.py` (`checker put`):
```python
buyer.json_dict("POST", f"/api/orders/{order_id}/review",
                json={"body": flag, "rating": 5, "private": True})
```

[эксплоит](spl_otz1.py)


### патчить

Самый простой фикс — убрать исключение, всегда проверять подпись:

```python
def _parse_cursor(cur_token: str, lim_raw):
    if "." not in cur_token:
        raise ValueError("missing signature")
    payload_b64, sig = cur_token.rsplit(".", 1)
    if not hmac.compare_digest(_sign(payload_b64), sig):
        raise ValueError("bad cursor signature")
    return _json.loads(_b64d(payload_b64).decode())
```

Либо, если `limit <= 3` нужен для обратной совместимости, добавить проверку `seller_id` из курсора против `session["user_id"]`:

```python
if lim is not None and lim <= 3:
    state = _json.loads(_b64d(cur_token.split(".")[0]).decode())
    if int(state.get("seller_id", -1)) != session["user_id"]:
        raise ValueError("seller_id mismatch")
    return state
```

# уязвимость 3.
## доступ к чужим подписанным контрактам 



Случайный hex-суффикс (`token_hex(8)` = 16 символов) задуман как секрет — без него нельзя угадать полное имя файла. Но логика `/api/contract` смотрит только на префикс:

```python
m = re.match(r"^\s*contract-(\d+)", requested)
if m:
    uid = m.group(1)
    hits = sorted(CONTRACT_DIR.glob(f"contract-{uid}-*.pdf"))
    if hits:
        return send_file(hits[0], ...)  # ← отдаёт первый найденный
```

Regex проверяет только `contract-<digits>` и игнорирует всё что после. Потом `glob` находит файл только по `user_id`. Hex-суффикс перестаёт быть защитой.

## Как работает атака

1. Атакующий регистрируется как seller (нужен `role=seller` для доступа к `/api/contract`).
2. Узнаёт `user_id` жертвы — он публично виден в `GET /api/products` как `seller_id` (либо простой перебор 1..N).
3. Запрашивает `GET /api/contract?file=contract-<victim_id>` — сервер сам находит файл через glob.

```
GET /api/contract?file=contract-42   →  200, PDF с подписью-флагом жертвы
```

Флаг хранится в PDF — `contract.py` в чекере:

```python
def put(checker, flag):
    client.register_seller(seller_name, seller_password, flag)  # flag = signature
    # → create_contract(user_id, company, tax_id, flag) → в PDF
```

## LFI-ветка (бонус)

Если запрос **не** матчит `contract-\d+`, код падает в path traversal ветку:

```python
candidates = [
    (CONTRACT_DIR / raw).resolve(),
    Path(raw).resolve(),
    CONTRACT_DIR / raw,
    Path(raw),
]
for target in candidates:
    if target.is_file():
        return send_file(target, ...)
```

Позволяет читать произвольные файлы файловой системы контейнера, например `/etc/passwd`, env-файлы с секретами и т.д. Но для CTF-флагов достаточно prefix-match ветки.


[эксплоит](contract_lfi.py)

## Как патчить

Нужно проверять полное имя файла, а не только prefix. Вариантов два:

**Вариант 1 — убрать glob, проверять точное имя из БД:**

```python
# вместо glob по uid — получить filename из БД и сравнить с запросом
with db() as conn, conn.cursor() as cur:
    cur.execute("SELECT contract_file FROM users WHERE id=%s AND role='seller'", (uid,))
    row = cur.fetchone()
if not row or row["contract_file"] != requested.strip():
    return error("contract not found", 404)
path = CONTRACT_DIR / row["contract_file"]
return send_file(path, ...)
```

**Вариант 2 — проверять что `requested` точно совпадает с `contract_file` текущего пользователя:**

```python
# разрешить доступ только к своему файлу
with db() as conn, conn.cursor() as cur:
    cur.execute("SELECT contract_file FROM users WHERE id=%s", (session["user_id"],))
    filename = cur.fetchone()["contract_file"]
if requested.strip() != filename:
    return error("forbidden", 403)
```

Дополнительно — убрать LFI-ветку (`candidates` с `Path(raw).resolve()`), она не нужна для нормальной работы сервиса.
