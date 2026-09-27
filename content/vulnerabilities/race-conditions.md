# Race Conditions
Tags: #vulnerability #race-condition #toctou #concurrency #day5

## What is a race condition?

A **TOCTOU** (Time Of Check to Time Of Use) vulnerability. There's a gap between when the server checks a condition and when it acts on it. In that gap, the state can change.

Bank account with $1000. Two $800 withdrawal requests arrive simultaneously on separate threads:

```
Thread 1                          Thread 2
────────                          ────────
Read balance → $1000
                                  Read balance → $1000
Check: 1000 >= 800? Yes
                                  Check: 1000 >= 800? Yes
Update balance → $200
                                  Update balance → $200
Dispense $800
                                  Dispense $800
```

Both threads read $1000 before either updated. User received $1600 from a $1000 account. The bank lost $600.

## Where do race conditions appear in real applications?

**Coupon/discount code redemption** — "has this coupon been used?" → both threads see "no" → both apply the discount. Send 50 concurrent requests, get 50 discounts from one single-use coupon.

**Vote/like manipulation** — "has this user already liked?" → both see "no" → both add a like. Send 100 concurrent requests, get 100 likes from one user.

**Gift card / wallet top-up** — "is this gift card valid?" → both see "yes" → both credit the wallet. $50 card credited twice = $100.

**Username uniqueness** — "is 'admin' taken?" → both see "no" → both create accounts. Two accounts with same username → authentication confusion, account takeover.

**Inventory / limited stock** — "is item in stock?" → both see "1 remaining" → both process orders. Stock goes negative, company fulfills two orders with one item.

**Sign-up bonus abuse** — email verification credits $10. Send 50 concurrent requests to the verification endpoint → get $500 instead of $10. Found on multiple platforms in bug bounties.

**Transfer between accounts** — both threads read same initial balances, transfer executes twice but debit only effectively happens once. Money created out of thin air.

**Rate limit bypass** — rate limit check and increment aren't atomic. Both threads see "4 attempts" (under limit of 5), both allow. Send 100 simultaneous login attempts — rate limiter only catches a few.

**2FA bypass** — 3-attempt limit on 2FA codes. Send 100 concurrent requests with different codes — all pass the attempt check before any increment it. Brute-force the 2FA code in one burst.

## How do you test for race conditions?

**1. Identify TOCTOU operations.** Any action with a check-then-act pattern: check balance then deduct, check coupon then apply, check stock then order.

**2. Use Burp Suite's Turbo Intruder or Repeater group send.** Send 20-50 identical requests simultaneously. Turbo Intruder's single-packet attack sends all requests in one TCP packet, maximizing concurrent processing.

**3. Check for double results.** Was the coupon applied twice? Did the balance go negative? Were two likes registered?

**4. Vary the timing.** Sometimes exact simultaneous requests don't trigger the race. Stagger by a few milliseconds — the vulnerability window might be narrow.

## How do you fix race conditions?

### Fix 1: Atomic Operations

**The problem:** Check-then-act happens in multiple steps with gaps between them.

```python
# Three separate steps — gap between each
balance = db.query("SELECT balance WHERE id = 1")  # Step 1: Read
if balance >= 800:                                   # Step 2: Check
    db.query("UPDATE accounts SET balance = balance - 800")  # Step 3: Update
```

**The fix:** Collapse everything into one indivisible database operation:

```sql
UPDATE accounts SET balance = balance - 800
WHERE id = 1 AND balance >= 800;
```

One SQL statement reads, checks, and updates atomically. The database guarantees no other thread sees a halfway state. Check if it worked via rows affected:

```python
result = db.execute("UPDATE ... WHERE id = 1 AND balance >= 800")
if result.rowcount == 1:  # condition was true, balance deducted
    dispense_money()
elif result.rowcount == 0:  # condition was false, nothing changed
    return "Insufficient funds"
```

**Best for:** Simple check-and-update that fits in one SQL statement. Best performance, simplest code.

### Fix 2: Database Unique Constraints

**The problem:** Two threads both check "does this record exist?" → both see "no" → both insert.

**The fix:** Let the database enforce uniqueness:

```sql
CREATE UNIQUE INDEX idx_coupon_user ON redemptions (coupon_id, user_id);
```

```python
try:
    db.query("INSERT INTO redemptions (coupon_id, user_id) VALUES (5, 1)")
    apply_discount()
except UniqueViolationError:
    return "Coupon already used"
```

The database guarantees only one insert succeeds. Even if both execute at the exact same nanosecond, the database serializes inserts on unique indexes — one wins, one fails. No application-level checking needed.

**Best for:** "Do this only once" operations — coupon redemption, voting, registration, one-like-per-user. Strongest guarantee.

### Fix 3: Pessimistic Locking (FOR UPDATE)

**The problem:** Operations too complex for a single SQL statement, but all within one database.

**The fix:** Lock the row so no other thread can read or modify it until you're done:

```sql
-- Thread 1:
BEGIN;
SELECT balance FROM accounts WHERE id = 1 FOR UPDATE;
-- ROW IS NOW LOCKED — Thread 2 freezes here if it tries
UPDATE accounts SET balance = balance - 800 WHERE id = 1;
COMMIT;  -- lock released

-- Thread 2 (was waiting, now unfreezes):
SELECT balance FROM accounts WHERE id = 1 FOR UPDATE;
-- Reads $200 (the UPDATED value), not the stale $1000
-- Check: 200 >= 800? No → reject
```

Regular `SELECT` doesn't lock — multiple threads read freely. `FOR UPDATE` says "I'm going to modify this row, lock it now." The second thread **waits** until the first commits.

**Tradeoff:** Threads queue up on the same row (lock contention). High-traffic applications slow down. Called "pessimistic" because you assume conflicts and prevent them preemptively.

**Best for:** Complex multi-step operations within one database.

### Fix 4: Distributed Locks (Redis)

**The problem:** Race condition spans multiple systems — database + payment API + inventory service. Can't wrap everything in one database transaction. Or multiple application servers need to coordinate.

**The fix:** Redis as a shared coordination point accessible by all servers:

```python
def redeem_coupon(coupon_id, user_id):
    lock_key = f"lock:coupon:{coupon_id}"

    # NX = only set if key doesn't exist. EX = expire after 5 seconds.
    acquired = redis.set(lock_key, "locked", nx=True, ex=5)

    if not acquired:
        return "Another request is processing this coupon"

    try:
        if not coupon.is_used():
            apply_discount()
            coupon.mark_used()
    finally:
        redis.delete(lock_key)  # always release
```

Thread 1 sets the key (succeeds) → Thread 2 tries to set (key exists, fails, rejected). The 5-second expiration is a safety net — if Thread 1 crashes, the lock auto-releases.

**Best for:** Operations spanning multiple systems where database locks aren't feasible.

### Fix 5: Idempotency Keys

**The problem:** Duplicate submissions — user double-clicks "Pay," network retries, webhooks fire twice.

**The fix:** Client generates a unique ID per intended operation:

```
POST /api/transfer HTTP/1.1
Idempotency-Key: 550e8400-e29b-41d4-a716-446655440000
```

Server checks if this key was already processed. If yes, return the cached result without doing anything. If no, process and store the result:

```python
def transfer(request):
    key = request.headers['Idempotency-Key']

    existing = db.query("SELECT result FROM idempotency_store WHERE key = %s", key)
    if existing:
        return existing.result  # already processed, return cached result

    result = do_transfer(request.data)
    db.query("INSERT INTO idempotency_store (key, result) VALUES (%s, %s)", key, result)
    return result
```

The idempotency store itself needs a unique constraint to prevent race conditions on the lookup.

**Best for:** Payment processing, any operation where clients might retry. Stripe, PayPal, and most payment APIs require idempotency keys.

### When to use each fix

| Fix | Best for |
|---|---|
| Atomic operations | Simple check-and-update in one SQL statement |
| Unique constraints | "Do this only once" operations |
| Pessimistic locking | Complex multi-step operations within one database |
| Distributed locks | Operations spanning multiple systems |
| Idempotency keys | Preventing duplicate submissions from clients |

## My Notes
