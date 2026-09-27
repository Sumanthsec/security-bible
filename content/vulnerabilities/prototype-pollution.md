# Prototype Pollution
Tags: #vulnerability #prototype-pollution #javascript #nodejs #day5

## What is JavaScript's prototype and why does it matter?

Every object in JavaScript has a hidden link to another object called its **prototype** — a parent it inherits properties from. When you access a property, JavaScript looks at the object first. If not found, it walks up the prototype chain.

```javascript
const user = { name: "John", role: "customer" };

user.name;        // "John" — found on the object itself
user.toString();  // works — not on user, found on Object.prototype
```

`Object.prototype` sits at the top of the chain for almost every object. It's the **shared ancestor**:

```
user object   → Object.prototype → null
admin object  → Object.prototype → null
config object → Object.prototype → null
```

All objects share the same `Object.prototype`. If an attacker writes a property to it, **every object in the application inherits that property**.

## How does the attack work?

If the attacker adds `isAdmin: true` to `Object.prototype`:

```javascript
Object.prototype.isAdmin = true;

const user = { name: "John" };
const guest = { name: "visitor" };

user.isAdmin   // true — inherited from polluted prototype
guest.isAdmin  // true — inherited from polluted prototype
```

One pollution affected every object in the entire application. Any code that does `if (user.isAdmin)` without checking if the property is actually on the user object grants admin access.

## How does user input reach the prototype?

The most common vector is **object merge / deep copy operations**. Applications take user-supplied JSON and recursively merge it into existing objects:

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
```

The attacker sends:

```json
{"__proto__": {"isAdmin": true}}
```

Inside the merge: key is `__proto__` → `target["__proto__"]` is not a regular property, it's a special accessor pointing to `Object.prototype` → recurse into `merge(Object.prototype, {"isAdmin": true})` → sets `Object.prototype.isAdmin = true`.

The merge function didn't know `__proto__` was special. JavaScript interpreted it as "access the prototype."

An alternative path reaches the same destination:

```json
{"constructor": {"prototype": {"isAdmin": true}}}
```

Every object has `constructor` → every function has `prototype` → same `Object.prototype` reached.

## Where does this happen in real applications?

**Express.js query string parsing:**

```
GET /api/search?__proto__[isAdmin]=true
```

The query parser creates nested objects from parameters. `__proto__` gets treated as a key.

**Lodash `_.merge()` and `_.defaultsDeep()`** — were vulnerable for years. Millions of applications use Lodash.

**jQuery `$.extend(true, {}, userInput)`** — deep extend was vulnerable.

**Any custom merge/clone/deepCopy function** that doesn't check for `__proto__`.

**Settings/preferences endpoints** — any API that accepts nested JSON and merges into config objects.

## What can attackers achieve?

**Privilege escalation:**

```json
{"__proto__": {"isAdmin": true, "role": "superadmin"}}
```

Application checks `user.role` — user object doesn't have it explicitly, inherits `"superadmin"` from prototype.

**RCE (server-side Node.js):**

Pollute options that `child_process` reads from:

```json
{"__proto__": {"shell": true, "argv0": "node", "env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}
```

When the application later calls `child_process.execSync("ls", options)`, the polluted properties control shell execution. Known chains also exist through Handlebars template compilation.

**CVE-2019-7609 (Kibana)** — prototype pollution through Timelion visualization → reached `child_process.spawn` options → full RCE on Kibana servers. One HTTP request could compromise enterprise logging infrastructure.

**XSS (client-side):**

```javascript
// Pollute:
Object.prototype.innerHTML = "<img src=x onerror=alert(1)>";

// Later, some component:
element.innerHTML = config.welcomeMessage;
// config.welcomeMessage is undefined → inherits XSS payload
```

**Denial of service:**

```json
{"__proto__": {"toString": "not a function"}}
```

Every object's `toString()` is now a string instead of a function. Any code calling `.toString()` crashes. Entire application breaks.

## Why is prototype pollution unique?

The injection point and the impact point are **completely decoupled**. With [[SQL Injection]], you inject into a query and the query breaks. With prototype pollution, you pollute a property on one endpoint and the impact appears in completely different code, in a different file, executing minutes later.

This makes it hard to find through code review — the vulnerable merge and the exploitable property check may be in unrelated parts of the codebase.

## How do you test for it?

**1. Identify endpoints** that accept nested JSON — profile updates, settings, preferences, config endpoints.

**2. Send a canary payload:**

```json
{"__proto__": {"polluted": "yes"}}
```

**3. Check for behavioral changes.** Does a previously forbidden feature now work? Try:

```json
{"__proto__": {"status": 555}}
```

If the HTTP response returns status 555, the pollution reached Express's response handling.

**4. Trace what the application reads from objects** without own-property checks to determine which properties to pollute for privilege escalation, XSS, or RCE.

## How do you fix prototype pollution?

**1. `Object.create(null)` for user-controlled data** — objects with no prototype, nothing to pollute:

```javascript
const safeObj = Object.create(null);
```

**2. Reject dangerous keys before merging:**

```javascript
if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
    continue;
}
```

**3. Use `Object.hasOwn()` when checking properties:**

```javascript
// Vulnerable — checks inherited properties
if (user.isAdmin) { grantAccess(); }

// Safe — only checks own properties
if (Object.hasOwn(user, 'isAdmin')) { grantAccess(); }
```

**4. Freeze the prototype:**

```javascript
Object.freeze(Object.prototype);
```

Nothing can be added after this. Can break libraries that legitimately modify prototypes.

**5. Use `Map` instead of plain objects** for key-value stores — `Map.set("__proto__", "value")` is just a regular key, doesn't touch prototypes.

**6. Update libraries** — Lodash, jQuery, Express have all patched their merge functions to reject `__proto__` keys.

## My Notes
