# OAuth and OIDC
Tags: #how-it-works #oauth #oidc #authentication #authorization #day5

## Why does OAuth exist?

You want to log into Spotify using your Google account. Spotify needs to verify you're a real Google user and access your profile info. But you don't want to give Spotify your Google password.

OAuth: "Let Spotify access some of my Google data without giving Spotify my Google password."

## OAuth 1.0 — how does it work?

Before the flow, PrintApp registers with Flickr and receives a **consumer key** (public ID) and **consumer secret** (private proof).

### Phase 1: Get a Request Token (server-to-server)

PrintApp's server requests a temporary token from Flickr. The request is **signed with HMAC-SHA1** — parameters sorted alphabetically, combined into a signature base string, signed with `consumer_secret + "&"`. Flickr verifies by recreating the signature.

Flickr returns a **request token** + **request token secret** (both temporary).

### Phase 2: User Authorization (browser)

PrintApp redirects your browser to Flickr's login page with the request token. You log in (credentials go to Flickr only — PrintApp never sees them), approve access, and Flickr redirects back to PrintApp with an **oauth_verifier** — proof that you approved.

### Phase 3: Exchange for Access Token (server-to-server)

PrintApp sends the request token + verifier to Flickr, signed with `consumer_secret + "&" + request_token_secret` (two secrets combined). Flickr verifies everything and returns an **access token** + **access token secret** (long-lived).

### Phase 4: Call APIs

**Every single API request** is signed with `consumer_secret + "&" + access_token_secret`. Every request includes a unique nonce and timestamp to prevent replay attacks.

```
Authorization: OAuth
    oauth_consumer_key="abc123",
    oauth_token="access_token_444",
    oauth_signature_method="HMAC-SHA1",
    oauth_timestamp="1699999999",
    oauth_nonce="uniquerandom3",
    oauth_signature="kYjzVBB8Y0ZFabxSWbWovY3uYSQ="
```

Secure (works without HTTPS — signatures protect everything) but painful (one wrong character in the signature base string = failure, debugging is a nightmare).

## OAuth 2.0 — how does it work?

Dropped cryptographic signing. Relies on HTTPS instead. Before the flow, Spotify registers with Google and receives a **client ID** + **client secret**, and registers its **redirect URI**.

### Step 1: Redirect User to Google

```
https://accounts.google.com/authorize?
    response_type=code
    &client_id=spotify_app_id
    &redirect_uri=https://spotify.com/callback
    &scope=email profile
    &state=random_csrf_value
```

| Parameter | Purpose |
|---|---|
| `response_type=code` | "I want an authorization code" |
| `client_id` | Identifies Spotify to Google |
| `redirect_uri` | Must match pre-registered URL — Google rejects mismatches |
| `scope` | What permissions Spotify wants (email, profile — NOT Gmail, Drive) |
| `state` | Random CSRF token stored in user's session |

### Step 2: User Logs In and Approves

Browser is on Google's domain. You enter Google credentials — Spotify never sees them. You see a consent screen listing requested permissions and click Allow.

### Step 3: Google Redirects Back with Authorization Code

```
https://spotify.com/callback?code=AUTH_CODE_XYZ&state=random_csrf_value
```

Spotify **verifies state matches** what it stored in the session. If not — CSRF attack, reject.

The authorization code is short-lived (~10 minutes), single-use, and **useless without the client_secret**. It's visible in the browser URL bar — that's why it's NOT the access token.

### Step 4: Exchange Code for Tokens (server-to-server)

Spotify's backend sends directly to Google — **browser is NOT involved**:

```
POST https://oauth2.googleapis.com/token

grant_type=authorization_code
&code=AUTH_CODE_XYZ
&client_id=spotify_app_id
&client_secret=spotify_secret_key
&redirect_uri=https://spotify.com/callback
```

The `client_secret` proves this is really Spotify's server. It **never appears in the browser**. Even if someone intercepts the auth code, they can't exchange it without the secret.

### Step 5: Google Returns Tokens

```json
{
    "access_token": "ya29.a0AfH6SMBx2...",
    "refresh_token": "1//04abc123...",
    "expires_in": 3600,
    "token_type": "Bearer",
    "id_token": "eyJhbGciOiJSUzI1NiJ9..."
}
```

| Token | Purpose |
|---|---|
| `access_token` | Key to Google's API. Short-lived (~1 hour). Bearer token — whoever has it can use it (why HTTPS is mandatory). |
| `refresh_token` | Gets new access tokens when current one expires. Long-lived. Stored on Spotify's server. |
| `id_token` | JWT with user identity (OIDC — see below). |

### Step 6: Call APIs

```
GET https://www.googleapis.com/oauth2/v2/userinfo
Authorization: Bearer ya29.a0AfH6SMBx2...
```

No signature. No nonce. No timestamp. Just the token in the header. HTTPS encrypts the connection.

### Step 7: Refresh (happens silently later)

Access token expires after 1 hour. Spotify exchanges the refresh token for a new access token — server-to-server, no user interaction. This is why you stay logged in for weeks.

## What are the key differences between OAuth 1.0 and 2.0?

| Aspect | OAuth 1.0 | OAuth 2.0 |
|---|---|---|
| Signing | Every request signed (HMAC-SHA1) | No signing — bearer tokens over HTTPS |
| Without HTTPS | Secure (signatures protect) | Insecure (tokens in plaintext) |
| Complexity | Sort params, create base string, sign, add nonce+timestamp to every request | Just send the token in a header |
| Extra step | Get request token first | Skipped — goes straight to user redirect |
| Token refresh | Doesn't exist — re-do entire flow | Refresh token renews silently |
| Flows | One flow for everything | Multiple flows (auth code, PKCE, client credentials) |
| CSRF | Nonce + timestamp on every request | State parameter on initial redirect |
| Status | Nearly dead | Universal standard |

**The tradeoff:** OAuth 1.0 is more secure in theory but so complex that developers implemented it incorrectly, creating bugs. OAuth 2.0 is simpler to implement correctly but relies entirely on HTTPS.

## What is OIDC and why does it exist on top of OAuth 2.0?

**OAuth 2.0 is authorization** — "what can this app access?"
**OIDC is authentication** — "who is this user?"

OAuth 2.0 gives you an access token, but the access token doesn't tell you who the user is. Developers started hacking around this by calling `/userinfo` APIs, but every provider had different endpoints and formats.

OIDC adds one key thing: the **ID Token** — a JWT containing the user's identity, cryptographically signed by the provider.

### What's in the ID Token?

```json
{
    "iss": "https://accounts.google.com",
    "sub": "1234567890",
    "aud": "spotify_app_id",
    "exp": 1699999999,
    "iat": 1699996399,
    "auth_time": 1699996300,
    "nonce": "random_nonce_from_spotify",
    "email": "john@gmail.com",
    "email_verified": true,
    "name": "John Smith",
    "at_hash": "HK6E_P6Dh8Y93mRNtsDB1Q"
}
```

| Claim | Purpose |
|---|---|
| `iss` (issuer) | Who issued this — must match Google's known issuer URL |
| `sub` (subject) | Stable unique user ID — never changes even if email changes |
| `aud` (audience) | Who this was issued FOR — must match Spotify's client_id. Reject if it's for a different app. |
| `exp` | Expiration — reject expired tokens |
| `auth_time` | When user actually authenticated — force re-login if too old |
| `nonce` | Must match what Spotify sent — prevents replay attacks (reusing old ID tokens) |
| `email_verified` | Did Google verify this email? Critical — if false, user might have typed anything |
| `at_hash` | Hash of the access token — ties ID token to specific access token, prevents token substitution |

### How does OIDC modify the OAuth 2.0 flow?

Almost identical. Three changes:

**1.** Add `openid` to scope and include a `nonce`:

```
&scope=openid email profile
&nonce=random_replay_prevention
```

`openid` is the signal: "I want authentication, give me an ID token." Without it, it's plain OAuth 2.0.

**2.** Token response includes `id_token` alongside `access_token`.

**3.** Spotify validates the ID token — verify signature using Google's public keys, check `iss`, `aud`, `exp`, `nonce`. Extract user identity directly from the JWT. No `/userinfo` API call needed.

### OIDC Discovery

Providers publish a discovery document at a well-known URL:

```
GET https://accounts.google.com/.well-known/openid-configuration
```

Returns all endpoints (authorize, token, userinfo, JWKS), supported scopes, algorithms. Any app can auto-configure for any OIDC provider by reading this document.

### The relationship

```
┌──────────────────────────────────────────┐
│                OIDC                       │
│                                           │
│  ┌────────────────────────────────────┐  │
│  │          OAuth 2.0                 │  │
│  │  Auth Code Grant, Access Token,    │  │
│  │  Refresh Token, Scopes,            │  │
│  │  Client ID / Secret                │  │
│  └────────────────────────────────────┘  │
│                                           │
│  + ID Token (JWT with user identity)      │
│  + Standard UserInfo endpoint             │
│  + Discovery document                     │
│  + Nonce for replay prevention            │
│  + Standard claims (sub, email, name)     │
└──────────────────────────────────────────┘
```

## OAuth 2.0 — other flows

**PKCE (Proof Key for Code Exchange)** — for mobile/SPA apps that can't keep a `client_secret` safe. App generates a random `code_verifier`, sends `SHA256(code_verifier)` as `code_challenge` with the auth request. When exchanging the code, app sends the original `code_verifier`. Provider verifies the hash matches. Even if attacker intercepts the code, they don't have the `code_verifier`.

**Implicit Flow (deprecated)** — access token returned directly in the redirect URL fragment (`#access_token=...`). No server-to-server exchange. Token exposed in browser. Insecure — replaced by PKCE.

**Client Credentials** — no user involved. Application-to-application: `client_id` + `client_secret` → access token. Backend services calling other backend services.

## Key terms

| Term | Meaning |
|---|---|
| Authorization Server | Google (issues tokens) |
| Resource Server | Google APIs (accepts tokens, returns data) |
| Client | Spotify (wants to access Google data) |
| Resource Owner | You (the user) |
| Authorization Code | Short-lived code exchanged for tokens |
| Access Token | Token used to call APIs |
| Refresh Token | Long-lived token to get new access tokens |
| Redirect URI | Where user goes after approving — pre-registered |
| Scope | What permissions are granted |
| State | CSRF protection parameter |
| Nonce | Replay prevention (OIDC) |
| Client ID | Public app identifier |
| Client Secret | Private key known only to app's backend |
| PKCE | Proof Key for Code Exchange — protects public clients |

## My Notes
