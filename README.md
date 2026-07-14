# DBSC hello-world

A minimal Rust (axum) HTTPS server that makes the **Device Bound Session Credentials
(DBSC)** handshake *visible*, so you can learn it by watching real requests. Every DBSC
header is logged to the terminal.

---

## 1. What DBSC is (the 60-second version)

Cookie theft is a big account-takeover vector: malware copies your session cookie and
replays it from the attacker's machine. **DBSC** defeats replay by binding a session to a
**private key that lives in the device's hardware** (Secure Enclave on macOS, TPM on
Windows) and never leaves it.

- On login, the **browser** generates a device key pair and proves possession of the
  private key by signing a challenge. The server stores the **public** key.
- The server issues a **short-lived** cookie (e.g. 20s here).
- Just before that cookie expires, the browser **automatically** re-proves possession
  (signs a fresh challenge) to get a new cookie — no page JavaScript involved.

A thief who copies only the cookie can't refresh it (they don't have the private key), so
the stolen session dies within seconds on their machine.

The whole crypto dance is done by the browser. **The server just:** (1) invites
registration, (2) verifies the signed proof and sets a cookie, (3) re-verifies on refresh.

> **Common misconception — the bound cookie is NOT encrypted or signed with the private key.**
> It's a **plain, opaque bearer token** (a random string), sent as an ordinary cookie; requests
> are **not** individually signed either. The private key's *only* job is to **sign the challenge
> at refresh** (proof-of-possession) to mint a new cookie. So the security is not "the cookie is
> cryptographic" — it's **short cookie life × only the device can refresh**:
>
> ```
> Private key → signs the CHALLENGE at refresh   → mints a new short-lived cookie
> Cookie      → plain token, sent normally        → proves "I hold a currently-valid session"
> ```
>
> A stolen cookie therefore works only until it **expires** (the thief can't refresh it) — DBSC
> shrinks the theft window from "forever" to one cookie lifetime, rather than making each request
> cryptographically signed (which would need heavy browser/JS changes). On the server, the cookie
> value is validated by **comparing it to the stored value** for the session (constant-time), not
> by decrypting or verifying a signature on it.

---

## 2. Endpoints (6)

| Method & path         | Who calls it            | What it does |
|-----------------------|-------------------------|--------------|
| `GET  /`              | Web client (you)        | Serves the demo page. |
| `POST /start-form`    | Web client (Start session button) | Replies **303 → `/`** with a `Secure-Session-Registration` header + a `dbsc-registration-sessions-id` correlation cookie. This response is what makes the browser start DBSC. |
| `POST /dbsc/register` | **Browser (automatic)** | Receives the signed proof JWT (`Secure-Session-Response`). The JWT **header** embeds the device **public key** as a `jwk`; the **claims** echo our challenge back as the `jti`. We verify the ES256 signature, store the key under a new `session_identifier`, and return the **session config** JSON + a short-lived bound cookie. |
| `POST /dbsc/refresh`  | **Browser (automatic)** | Called when the bound cookie needs refreshing. First hit has no proof → we reply **403 + `Secure-Session-Challenge`**. The browser re-signs (same device key; new challenge as `jti`, **no `jwk`**) and retries → we verify against the **stored** key and re-mint the cookie. Unknown session → **404** (drops stale sessions). |
| `GET  /api/protected` | Web client (Call protected button) | Reports whether the device-bound cookie was delivered (`authenticated: true/false`). |
| `GET  /logout`        | Web client (Logout button) | **Revoke**: deletes the server-side `Binding`, expires the bound cookie, and sends `Clear-Site-Data` to end the DBSC session. A future refresh then gets `404`. |

Header names are `Secure-Session-*`; Chrome's docs get these right — it's older blog posts
/ search results that still show the obsolete `Sec-Session-*` (don't copy those). Session
id on refresh is `Sec-Secure-Session-Id`.

---

## 3. The flow (sequence diagram)

Three participants: **Web client** = the page / user-initiated requests · **Browser** =
Chrome's DBSC engine making calls automatically, no user action · **Server** = this app.

```mermaid
sequenceDiagram
    participant W as Web client
    participant B as Browser
    participant S as Server

    rect rgb(240, 246, 255)
    Note over W,S: Registration — once, at login (the Start session button here)
    W->>S: POST /start-form (user clicks Start session)
    S-->>W: 303 to / + Secure-Session-Registration (algs, path, challenge)<br/>+ Set-Cookie correlation cookie
    Note over B: Reads the header, generates a device key pair<br/>private key stays in hardware
    B->>S: POST /dbsc/register (automatic) signed JWT<br/>jwk = public key, jti = challenge
    Note over S: Verify ES256 sig using the jwk<br/>(prod also checks jti == challenge)<br/>store session_identifier to public key
    S-->>B: 200 session config + Set-Cookie auth_cookie (20s)
    end

    rect rgb(240, 255, 244)
    Note over W,S: Refresh — repeats for the life of the session, automatic, no user action
    loop every ~cookie lifetime
        B->>S: POST /dbsc/refresh (Sec-Secure-Session-Id, no proof)
        S-->>B: 403 Secure-Session-Challenge (new challenge)<br/>unknown session to 404 (drop stale)
        B->>S: POST /dbsc/refresh (re-signed JWT)<br/>jti = new challenge, NO jwk
        Note over S: Verify against the STORED key
        S-->>B: 200 session config + fresh Set-Cookie
    end
    end

    rect rgb(255, 245, 245)
    Note over W,S: App request
    W->>S: GET /api/protected (user clicks Call protected)
    S-->>W: authenticated true  (bound cookie delivered; false only if no active session)
    end
```

Plain-text version:

```
── Registration (once, at "login") ──────────────────────────────────
You     → POST /start-form
Server  → 303 to /  + Secure-Session-Registration (algs, path, challenge)
                    + Set-Cookie (correlation cookie)
Browser makes a device key pair (private key stays in hardware)
Browser → POST /dbsc/register   (signed JWT: jwk = public key, jti = challenge)
Server verifies sig via jwk, stores session_identifier → public key,
        → 200 session config + Set-Cookie auth_cookie (20s)

── Refresh (repeats every ~cookie lifetime, automatic) ──────────────
Browser → POST /dbsc/refresh    (Sec-Secure-Session-Id, no proof)
Server  → 403 + Secure-Session-Challenge (new challenge)   [unknown session → 404, dropped]
Browser → POST /dbsc/refresh    (re-signed JWT: jti = new challenge, NO jwk)
Server verifies vs STORED key,  → 200 session config + fresh Set-Cookie

── App request ──────────────────────────────────────────────────────
You     → GET /api/protected
Server  → authenticated true   (bound cookie rode the request; false only if no active session)
```

**What's inside the proof JWT** (a compact JWS — `header.payload.signature`):

- **`jwk`** (in the JWT *header*) — the device's **public** key (EC P-256 `x`/`y` coordinates).
  Sent **only at registration**; the private half never leaves the hardware. The server stores
  this jwk and verifies every future proof against it. On **refresh there is no `jwk`** — the
  key is already known, so re-sending it would defeat the point.
- **`jti`** (a JWT *claim*) — the **challenge** the server issued, echoed back. It proves the
  signature is **fresh**, not a replay. Present on **both** the register and refresh JWTs (each
  carries whatever challenge the server most recently issued). A production server checks
  `jti == the challenge it sent`; this demo logs it (see §5). The signature covers
  `header.payload`, so a valid signature proves possession of the private key *and* binds this
  exact challenge.

### From `jwk` to a verifiable key (how the server rebuilds the public key)

An EC public key **is a point `(x, y)` on the P-256 curve** (the private key is a secret number
`d`; the public key is the point `d·G`). The `jwk` just carries those two coordinates as
**base64url-encoded, 32-byte big-endian integers**. "Getting the public key from the `jwk`" means
converting those two strings into the byte format the crypto library expects. Worked example from
a real registration JWT header:

```json
"jwk": { "kty":"EC", "crv":"P-256",
         "x":"DA_3CaScQDr_kHODhKDgBxd8293dH3XRPmJcRNd-oNU",
         "y":"V5XJ0ZRAZQA0t3SR5ZkA80nvjNUdt_90AvoekPXQtgc" }
```

1. **Pull `x` and `y`** out of the JWK JSON (`pubkey_from_jwk` in `main.rs`) — still just strings.
2. **base64url-decode each → 32 raw bytes** (P-256 coordinates are 32 bytes; the code rejects
   anything else):
   ```
   x = 0c0ff709 a49c403a ff907383 84a0e007 177cdbdd dd1f75d1 3e625c44 d77ea0d5
   y = 5795c9d1 94406500 34b77491 e59900f3 49ef8cd5 1db7ff74 02fa1e90 f5d0b607
   ```
3. **Concatenate into the SEC1 *uncompressed point*** — `0x04 || X || Y` (1 + 32 + 32 = 65 bytes).
   The leading `0x04` is the SEC1 tag meaning "uncompressed — both coordinates follow":
   ```
   04 0c0ff709…d77ea0d5 5795c9d1…f5d0b607
   ```
4. **Parse it:** `VerifyingKey::from_sec1_bytes(&sec1)` turns those 65 bytes into a usable key.

Then verify: `vk.verify(signing_input, sig)` where `signing_input` = the literal `header.payload`
bytes and `sig` = the JWT's raw 64-byte `r‖s` signature (not DER). Success ⇒ the device holds the
private key matching that point.

**Why the `04 || X || Y` dance?** JWK and the crypto library describe the *same* key in *different*
formats — JWK as "two base64url numbers," SEC1 as "one byte string." Step 3 is purely a format
conversion. (A production server does the identical thing via a helper, e.g. `dbsc-php` uses
`jwkToPem` then verifies with OpenSSL.)

**Registration vs refresh:** the `jwk` is present **only at registration** — that's when you run
these steps and **store** the resulting key. On **refresh there is no `jwk`**, so you verify
against the **stored** key. That's the anti-theft core: refresh proofs are always checked against
the key captured once at registration, so only the original device can produce them.

**Why refresh must NOT trust a `jwk` (it would be self-certifying).** This is the crux, worth
spelling out. Suppose refresh JWTs *did* carry a `jwk` and the server verified against **that**
attached key. Then a thief who stole the cookie could: generate **their own** key pair → put
**their** public key in the `jwk` → sign the challenge with **their** private key → and the
signature verifies against the attached key ✅. The signature would prove only "I own *some*
key" — meaningless, and anyone could do it. By **ignoring any incoming key and checking against
the stored one**, only the holder of the **original** device private key (enrolled once, living
in hardware) can produce a valid refresh — a stolen cookie plus the attacker's own key **fails**.
That is exactly why the bound cookie can't just be replayed. Mental model: registration *enrolls*
the key ("remember this public key"); refresh *matches against the enrolled key* — you never
re-enroll a new key on refresh, or the lock would be meaningless. (This server verifies against
`stored_key` only; even if a refresh JWT included a `jwk`, it would be ignored.)

### The session config (the JSON body of Flows 2 & 4)

The `200` response to register **and** refresh carries a JSON **session config** — the server's
instruction sheet that lets Chrome run the whole session on its own (no page JavaScript). Example:

```json
{
  "session_identifier": "sess3",
  "refresh_url": "/dbsc/refresh",
  "scope": {
    "origin": "https://localhost:3000",
    "include_site": false,
    "scope_specification": [ { "type": "include", "domain": "localhost", "path": "/" } ]
  },
  "credentials": [ { "type": "cookie", "name": "auth_cookie",
                     "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax" } ]
}
```

| Field | Meaning / what Chrome does with it |
|-------|------------------------------------|
| **`session_identifier`** | Handle for this session; Chrome echoes it back as `Sec-Secure-Session-Id` on every refresh so the server knows which stored key to verify against. |
| **`refresh_url`** | **Where Chrome POSTs to renew the cookie** when it nears expiry. Chrome **auto-excludes** this URL from the scope so refresh requests aren't themselves deferred. |
| **`scope`** | **Which requests this session governs** — which must carry a fresh bound cookie (and which Chrome defers + refreshes for). |
| ↳ `origin` | The origin the session belongs to. |
| ↳ `include_site` | `false` = **this origin only** (no subdomain span); `true` = the whole registrable site (`*.example.com`). |
| ↳ `scope_specification` | `include`/`exclude` rules by domain+path. Here one `include` of `/` → manage the cookie for **all paths**. Add `exclude` rules (e.g. `/static`) to leave paths unmanaged. |
| **`credentials`** | **Which cookie(s) Chrome treats as device-bound and keeps fresh.** |
| ↳ `name` | Must **match the `Set-Cookie` name** (`auth_cookie`) or Chrome won't link them. |
| ↳ `attributes` | The attribute template for the managed cookie (mirrors the `Set-Cookie`, minus `Max-Age`). |

So after Flow 2 Chrome knows: *"for requests in **scope**, keep the cookie named `auth_cookie`
fresh; when it's about to expire, POST to **`refresh_url`** with **`session_identifier`**, get a
new cookie, carry on."* That's what makes the register/refresh loop self-sustaining — the config
is returned on **both** register and refresh so Chrome always holds the current instructions.

### Every id / value and how long it lives — don't mix them up

DBSC juggles several ids and values with **very different lifetimes**. Confusing them is the #1
source of "wait, which one is this?" Here they all are, grouped by lifetime:

| Value | Example | Born when | Rotates? | Lives for | Whole session? |
|-------|---------|-----------|----------|-----------|:---:|
| **device key** (public stored server-side; private in hardware) | — | Registration (Flow 2) | No | **the whole login session** | ✅ |
| **`session_identifier`** (the "session id") | `sess3` | Registration (Flow 2) | No — stable | **the whole login session** | ✅ |
| *(production)* **login/session cookie** ("auth token") | — | Login | No (maybe rotated) | **the whole login session** | ✅ |
| **bound cookie value** (`auth_cookie`) | `cookie4` → `cookie6` → … | Every register **and** refresh | **Yes — every refresh** | ~one refresh cycle (`Max-Age=20s`) | ❌ |
| **refresh challenge** | `refchal5` → `refchal7` | Every refresh (`403`) | **Yes — every refresh**, single-use | until used / next refresh (< challenge TTL) | ❌ |
| **registration challenge** | `chal1` | Flow 1 invite | One-time | just the registration handshake | ❌ |
| **correlation cookie** (`dbsc-registration-sessions-id`) | `regid2` | Flow 1 | One-time | registration window (minutes); **gone in prod** | ❌ |

Read it as three tiers:

- **Lives the whole session (the "anchors"):** the **device key** (the real anchor — everything
  is verified against it), its stable handle **`session_identifier`**, and in production the
  **login cookie**. These persist across every refresh, tab close, and multi-day return.
- **Rotates on every refresh (the security churn):** the **bound cookie value** and the **refresh
  challenge**. Being short-lived and single-use is the *point* — it's what makes a stolen cookie
  useless within seconds.
- **One-time / setup only:** the **registration challenge** (signed once) and the **correlation
  cookie** (bridges login→register during setup; doesn't exist in production).

**The key insight:** the thing that persists all session is **not a secret you send around** — it's
the **device key** (plus its handle and, in prod, the login cookie). The credential that actually
travels (the bound cookie) and the challenge are deliberately **short-lived and rotating**. That's
the whole DBSC trick: *a permanent hardware anchor issuing ever-changing, disposable credentials.*

#### What "the session id is stable" really means

The `session_identifier` is created **once, at registration**, and then **reused for the
entire life of that login session** — through every automatic refresh, even if the user
closes the tab and comes back days later. It is **not** regenerated on refresh (only the
*cookie value* is). Think of it as a **handle to a server-side binding**
(`session_identifier → device public key`), and that binding lives as long as the login
session does.

So it is *stable per login session*, **not** a permanent per-user value:

- **Same login session** (refreshes, tab closed & reopened, returning after days while the
  session is still valid) → **same `session_identifier`**. The bound cookie has expired, but
  Chrome silently refreshes it under the same id — no re-login, invisible to the user.
- **A new login** (the previous session expired, the user logged out, or you revoked it) →
  a **brand-new registration → brand-new `session_identifier`** bound to a fresh key proof.
  You do **not** reuse the old id for a new login — each session gets its own (so you can
  revoke them independently); the reference servers even *reject* re-registering an
  already-bound session.

**The rule in one line:** one login session ↔ one `session_identifier`. Stable while that
session lives; new only when the user registers again. Its lifetime is **your** decision — it
lives exactly as long as the server-side binding, which you tie to your login/session TTL
(a 30-day "remember me" keeps the same id for weeks; a short session rotates it sooner).

> In this demo there is no real login, so the store is keyed directly by the
> `session_identifier` and every "Start session" click is a brand-new session. A production
> server keys its binding by the **stable app session id** instead, and treats the
> `session_identifier` as a separate nonce the browser echoes back (see §9.3).

### The two "path"s in Flow 1 are unrelated

Flow 1's response has two tokens that both say "path" — they live on **different headers** and
mean **completely different things**. The name collision trips everyone up:

```
Secure-Session-Registration: (ES256); path="/dbsc/register"; challenge="…"   ← header #1
Set-Cookie: dbsc-registration-sessions-id=regid11; Path=/; Max-Age=3600       ← header #2
```

| Token | On which header | Kind | What it means |
|-------|-----------------|------|---------------|
| `path="/dbsc/register"` | `Secure-Session-Registration` | a **DBSC parameter** | The **endpoint** Chrome should POST the signed proof JWT to. |
| `Path=/` | `Set-Cookie` | a **standard cookie attribute** ([RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265)) | The **URL scope** of the correlation cookie — which requests the browser attaches it to. |

- `path="/dbsc/register"` is a DBSC *instruction* ("post your proof here"). Lowercase, and it's
  a parameter of the registration structured field.
- `Path=/` is ordinary cookie plumbing, nothing DBSC-specific ("send this cookie on any URL
  under `/`"). It's `/` here so the correlation cookie is guaranteed to ride along on the very
  next request — the `POST /dbsc/register` — which is how the reference server correlates that
  call back to the login. (This demo sets the cookie but doesn't read it — see §7.)

So one is "**where to send the proof**", the other is "**which URLs this cookie is sent for**".

### The correlation cookie is a demo stand-in — production doesn't need it

`dbsc-registration-sessions-id` exists here only because a hello-world has **no real login**. Its
whole job is to answer *"which logged-in user is this `/dbsc/register` POST?"* — and in a real app
your **login session cookie already answers that**: it rides the same-origin `/register` request
automatically (we saw it do exactly that in the logs). So a dedicated correlation cookie is
**redundant in production** — you'd drop it.

What `/dbsc/register` actually needs, and how the login cookie covers it without a third cookie:

1. **Identify the authenticated user/session** → the **long-lived login cookie** on the request. ✅
2. **Recover the challenge you issued** (to check the JWT's `jti`) → keep it in **server-side
   state keyed by the session id** (the "pending registration" record in §9.5) — not in a cookie. ✅

So the cookie counts differ:

| | This demo | Production |
|---|-----------|------------|
| Login/session cookie | *(none — no login)* | **long-lived** — auth + identifies the user at `/register` |
| Correlation cookie | `dbsc-registration-sessions-id` (stand-in) | **not needed** |
| Bound cookie | `auth_cookie` (short) | `auth_cookie`-equivalent (short) |

**Its `Max-Age` also isn't tied to any auth token:** it only needs to outlive the registration
handshake (≈ the challenge TTL, minutes) — not the short bound cookie, and not the long login
session. In production it disappears entirely. *(This demo sets it but never reads it — see §7.)*

### Two challenge-bearing headers, and why they look different

Both Flow 1 and Flow 3 hand the browser a challenge to sign — but via **two different headers**
with different shapes. That surprises people; here's why:

```
Flow 1:  Secure-Session-Registration: (ES256); path="/dbsc/register"; challenge="chal1"; authorization="auth-code-123"
Flow 3:  Secure-Session-Challenge:    "refchal5"; id="sess3"
```

| | Flow 1 — `Secure-Session-Registration` | Flow 3 — `Secure-Session-Challenge` |
|---|---|---|
| **Job** | Start a **new** session | Re-prove an **existing** session |
| **Who initiates** | Server **invites** (rides the login/303) | Server **responds** to the browser's own refresh attempt |
| `(ES256)` algorithm | ✅ negotiate the alg (once) | ❌ already agreed at registration |
| `path=` endpoint | ✅ where to POST the proof | ❌ browser already knows `refresh_url` (from the config) |
| **challenge** | ✅ as a `challenge="…"` **parameter** | ✅ as the **main value** `"refchal5"` |
| `authorization=` | ✅ optional app auth code (setup-time) | ❌ not relevant to a refresh |
| `id=` | ❌ no session exists yet | ✅ **which** session this is for |

**Why registration carries more:** nothing is set up yet, so it must bootstrap *everything* —
which algorithm to sign with, *where* to send the proof, the challenge, and an auth code. After
that it's all remembered (in the session config), so the refresh challenge only needs the two
things that actually change: the **new challenge** and **which session** (`id`).

**Why only the challenge header has `id`:** on refresh the browser may hold several sessions, so
it must say which one; at registration there's no session yet (the flow is identified by the
`path` you post to instead).

**The deeper reason — invite vs. response:** registration is server-*initiated* (you invite the
browser), so the challenge is *bundled into the invite* → **single-phase**. Refresh is
browser-*initiated* (the browser decides its cookie is expiring and calls you), so there's no
invite to bundle into — the server hands back a **standalone** `Secure-Session-Challenge` in a
`403`, the browser signs it and retries → **two-phase**. (They're also two distinct
structured-field grammars per the spec: registration = inner-list `(ES256)` + params with the
challenge as a *parameter*; challenge = a *string* value + an `id` param — Chrome expects exactly
these shapes.)

---

## 4. Setup & run

DBSC needs **real TLS** (not `http://localhost`) and several Chrome flags. On macOS all of
the following were required — each was a separate dead-end during development.

**a) Trusted HTTPS cert** (self-signed throws errors DBSC also rejects):
```bash
brew install mkcert
mkcert -install                      # add a local CA to the system keychain
mkcert localhost 127.0.0.1 ::1       # creates localhost+2.pem / localhost+2-key.pem
```

**b) Chrome flags** (`chrome://flags`, then **Relaunch**):
- **Device Bound Session Credentials (Standard)** → **`Enabled – For developers`**
  (plain "Enabled" still requires an Origin-Trial token that `localhost` can't have;
  "For developers" skips that check)
- **Enable UnexportableKeyService mojo service in the browser process** → **`Enabled`**
  (`#use-unexportable-key-service-in-browser-process`) — lets macOS generate the device
  key; without it registration silently fails
- **Device Bound Session Credentials (Standard) Persistence** → Enabled
- *(optional)* **… DevTools Debugging** → Enabled

**c) Run & open:**
```bash
cargo run
```
Open **`https://localhost:3000`** (exactly `localhost`, not `127.0.0.1`/a LAN host).
Open DevTools → Network, click **Start session**, watch the terminal.

Tip: if you've been testing a lot, DevTools → **Application → Clear site data** to drop
old persisted DBSC sessions before a fresh run.

---

## 5. What works vs. what doesn't

> **TL;DR — it all works, including on macOS.** The long "doesn't work on macOS" investigation in
> this section's history turned out to be a **bug in this demo's cookie parsing**, not a DBSC or
> platform limitation. Once fixed, the device-bound cookie reaches app requests (both `fetch()`
> and navigations) and `/api/protected` returns `authenticated=true`.

### Findings summary (macOS Chrome, over a real HTTPS domain)

| Result | Status |
|--------|--------|
| DBSC handshake — register + refresh, ES256 verified vs. stored key | ✅ works |
| Bound cookie reaches `/api/protected` (**`fetch()`**) → `authenticated=true` | ✅ works |
| Bound cookie reaches `/protected-page` (**navigation**) → `authenticated=true` | ✅ works |
| Stale-session handling — unknown session ids get `404` | ✅ works |

### The bug that made it look broken (and the fix)
`/api/protected` reported `authenticated=false` for a long time even though DevTools clearly showed
the bound cookie on the request. Cause: **Chrome sends cookies across more than one `Cookie:`
request header** — ordinary cookies in one, the **DBSC-managed cookie in a separate header** — and
the server read only the **first** via `headers.get(COOKIE)`. The bound cookie sat in the *second*
header, so it was never seen. Fix: read **all** headers with `headers.get_all(COOKIE)` (see
`has_bound_cookie` / `cookie_in` in `src/main.rs`). Post-fix, the logs show it plainly:

```
FLOW 6: PROTECTED PAGE
  raw Cookie header count = 2
  Cookie[0]: dbsc-registration-sessions-id=regid2
  Cookie[1]: __Host-auth_cookie=cookie4      ← the bound cookie, in a SECOND Cookie header
  authenticated=true
```

### ✅ Works (verified in the server logs)
- **Registration** — Chrome generates a device key, signs a JWT (`typ: dbsc+jwt`), and the
  server **verifies the ES256 signature** (`verified: true`), then issues the bound cookie.
- **Refresh** — the full anti-theft cycle: `403 Secure-Session-Challenge` → Chrome
  **re-signs with the same device key** → server verifies **against the stored key** →
  re-mints the cookie. This is the core DBSC mechanism, and it runs end to end.
- **Stale-session handling** — unknown session ids get `404`, so old persisted sessions
  are dropped instead of causing a refresh storm.

### Every "ruled out" was a false negative from that one bug
While the parser read only the first header, we chased a long list of red herrings — each now
known to be irrelevant, because the fix made every one of them deliver `true`: `fetch()` vs.
navigation · `SameSite` Lax/Strict · `Domain=` vs. host-only · the `__Host-` prefix · cookie
**name** · **lifetime** (`Max-Age` 20/120/300) · `scope_specification` present/absent · **`localhost`
vs. a real domain** · the **Secure Web Apps `.fbinfra.net` tunnel**. None of them mattered.

Two sub-mysteries the same bug explains:
- **`report-uri/dbsc-php`'s `/account` "worked" while our demo didn't** — PHP's `$_COOKIE` already
  merges all `Cookie` headers, so it never hit this; our Rust `.get()` read only the first.
- **The bound cookie "sometimes" appeared on `/dbsc/refresh`** — the **order of the two `Cookie`
  headers varied**, so `.get()` occasionally happened to return the bound one, which sent us down
  several wrong paths.

### Lesson
On the wire (especially HTTP/2, which Chrome uses over TLS) a single request can carry **multiple
`Cookie` headers**, and DBSC puts its managed cookie in its own. **Always read them all**
(`get_all`), never just the first. That was the entire bug — DBSC worked on macOS the whole time,
over both `localhost` and the internal tunnel, for both `fetch()` and navigations.

---

## 6. Key learnings (the gotchas, condensed)

1. **HTTPS is mandatory** — `http://localhost` is a "secure context" but not a
   *cryptographic* transport, so Chrome silently ignores the registration header.
2. **The cert must be trusted** — use `mkcert`, not a bare self-signed cert.
3. **`Enabled – For developers`**, not plain "Enabled" (skips the Origin-Trial-token gate
   that blocks localhost).
4. **UnexportableKeyService flag** is required on macOS to generate the device key.
5. **Header names are `Secure-Session-*`** (registration/response/challenge) and
   `Sec-Secure-Session-Id`. The Chrome docs get this right; lots of *older blog posts /
   search results* still show the obsolete `Sec-Session-*` — don't copy those.
6. **Registration must ride a form-POST → 303**; Chrome ignores the header on a plain GET
   navigation or a `fetch()` response.
7. **Refresh challenge must return `403`** (not 401) — Chrome only re-signs on 403.
8. **Challenges should be short & alphanumeric** — Chrome is picky.
9. **Reject unknown sessions with `404`** or persisted sessions cause an infinite
   refresh storm after a server restart.
10. **`Domain=` is *not* required for the bound cookie.** We use a **host-only** cookie with
    `Secure` + `HttpOnly` (matching the production `dbsc-php` lib). The two references
    disagree here — `drubery` uses `Domain=`, `dbsc-php` uses host-only + `Secure` +
    `HttpOnly` — and both handshake fine. (An earlier version of this list wrongly claimed
    `Domain=` was required; it isn't.)
11. **Bound cookie uses `SameSite=Lax`, not `Strict`.** `Secure` + `HttpOnly` are always right
    for a session cookie. For `SameSite`, `Lax` is the better default: `Strict` would drop the
    cookie when a user arrives via an **external top-level link** (they'd look logged out until
    they navigate internally) — a real login-UX cost for no meaningful gain on a
    hardware-bound, refreshed-every-few-minutes cookie. The Chrome docs and both reference libs
    all use `Lax`. Reserve `Strict` for a separate, extra-sensitive cookie (e.g. a step-up
    token). *(This demo originally used `Strict`; we switched to `Lax` to match the references —
    it made no difference to delivery, see §5.)*

---

## 7. How this differs from the Chrome docs

Compared against
[Chrome's DBSC guide](https://developer.chrome.com/docs/web-platform/device-bound-session-credentials).
First, the important correction: **the Chrome docs are actually correct on the header
names** — `Secure-Session-Registration`, `Secure-Session-Response`,
`Secure-Session-Challenge`, and `Sec-Secure-Session-Id`. (An early failure here was
self-inflicted: the first version used the obsolete `Sec-Session-*` names from memory,
which Chrome silently ignores. The docs never said that.)

### Where we follow the docs exactly
- **Header names** (all `Secure-Session-*` / `Sec-Secure-Session-Id`).
- **Refresh flow**: server challenges with **`403` + `Secure-Session-Challenge`**, the
  browser retries with `Secure-Session-Response`, server returns `200` + fresh cookie.
- **Session-config JSON** shape: `session_identifier`, `refresh_url`, `scope`
  (`origin` / `include_site` / `scope_specification`), `credentials`.
- **HTTPS required.**

### Where we differ, and why

| # | Chrome docs | This project | Why |
|---|-------------|--------------|-----|
| 1 | Emits `Secure-Session-Registration` on the **login response** (`200` + a long-lived cookie). | Emits it on a **form-POST → `303` redirect** (the *Start session* button). | A hello-world has no real login. A button submitting a form is the simplest trigger, and the `303`-redirect shape (matching the reference test server) is what reliably makes Chrome start registration. Functionally it's still "a POST whose response carries the header." |
| 2 | Registration header example: `(ES256 RS256); path="/StartSession"` — **no `challenge`**. | We add `challenge="…"` and `authorization="…"`. | The `challenge` is echoed back in the JWT's `jti`, which is how a real server does anti-replay; both are permitted by the [spec](https://w3c.github.io/webappsec-dbsc/). Harmless to include. |
| 3 | Bound cookie: `Max-Age=600` (10 min), `SameSite=Lax`, `Secure`. | `Max-Age=20`, `SameSite=Lax`, `Secure`, `HttpOnly`, host-only (no `Domain`). | 20s makes the auto-refresh observable within seconds. `SameSite=Lax` matches the docs; `Secure`+`HttpOnly`+host-only matches the production lib [`report-uri/dbsc-php`](https://github.com/report-uri/dbsc-php). |
| 4 | **No enablement steps** (it documents shipped/production behavior). | Requires Chrome flags: **`Enabled – For developers`**, **UnexportableKeyService**, software-keys. | On macOS, DBSC is still "manual testing"; those flags (from the [testing wiki](https://github.com/w3c/webappsec-dbsc/wiki/Testing-early-versions-of-DBSC)) skip the Origin-Trial-token check and let the OS generate the device key. Without them Chrome silently does nothing on `localhost`. |
| 5 | Describes an optional **long-lived fallback cookie** for when refresh fails. | Not implemented. | Out of scope for a minimal demo. |
| 6 | Barely specifies the **JWT** ("a public key in a JWT"). | We parse it fully: read the EC `jwk` from the JWT header at registration, verify ES256; on refresh verify against the **stored** key. | The docs punt JWT details to the spec; we implemented them so the proof is actually checked. |
| 7 | Doesn't discuss server session lifecycle. | We **reject unknown sessions with `404`**. | Our session store is in-memory and resets on restart, but the browser persists sessions — without the `404` those stale sessions refresh forever (a storm). |
| 8 | Implies the bound cookie is delivered to your app's requests. | Same — it **is** delivered (`authenticated=true`), once the server reads **all** `Cookie` headers. | Chrome splits cookies across multiple `Cookie` headers (the bound cookie in its own); reading only the first made it *look* undelivered — a demo bug, not a DBSC limitation (see §5). |

### vs. the official reference server ([drubery/dbsc-test-server](https://github.com/drubery/dbsc-test-server))

This is the Chrome team's reference DBSC test server (TypeScript/Deno, live at
`https://drubery-dbsc-test-server.deno.dev/`). **Our implementation is modeled on it** —
the two things that differ from the Chrome-doc example (the **form-POST→`303` trigger** and
the **`challenge` parameter**) come straight from this server, and it uses the same
`Secure-Session-*` headers and `403` refresh. So "our way" *is* essentially "the reference
way." Where we differ, it's because **we simplified** or because we run on **localhost**:

| Aspect | Reference server | This project | Why we differ |
|--------|------------------|--------------|---------------|
| Correlation cookie `dbsc-registration-sessions-id` | Sets it in the form handler **and reads it** in `/register` to look up the pending session. | We **set it but don't read it** — `/register` just mints a fresh `session_identifier`. | Kept the demo minimal; correlation isn't needed when we create the session on the fly. |
| JWT claim checks | Verifies signature **and** that `jti` == the issued challenge and `authorization` == the auth code. | We verify the **signature only** (log the claims). | Simpler to read; the signature is the core proof-of-possession. |
| Enablement | Ships an **Origin-Trial token** (`origin-trial` header) valid for its real `deno.dev` domain. | Uses **Chrome testing flags** on `localhost`. | `localhost` can't carry a domain-bound OT token, so we take the flags door instead. |
| Scope / cookie config | A form lets you set scope include/exclude paths, cookie name/value/lifetime at runtime. | **Hardcoded** (whole-origin scope, `auth_cookie`, 20s). | A hello-world doesn't need the knobs. |
| Protected endpoint | **None** — it only shows a session table. | We added **`/api/protected`** to test cookie delivery. | To make "is the bound cookie delivered?" observable (which surfaced our multi-`Cookie`-header parsing bug — §5). |
| Language / stack | TypeScript on Deno; `fast-jwt` + `jwkToPem`. | Rust on axum; `p256` for ES256. | Personal preference / learning in Rust. |

**Bottom line:** the reference is the more complete, production-shaped implementation; ours
is a trimmed-down, heavily-commented Rust port of the same protocol, plus a protected
endpoint to probe cookie delivery.

### vs. the production PHP library ([report-uri/dbsc-php](https://github.com/report-uri/dbsc-php))

Where `drubery` is Chrome's reference *test server*, `dbsc-php` is a **production** library —
Report URI's real DBSC integration, extracted as a framework-agnostic package (PHP 8.1+,
~700 lines, zero deps beyond `ext-openssl`). It's the source of this project's **security
hardening**, so comparing against it shows exactly how much a *demo* omits versus a real
server.

**What we deliberately share with it** (our hardening follows it): single-phase register /
two-phase (`403`→`200`) refresh · `Secure-Session-*` headers with the `id` sf-parameter on
the challenge · offering only `(ES256)` in the registration header (not the Chrome docs'
`(ES256 RS256)`) · a host-only `Secure`+`HttpOnly` bound cookie · **ES256 pinned** to block
`alg` confusion (`none` / RS-with-EC-key) · a **fresh cookie value minted on every refresh**
(re-emitting the old value makes Chrome think no refresh happened and drop the session).

| Aspect | `dbsc-php` (production) | This project (demo) | Why we differ |
|--------|------------------------|---------------------|---------------|
| Shape | Framework-agnostic **library**: `DbscServer` takes a `RequestContext`, returns a `DbscResponse`; never touches globals / headers / cookies itself. | A **runnable HTTPS server** you `cargo run`. | We want something you can launch and watch, not embed. |
| Stack | PHP 8.1+, `ext-openssl`. | Rust + axum, `p256`. | Learning in Rust. |
| Storage | Your `StoreInterface` (Redis / table), keyed by the **stable app session id** in a **dedicated key space** — never a shared session blob (a race there clobbers the binding and silently disables enforcement). | In-memory `HashMap` keyed by the **DBSC `session_identifier`**, cleared on restart. | A hello-world has no login / app-session; the map is enough to demo register→refresh. |
| JWT checks | **Rejects** (throws) on bad signature, wrong / expired challenge (`jti` vs stored, constant-time), or `alg≠ES256`. | Pins `alg=ES256` and *computes* signature validity, but **logs & continues** — never rejects; `jti` not checked. | Deliberate demo shortcut so even a failed check still shows the flow. A real server must reject — the code comment says exactly this. |
| Challenge | 32 crypto-random bytes, single-use; `challengeTtl` **must exceed `cookieMaxAge`** (enforced in `Config`) so a challenge cached just before expiry still validates. | Monotonic counter (`chal1`, `chal2`, …), not verified. | Not security-relevant in a demo; short & alphanumeric keeps Chrome happy. |
| Registration header | `(ES256); path="/dbsc/register"; challenge="…"` — **no** `authorization`. | Same, but we add `authorization="auth-code-123"`. | Both are spec-legal; we include it to show where an auth code would ride. |
| Bound cookie | `__Host-dbsc` (default), `Max-Age=300`, `SameSite=Lax`. | `auth_cookie`, `Max-Age=20`, `SameSite=Lax`. | 20s makes the auto-refresh observable in seconds. We tried the `__Host-` prefix (see §5) — it made no difference to delivery here, so we kept a plain host-only name. |
| `scope` JSON | `origin` + `include_site:false`, **no `scope_specification`** (a `__Host-` cookie can't span subdomains anyway). | `origin` + `include_site:false` + an explicit `scope_specification` **include** rule. | Both work; we keep the explicit rule to make the scope visible. |
| Enforcement | Full gate **primitives**: `getBinding`, constant-time `boundCookieMatches` (with a single-depth previous-value overlap for refresh races), document-vs-subresource, a registration grace window. The caller wires the policy. | None — just `/api/protected` reporting whether the cookie rode along. | We only *probe* delivery (which surfaced our cookie-parsing bug — §5); we don't gate. |
| Refresh robustness | Single-depth **challenge + cookie overlap** windows for latency races; an optional single-phase **first** refresh via `advertiseRefreshChallenge`. | Straight `403`→proof→`200`, fresh cookie each time, no overlap. | Those windows matter under real network latency, not on loopback. |
| Revoke / logout | `revoke()` deletes state + emits a cookie deletion (distinct enforcement-terminated vs logout audit events). | Not implemented. | Out of scope for the demo. |
| Audit + tests | `AuditLoggerInterface` events; a self-contained attack-case harness (wrong device key, wrong / expired challenge, stale cookie, `alg=none`). | `println!` to stdout; no tests. | The whole point here is *visibility in the terminal*, not coverage. |

**Bottom line:** `dbsc-php` is what a **correct, production** DBSC server looks like —
rejection on every failed check, real storage discipline, an enforcement gate, revocation,
latency-race overlap windows, and attack tests. This project is a **single-file demo** that
speaks the same wire protocol and borrows `dbsc-php`'s crypto / cookie hardening, but
deliberately *logs-and-continues* instead of enforcing, so you can watch every step. Building
the real thing → read `dbsc-php`; learning the handshake → read this.

---

## 8. Files & references

- `src/main.rs` — the whole server (6 handlers + JWT/ES256 verification + `Binding` store), heavily commented.
- `localhost+2*.pem` — mkcert TLS cert/key (git-ignored via the parent repo).
- Reference servers to diff against: <https://github.com/drubery/dbsc-test-server> (Chrome
  team's Deno test server) and <https://github.com/report-uri/dbsc-php> (production PHP lib
  with an attack-case test harness; our JWT/cookie hardening follows it)
- Spec: <https://w3c.github.io/webappsec-dbsc/> ·
  Testing guide: <https://github.com/w3c/webappsec-dbsc/wiki/Testing-early-versions-of-DBSC> ·
  Chrome docs: <https://developer.chrome.com/docs/web-platform/device-bound-session-credentials>

---

## 9. Next steps (turning this demo into a real integration)

This is a hello-world: it demonstrates the *handshake* with a `Start session` button and
*logs-and-continues* instead of enforcing. To make it real, in rough priority order:

### 9.1 Fold registration into the real login — drop the button

There is **no** browser "call `/start-form`" step, and no client feature-detection. DBSC
registration is **server-triggered**: you attach the `Secure-Session-Registration` header to
a response your app *already* sends. The natural home is the **login response**.

- A real login is a **POST** of credentials, and usually already redirects on success
  (Post/Redirect/Get). Just **add the header to that response**:

  ```
  POST /login   (credentials)
  → 303 See Other
    Location: /dashboard
    Secure-Session-Registration: (ES256); path="/dbsc/register"; challenge="…"
    Set-Cookie: session=…          (your normal app session cookie)
  ```

- Status is `303`/`302` **or** `200` — whatever your login already returns. It is **not**
  `403`/`401` (those would make Chrome report a Challenge Error). `403` belongs only to the
  `/dbsc/refresh` challenge. Registration is single-phase; refresh is two-phase.
- The header **must ride the response to a POST navigation**, never a `fetch()`/XHR response
  or a plain GET (Chrome silently drops it there — see §6, learning 6). So the button here is
  a stand-in for the login POST; a real app deletes it and the `/start-form` handler and
  merges that `303`-with-header logic into `POST /login`.
- **No feature detection needed:** always send the header. DBSC-capable browsers register;
  others ignore it and continue on normal cookies (additive, can't lock anyone out).

### 9.2 Actually enforce (the security payoff — currently missing)

Today `/dbsc/register` and `/dbsc/refresh` **log** verification and continue. A real server
must:

- **Reject** on any failed check: `alg≠ES256`, bad signature, and `jti` ≠ the challenge we
  issued (and, at registration, the `authorization` code). Use constant-time comparison.
- Add an **enforcement gate** on protected routes: if a session is bound (a binding exists)
  but the request's bound cookie is missing/mismatched, **revoke + log the user out** — don't
  just report `authenticated:false`. Enforce on document loads *and* subresources past a short
  registration grace, and skip the gate on the `/dbsc/*` endpoints. (See `report-uri/dbsc-php`
  §7 for the exact primitives.)

### 9.3 Production-grade state & crypto

- **Real storage** keyed by a **stable session id** in a **dedicated key space** (Redis/DB),
  not an in-memory `HashMap` and not a shared session blob (the read-modify-write race
  clobbers the binding and silently disables enforcement).
- **Crypto-random, single-use challenges** (not the demo's monotonic counter), with
  `challengeTtl > cookieMaxAge` so a challenge cached just before cookie expiry still validates.
- **Revocation** on logout (delete state + emit a bound-cookie deletion).
- **Latency-race overlap windows** (accept the single previous cookie value / challenge during
  the refresh round-trip) so normal requests racing a refresh don't get spuriously logged out.

### 9.4 Cookie delivery — confirmed working (read ALL Cookie headers)

An earlier version of this doc listed a "bound cookie not delivered to app requests" limitation.
That was a **demo bug** — reading only the first of Chrome's multiple `Cookie` headers — now fixed
(§5). The device-bound cookie **is** delivered to app requests on macOS. The only production
takeaway: make sure your server reads **all** `Cookie` headers (`get_all`), since the bound cookie
arrives in its own.

### 9.5 What to store server-side (per user / per session)

DBSC's whole security guarantee lives in **server-side state**: the public key you check every
refresh against, and the current cookie/challenge values. This demo keeps a toy version (a
`HashMap<session_identifier, PubKey>`); below is what a **real** server stores, modeled on the
production `report-uri/dbsc-php` (`Binding` + `PendingRegistration`).

**First, the golden rules:**

- **A user has *many* DBSC sessions** — one per device/browser (laptop + phone + work machine =
  three). So this is **per-session** state, indexed so you can also list/revoke **per user**.
- **Key it by your stable app session id, in a dedicated key space** (Redis, a table) — **never**
  inside a read-modify-written shared "session blob." The post-login navigation races the
  `/dbsc/register` POST; both rewrite the blob last-writer-wins, the binding is clobbered, and
  enforcement silently no-ops — the exact stolen-cookie hole DBSC exists to close.
- **Never store the private key.** It never leaves the device's hardware; you only ever receive
  and store the **public** key.

**Two records per session:**

**(A) Pending registration** — transient; written when you *offer* DBSC (emit the
`Secure-Session-Registration` header at login), deleted the moment `/dbsc/register` succeeds, and
expired on the challenge TTL if the device never answers.

| Field | Example | Why |
|-------|---------|-----|
| `user_id` | `u_8213` | Which account this registration is for. |
| `registration_challenge` | `f3a9…` (32 random bytes) | The nonce you put in the header; checked against the JWT's `jti` at register. |
| `created_at` | `1720…` | Enforce the challenge TTL (reject a stale registration). |

**(B) Binding** — the durable record; created on a *successful* `/dbsc/register` and its very
existence is the authoritative "this session is device-bound" mark. Lives for the session
lifetime.

| Field | Example | Why it's stored |
|-------|---------|-----------------|
| `user_id` | `u_8213` | Owner — lets you list/revoke all of a user's device sessions. |
| `session_identifier` | `sess_a1b2…` | The DBSC handle Chrome echoes in `Sec-Secure-Session-Id`; **your lookup key on every refresh**. Stable for the session's life (§3). |
| **`device_public_key`** (JWK or PEM) | `-----BEGIN PUBLIC KEY-----…` | **The crux.** Every future refresh proof is verified against this. Captured once from the registration JWT's `jwk`. |
| `algorithm` | `ES256` | Pin it; reject anything else (blocks alg-confusion). |
| `current_cookie_value` | `c_9f2e…` | Compared (constant-time) against the presented bound cookie at the enforcement gate. Rotates every refresh. |
| `current_challenge` + `challenge_issued_at` | `refchal_77…`, `1720…` | The nonce the **next** refresh JWT must carry as `jti`; time drives the TTL check. |
| `created_at` | `1720…` | Registration-grace window + session age. |
| `expires_at` | `1720…` | Tie to your session lifetime (a 30-day "remember me" keeps it for weeks; a short session sooner). |

**Recommended extras** (production-hardening for real network latency — see the `dbsc-php`
comparison in §7):

| Field | Why |
|-------|-----|
| `previous_cookie_value` + `previous_cookie_expires_at` | Accept the single prior cookie value during the refresh round-trip, so a normal request racing a refresh isn't spuriously logged out. |
| `previous_challenge` + `previous_challenge_at` | Same overlap idea for the challenge (a reactive `403` racing an advertised challenge). |
| `last_refreshed_at` / `has_refreshed` | Diagnostics, and to gate the optional single-phase *first* refresh (`advertiseRefreshChallenge`). |

**Invariant to enforce in config:** `challengeTtl` **must exceed** `cookieMaxAge`, so a challenge
the browser cached just before the cookie expired is still valid when it's finally used.

**Minimal viable set** (if you want the smallest correct binding): `user_id`,
`session_identifier`, `device_public_key`, `algorithm`, `current_cookie_value`,
`current_challenge` + `challenge_issued_at`, `created_at`, `expires_at`. Everything else is
robustness/observability on top.

> Mapping back to this demo: the `Binding` struct in `src/main.rs` implements a **minimal version
> of this table** — `user_id`, `device_public_key`, `algorithm`, `cookie_value`, `challenge`,
> `created_at`, `expires_at`, held in an in-memory `HashMap<session_identifier, Binding>` and
> printed on every register/refresh (`STORE [created]` / `STORE [updated]`) so you can watch it.
> What it still omits vs. production: real per-user keying (no login here), `jti`/expiry
> *enforcement* (we log & continue — §9.2), crypto-random challenges, and the latency-race overlap
> fields. So §9.2 + the extras above are the remaining gap between the demo and a real server.

---

## 10. Deploy behind a real HTTPS domain to test cookie delivery

§5 showed the bound cookie isn't delivered to app requests on the **macOS + `localhost`** path.
To retest on a **real, browser-trusted HTTPS origin**, the server is env-configurable (defaults =
the local mkcert setup), so no code changes are needed — just point it at a real host's cert and
origin:

```bash
export DBSC_ORIGIN="https://example.com"        # your real, browser-facing origin
export DBSC_BIND="[::]:8443"                      # socket to listen on
export DBSC_TLS_CERT="/path/to/fullchain.pem"    # a cert Chrome already trusts (e.g. Let's Encrypt)
export DBSC_TLS_KEY="/path/to/privkey.pem"
cargo run
```

Any host with a **publicly/organizationally trusted cert** works: a cloud VM with a Let's Encrypt
cert, a reverse proxy that forwards to this server, a dev tunnel that terminates TLS at a real
domain, etc. The requirement is a **real domain with a valid cert** (not `localhost`, not an IP) so
Chrome treats it as a proper secure context.

### It works on macOS
Cookie delivery was **confirmed on macOS Chrome** over a real internal HTTPS domain —
`/api/protected` returns `authenticated=true` (see §5). No Windows needed. (Earlier notes here
claimed macOS "still showed `authenticated=false`"; that was the multi-`Cookie`-header parsing bug,
since fixed.)
