//! DBSC (Device Bound Session Credentials) hello-world.
//!
//! A small HTTPS server that makes the DBSC handshake *visible* so you can learn it.
//! Each request/response pair is logged to stdout as a numbered FLOW (1-5). See README.md: what
//! DBSC is, the required Chrome flags, the sequence diagram, and what works vs. not.
//!
//! Endpoints (see README for the flow):
//!   GET  /               – the demo page (Start session / Call protected buttons)
//!   POST /start-form     – 200 carrying `Secure-Session-Registration` (starts DBSC)
//!   POST /dbsc/register  – Chrome POSTs its signed proof JWT here; we verify + open a session
//!   POST /dbsc/refresh   – Chrome re-proves possession here (challenge → signed retry → re-mint)
//!   GET  /api/protected  – reports whether the device-bound cookie rode along
//!
//! DBSC headers use the `Secure-Session-*` names (plus `Sec-Secure-Session-Id`). Chrome's
//! docs get these right; it's older blog posts / search results that still show the
//! obsolete `Sec-Session-*` — don't copy those. DBSC only runs over TLS, hence mkcert.

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Runtime config (env-overridable) so the *same* binary works both locally (mkcert cert on
/// `localhost`) and behind a real HTTPS domain (point the vars at that host's cert and origin).
/// Defaults reproduce the local setup, so `cargo run` is unchanged.
struct Config {
    origin: String,      // DBSC_ORIGIN      — browser-facing origin, e.g. https://example.com
    bind: String,        // DBSC_BIND        — socket to listen on, e.g. [::]:8443
    tls_cert: String,    // DBSC_TLS_CERT    — PEM cert path
    tls_key: String,     // DBSC_TLS_KEY     — PEM key path
    cookie_name: String, // DBSC_COOKIE_NAME — device-bound cookie name (default __Host-auth_cookie)
}
static CONFIG: OnceLock<Config> = OnceLock::new();
fn cfg() -> &'static Config {
    CONFIG.get().expect("CONFIG not initialized (set in main before serving)")
}
/// Bound-cookie lifetime, in SECONDS (RFC 6265 `Max-Age` is seconds, not ms). Set to 300 (5 min)
/// to match report-uri/dbsc-php and keep the cookie reliably present when you click a protected
/// page (a 20s cookie is often expired at click time). Lower it to watch refreshes more often.
const COOKIE_MAX_AGE_SECS: u64 = 300;
/// Session (binding) lifetime — how long the server keeps the device binding. Tie this to your
/// login/session TTL (e.g. a 30-day "remember me"). Independent of the short bound-cookie lifetime.
const SESSION_TTL_SECS: u64 = 30 * 24 * 3600;
/// How long a registration challenge stays valid (the registration window). A real server pairs
/// this with the refresh challenge TTL; here it just bounds the Flow 1 → Flow 2 handshake.
const REG_CHALLENGE_TTL_SECS: u64 = 300;

/// An EC P-256 public key (base64url X/Y coordinates), as carried in a device JWT's `jwk`.
#[derive(Clone)]
struct PubKey {
    x: String,
    y: String,
}

/// What a production DBSC server stores **per session** — a minimal version of
/// report-uri/dbsc-php's `Binding` (and README §9.5). Its existence in the store *is* the
/// "this session is device-bound" mark. Keyed by a stable session id.
///
/// This demo has no real login, so we key by the DBSC `session_identifier` and use a placeholder
/// `user_id`. A real server keys by the stable **app session id** and stores the real user.
#[derive(Clone)]
struct Binding {
    user_id: String,           // which account this belongs to (for revoke-all / auditing)
    device_public_key: PubKey, // THE crux — every refresh proof is verified against this
    algorithm: String,         // pinned signing alg ("ES256"); reject anything else
    cookie_value: String,      // current bound-cookie value; compare (constant-time) at the gate
    challenge: String,         // the nonce the next refresh JWT must carry as `jti` (anti-replay)
    created_at: u64,           // unix secs — registration time (grace / session age)
    expires_at: u64,           // unix secs — tie to your login/session lifetime
}

/// Written when we OFFER registration (Flow 1) and consumed at `/dbsc/register` (Flow 2). Holds
/// the challenge we issued so `register` can check the JWT's `jti` against it (anti-replay). Keyed
/// by `login_auth_id`. Modeled on report-uri/dbsc-php's `PendingRegistration` — the two-record
/// model: a *pending registration* at the trigger, a *Binding* only on success.
#[derive(Clone)]
struct PendingRegistration {
    challenge: String,
    created_at: u64,
}

/// In-memory stores. A real server uses Redis or a table keyed by the stable app session id in a
/// **dedicated** key space (never a shared session blob — see §9.5). Cleared on restart, so
/// browser-persisted sessions become "unknown" on refresh (→ 404, dropped).
#[derive(Clone, Default)]
struct AppState {
    /// session_identifier -> Binding (the established device-bound session).
    sessions: Arc<Mutex<HashMap<String, Binding>>>,
    /// login_auth_id -> PendingRegistration (the issued challenge, awaiting the register proof).
    pending: Arc<Mutex<HashMap<String, PendingRegistration>>>,
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Serializes each handler's multi-line log block so concurrent requests (Chrome fires many
/// refreshes at once) don't interleave their output. Held for the whole handler — there is no
/// `.await` inside any handler after it's taken, so the guard never crosses an await point.
static LOG_LOCK: Mutex<()> = Mutex::new(());

/// Unique short id/challenge for the demo, e.g. "sess3" (NOT cryptographically strong — a real
/// server uses crypto-random values; challenge length/charset don't matter, `dbsc-php` uses a
/// 32-byte hex nonce). The short counter is purely for readable logs.
fn nonce(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}{n}")
}

/// Print a consistent "FLOW N" banner so each request/response pair is easy to spot in the
/// terminal. Each handler then logs its full REQUEST and RESPONSE — status, every header it
/// sets (including cookies) and the body.
fn flow_header(n: u8, title: &str) {
    println!("\n════════ FLOW {n}: {title} ════════");
}

/// ALL incoming `Cookie:` header values, joined with "; ". HTTP allows **multiple** `Cookie`
/// headers, and `headers.get()` returns only the FIRST — so a cookie Chrome puts in a *second*
/// `Cookie` header (which is exactly what it does for the DBSC-managed cookie) would be silently
/// missed. Reading `get_all` is the fix — this is why our earlier checks reported `false` even
/// though DevTools showed the bound cookie on the request (see §5).
fn cookie_in(headers: &HeaderMap) -> String {
    let joined = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    if joined.is_empty() { "(none)".to_string() } else { joined }
}

/// True if any incoming `Cookie` header carries the device-bound cookie (across ALL headers).
fn has_bound_cookie(headers: &HeaderMap) -> bool {
    bound_cookie_value(headers).is_some()
}

/// The value of the cookie named `name` on this request (across all `Cookie` headers), if present.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
        .find_map(|c| c.trim().strip_prefix(&prefix).map(str::to_string))
}

/// The VALUE of the device-bound cookie on this request, if present.
fn bound_cookie_value(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, &cfg().cookie_name)
}

/// Current unix time in seconds (for the binding's created_at / expires_at).
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Print the stored session record so you can SEE exactly what a production server keeps per
/// session (the point of the demo's storage). Called on register (created) and refresh (updated).
fn print_binding(label: &str, session_id: &str, b: &Binding) {
    println!("  STORE [{label}]  key(session_identifier)={session_id} -> Binding {{");
    println!("           user_id          = {}", b.user_id);
    println!("           device_public_key= <EC P-256 x/y>   (verify every refresh against this)");
    println!("           algorithm        = {}", b.algorithm);
    println!("           cookie_value     = {}   (rotates every refresh)", b.cookie_value);
    println!("           challenge        = {}   (next refresh must present as jti)", b.challenge);
    println!("           created_at       = {}   expires_at = {}", b.created_at, b.expires_at);
    println!("         }}");
}

#[tokio::main]
async fn main() {
    // Env-overridable config; defaults = the local mkcert setup. To serve behind a real HTTPS
    // domain, set: DBSC_ORIGIN=https://<host> · DBSC_BIND=[::]:<port> ·
    // DBSC_TLS_CERT / DBSC_TLS_KEY = that host's cert/key paths.
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let _ = CONFIG.set(Config {
        origin: env("DBSC_ORIGIN", "https://localhost:3000"),
        bind: env("DBSC_BIND", "127.0.0.1:3000"),
        tls_cert: env("DBSC_TLS_CERT", "localhost+2.pem"),
        tls_key: env("DBSC_TLS_KEY", "localhost+2-key.pem"),
        cookie_name: env("DBSC_COOKIE_NAME", "__Host-auth_cookie"),
    });

    let state = AppState::default();
    let app = Router::new()
        .route("/", get(index))
        .route("/start-form", post(start_form))
        .route("/dbsc/register", post(register))
        .route("/dbsc/refresh", post(refresh))
        .route("/api/protected", get(protected))
        .route("/logout", get(logout))
        .with_state(state);

    // rustls 0.23 needs a process-wide crypto provider chosen explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring provider");

    // DBSC only engages over real TLS. Locally these are the files mkcert produces
    // (`mkcert localhost 127.0.0.1 ::1`); behind a real domain point DBSC_TLS_CERT/KEY at its cert.
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cfg().tls_cert, &cfg().tls_key)
        .await
        .expect(
            "TLS certs not found. Locally run:\n  \
             brew install mkcert && mkcert -install\n  \
             mkcert localhost 127.0.0.1 ::1\n  \
             (or set DBSC_TLS_CERT / DBSC_TLS_KEY to your cert paths).",
        );

    let addr: std::net::SocketAddr = cfg().bind.parse().expect("invalid DBSC_BIND (e.g. [::]:8443)");
    println!("\n=== DBSC hello-world (HTTPS) ===");
    println!("Open  {}  in Chrome (with the DBSC flags from README enabled).", cfg().origin);
    println!("Keep DevTools -> Network open to watch the Secure-Session-* handshake.\n");
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Serve the page. The registration invite is NOT emitted here — it rides the response to the
/// explicit "Start session" navigation (`start_form`), the way a real app emits it on login.
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Build the `Secure-Session-Registration` response header that invites Chrome to
/// begin device-bound registration.
///
/// WIRE FORMAT (structured field): (algs); path="..."; challenge="..."; authorization="..."
/// `path` = where Chrome will POST its signed proof; `challenge` is echoed back in the JWT as `jti`.
/// The caller mints the challenge and STORES it (a PendingRegistration) so `register` can verify it.
fn registration_header(challenge: &str) -> (HeaderName, HeaderValue) {
    // Offer only ES256 (the only alg we verify). Pinning one alg also avoids
    // algorithm-confusion, matching the reference PHP lib.
    let value = format!(
        "(ES256); path=\"/dbsc/register\"; challenge=\"{challenge}\"; authorization=\"auth-code-123\""
    );
    (
        HeaderName::from_static("secure-session-registration"),
        HeaderValue::from_str(&value).unwrap(),
    )
}

/// Step 1: the page's HTML <form> POSTs here. We reply with a **200** carrying
/// `Secure-Session-Registration` plus a cookie that stands in for the login — matching the Chrome
/// docs' login response and `report-uri/dbsc-php` (which also emit the header on a plain 200). The
/// header just has to ride the response to a top-level navigation (not a `fetch()`); 200 or a
/// 303 redirect both work.
async fn start_form(State(state): State<AppState>) -> Response {
    let _log = LOG_LOCK.lock().unwrap();
    let challenge = nonce("chal");
    let (reg_name, reg_value) = registration_header(&challenge);
    // `login_auth_id` stands in for your real login/auth SESSION cookie: it's how the server knows
    // *which logged-in user* the follow-up /dbsc/register POST belongs to. In a real app you don't
    // set a separate cookie here — your existing login session cookie does this (and rides the
    // same-origin /register request automatically). This demo has no login, so we mint a placeholder.
    let login_auth_id = nonce("login");
    // Store the issued challenge as a PendingRegistration keyed by login_auth_id, so /dbsc/register
    // can verify the JWT's `jti` against it (anti-replay). This is the record that belongs at Flow 1
    // — the Binding can't be created yet (no device key until register).
    state.pending.lock().unwrap().insert(
        login_auth_id.clone(),
        PendingRegistration { challenge, created_at: now_secs() },
    );
    let set_cookie = format!("login_auth_id={login_auth_id}; Path=/; Max-Age=3600");

    flow_header(1, "TRIGGER  (POST /start-form)");
    println!("  REQUEST : POST /start-form   (HTML form submit; no body)");
    println!("  RESPONSE: 200 OK");
    println!("            Secure-Session-Registration: {}", reg_value.to_str().unwrap_or("?"));
    println!("            Set-Cookie: {set_cookie}");
    println!("  STORE [pending]  key(login_auth_id)={login_auth_id} -> challenge stored for /register to check");

    let mut headers = HeaderMap::new();
    headers.insert(reg_name, reg_value);
    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&set_cookie).unwrap());
    let html = "<!doctype html><meta charset=\"utf-8\"><title>Session started</title>\
        <body style=\"font:15px/1.5 system-ui;max-width:720px;margin:40px auto;padding:0 16px\">\
        <h1>Session started</h1>\
        <p>Registration offered — Chrome now POSTs <code>/dbsc/register</code> automatically. \
        Watch the terminal.</p><p><a href=\"/\">&larr; back</a></p></body>";
    (StatusCode::OK, headers, Html(html)).into_response()
}

/// Step 2: Chrome POSTs its signed proof here. The JWT embeds the device PUBLIC key in
/// its `jwk` header; we verify the signature (proof-of-possession), store the key against
/// a new session, and return the session config + a short-lived bound cookie.
async fn register(State(state): State<AppState>, headers: HeaderMap, body: String) -> Response {
    let _log = LOG_LOCK.lock().unwrap();
    flow_header(2, "REGISTER  (POST /dbsc/register)");

    let Some(jwt) = jwt_from(&headers, &body) else {
        println!("  REQUEST : (missing proof JWT)");
        println!("  RESPONSE: 400 missing Secure-Session-Response");
        return (StatusCode::BAD_REQUEST, "missing Secure-Session-Response").into_response();
    };
    let Some((jwt_header, claims, signing_input, sig_b64)) = decode_jwt(&jwt) else {
        println!("  RESPONSE: 400 could not parse DBSC JWT");
        return (StatusCode::BAD_REQUEST, "could not parse DBSC JWT").into_response();
    };

    // Pin ES256 — reject alg=none / RS-with-EC-key confusion before touching the signature.
    if jwt_header.get("alg").and_then(|a| a.as_str()) != Some("ES256") {
        println!("  RESPONSE: 400 unsupported JWT alg (need ES256)");
        return (StatusCode::BAD_REQUEST, "unsupported JWT alg (need ES256)").into_response();
    }
    // The device public key is embedded in the JWT header (jwk) for registration.
    let Some(pubkey) = pubkey_from_jwk(&jwt_header) else {
        println!("  RESPONSE: 400 no jwk in JWT header");
        return (StatusCode::BAD_REQUEST, "no jwk in JWT header").into_response();
    };
    let verified = verify_sig(&signing_input, &sig_b64, &pubkey);
    let jti = claims.get("jti").and_then(|j| j.as_str()).unwrap_or("?").to_string();
    println!("  REQUEST : POST /dbsc/register");
    println!("            Cookie: {}", cookie_in(&headers));
    println!("            Secure-Session-Response (JWT): {jwt}");
    println!("            decoded -> jwk=<device public key>, jti={jti}, ES256 verified={verified}");

    // CHALLENGE CHECK: look up the PendingRegistration stored at Flow 1 (keyed by login_auth_id,
    // which rides this request as a Cookie), and require the JWT's `jti` to equal the challenge we
    // issued — and not be expired. `remove` consumes it so a challenge is single-use (anti-replay).
    let now = now_secs();
    let login = cookie_value(&headers, "login_auth_id");
    let pending = login.as_ref().and_then(|k| state.pending.lock().unwrap().remove(k));
    match pending {
        None => {
            println!("  RESPONSE: 400 no pending registration for login_auth_id={login:?} (challenge unknown)");
            return (StatusCode::BAD_REQUEST, "no pending registration").into_response();
        }
        Some(p) if now.saturating_sub(p.created_at) > REG_CHALLENGE_TTL_SECS => {
            println!("  RESPONSE: 400 registration challenge expired");
            return (StatusCode::BAD_REQUEST, "registration challenge expired").into_response();
        }
        Some(p) if p.challenge != jti => {
            println!("  RESPONSE: 400 challenge mismatch (jti={jti} != issued {})", p.challenge);
            return (StatusCode::BAD_REQUEST, "challenge mismatch").into_response();
        }
        Some(p) => println!("            challenge OK: jti matches the issued challenge ({})", p.challenge),
    }
    // (A production server would ALSO reject if !verified and check `authorization`; we still
    // "log & continue" on the ES256 signature to keep the demo forgiving — see README §9.2.)

    // Build the per-session record a production server would persist (see the `Binding` struct
    // and §9.5). In this demo user_id is a placeholder (no real login); a real app stores the
    // authenticated user and keys the store by its own session id.
    let session_id = nonce("sess");
    let cookie_value = nonce("cookie");
    let binding = Binding {
        user_id: "demo-user".to_string(),
        device_public_key: pubkey,
        algorithm: "ES256".to_string(),
        cookie_value: cookie_value.clone(),
        challenge: nonce("chal"),
        created_at: now,
        expires_at: now + SESSION_TTL_SECS,
    };
    print_binding("created", &session_id, &binding);
    state.sessions.lock().unwrap().insert(session_id.clone(), binding);

    session_response(&session_id, &cookie_value)
}

/// Step 3: Chrome calls this automatically when the bound cookie needs refreshing.
/// First call has no proof -> we reply 403 + a challenge; Chrome re-signs (with the SAME
/// device key) and retries -> we verify against the STORED key and re-mint the cookie.
async fn refresh(State(state): State<AppState>, headers: HeaderMap, body: String) -> Response {
    let _log = LOG_LOCK.lock().unwrap();
    // Session id arrives in `Sec-Secure-Session-Id` on refresh.
    let session_id = headers
        .get("sec-secure-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Reject sessions we don't know (e.g. persisted in the browser from a previous run).
    // Without this we'd blindly re-mint forever -> a refresh storm. 404 tells Chrome to
    // drop the stale session.
    // Look up the stored Binding for this session (this is why we persist it — to find the
    // device key and current state). Unknown -> 404 so Chrome drops a stale persisted session.
    let binding = state.sessions.lock().unwrap().get(&session_id).cloned();
    let Some(binding) = binding else {
        flow_header(3, "REFRESH — CHALLENGE  (POST /dbsc/refresh)");
        println!("  REQUEST : POST /dbsc/refresh");
        println!("            Cookie: {}", cookie_in(&headers));
        println!("            Sec-Secure-Session-Id: {session_id}  (unknown to server)");
        println!("  RESPONSE: 404 Not Found   (tells Chrome to drop the stale session)");
        println!("            body: unknown session");
        return (StatusCode::NOT_FOUND, "unknown session").into_response();
    };

    let Some(jwt) = jwt_from(&headers, &body) else {
        // No proof yet: demand one with a challenge. Status MUST be 403 (Chrome re-signs
        // on 403, not 401). Format: "<challenge>";id="<session_id>". Store the issued challenge
        // in the binding — a production server checks the next refresh's `jti` against it.
        let challenge = nonce("refchal");
        if let Some(b) = state.sessions.lock().unwrap().get_mut(&session_id) {
            b.challenge = challenge.clone();
        }
        let value = format!("\"{challenge}\";id=\"{session_id}\"");
        flow_header(3, "REFRESH — CHALLENGE  (POST /dbsc/refresh, no proof)");
        println!("  REQUEST : POST /dbsc/refresh");
        println!("            Cookie: {}", cookie_in(&headers));
        println!("            Sec-Secure-Session-Id: {session_id}   (no proof yet)");
        println!("  RESPONSE: 403 Forbidden");
        println!("            Secure-Session-Challenge: {value}");
        let mut out = HeaderMap::new();
        out.insert(
            HeaderName::from_static("secure-session-challenge"),
            HeaderValue::from_str(&value).unwrap(),
        );
        return (StatusCode::FORBIDDEN, out, "challenge issued").into_response();
    };

    // Proof provided: the refresh JWT has NO embedded key — verify it against the key stored in
    // the Binding at registration. That's the whole point: only this device can re-sign.
    flow_header(4, "REFRESH — PROOF  (POST /dbsc/refresh, signed JWT)");
    let (jti, verified) = match decode_jwt(&jwt) {
        Some((jwt_header, claims, signing_input, sig_b64)) => {
            let es256 = jwt_header.get("alg").and_then(|a| a.as_str()) == Some("ES256");
            let v = es256 && verify_sig(&signing_input, &sig_b64, &binding.device_public_key);
            let jti = claims.get("jti").and_then(|j| j.as_str()).unwrap_or("?").to_string();
            (jti, v)
        }
        None => ("?".to_string(), false),
    };
    println!("  REQUEST : POST /dbsc/refresh");
    println!("            Cookie: {}", cookie_in(&headers));
    println!("            Sec-Secure-Session-Id: {session_id}");
    println!("            Secure-Session-Response (JWT): {jwt}");
    println!("            decoded -> jti={jti}, no jwk, verified vs STORED key={verified}");

    // Rotate the stored cookie value + challenge (both MUST change every refresh).
    let cookie_value = nonce("cookie");
    if let Some(b) = state.sessions.lock().unwrap().get_mut(&session_id) {
        b.cookie_value = cookie_value.clone();
        b.challenge = nonce("chal");
        print_binding("updated", &session_id, b);
    }
    session_response(&session_id, &cookie_value)
}

/// Build the DBSC session-config JSON + `Set-Cookie` shared by register/refresh. The caller mints
/// and stores `cookie_value` in the `Binding`, then passes it here so the wire value matches state.
fn session_response(session_id: &str, cookie_value: &str) -> Response {
    let config = json!({
        "session_identifier": session_id,
        "refresh_url": "/dbsc/refresh",
        // Scope = which requests Chrome manages the bound cookie for. include_site:false =
        // this origin only; omitting scope_specification (like report-uri/dbsc-php) means Chrome
        // manages the cookie for ALL paths on the origin by default. (An explicit include rule
        // also works — it was never the problem; the delivery bug was reading only the first
        // Cookie header, see §5.)
        "scope": {
            "origin": cfg().origin.as_str(),
            "include_site": false
        },
        // The cookie Chrome treats as device-bound. Host-only (no Domain) + Secure +
        // HttpOnly, matching the production reference lib (report-uri/dbsc-php). A fresh
        // value is minted every register/refresh (re-using the old value makes Chrome
        // think "no refresh happened" and drop the session).
        "credentials": [{
            "type": "cookie",
            "name": cfg().cookie_name.as_str(),
            "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax"
        }]
    });

    // SameSite=Lax (not Strict): matches the Chrome docs + both reference libs. Lax keeps the
    // cookie working when the user arrives via an external top-level link; Strict would drop it
    // on that first navigation (login-UX cost) for no real gain on a hardware-bound cookie.
    let set_cookie = format!(
        "{}={cookie_value}; Path=/; Max-Age={COOKIE_MAX_AGE_SECS}; Secure; HttpOnly; SameSite=Lax",
        cfg().cookie_name
    );
    println!("  RESPONSE: 200 OK");
    println!("            Set-Cookie: {set_cookie}");
    println!(
        "            body (session config): {}",
        serde_json::to_string(&config).unwrap_or_default()
    );

    let mut out = HeaderMap::new();
    out.insert(header::SET_COOKIE, HeaderValue::from_str(&set_cookie).unwrap());
    (StatusCode::OK, out, Json(config)).into_response()
}

/// A "protected" endpoint: reports whether the device-bound cookie rode the request.
async fn protected(headers: HeaderMap) -> Response {
    let _log = LOG_LOCK.lock().unwrap();
    let cookie = cookie_in(&headers);
    let authed = has_bound_cookie(&headers);
    flow_header(5, "PROTECTED  (GET /api/protected)");
    println!("  REQUEST : GET /api/protected  |  Cookie: {cookie}");
    println!("  RESPONSE: authenticated={authed}");
    Json(json!({ "authenticated": authed, "cookie_header": cookie })).into_response()
}

/// Revoke (logout): end the device-bound session. Deletes the server-side `Binding` (so any
/// future `/dbsc/refresh` gets 404 and Chrome drops the session), deletes the bound cookie, and
/// sends `Clear-Site-Data` to tell Chrome to clear cookies + end the DBSC session for the origin.
///
/// A production server revokes the ONE session keyed by the login id. This demo has no login, so
/// it finds the binding by the presented bound-cookie value (what a normal app request carries).
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let _log = LOG_LOCK.lock().unwrap();
    flow_header(7, "LOGOUT / REVOKE  (GET /logout)");

    let presented = bound_cookie_value(&headers);
    let mut revoked = None;
    {
        let mut store = state.sessions.lock().unwrap();
        let sid = presented
            .as_ref()
            .and_then(|val| store.iter().find(|(_, b)| &b.cookie_value == val).map(|(k, _)| k.clone()));
        if let Some(sid) = sid {
            store.remove(&sid);
            revoked = Some(sid);
        }
    }
    match &revoked {
        Some(sid) => println!("  REVOKE  : deleted Binding for session_identifier={sid}"),
        None => println!("  REVOKE  : no matching session to delete (no/unknown bound cookie)"),
    }

    // Tell the browser to drop the bound cookie and end the DBSC session for this origin.
    let del = format!("{}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax", cfg().cookie_name);
    println!("  RESPONSE: 200 OK");
    println!("            Set-Cookie: {del}   (expires the bound cookie)");
    println!("            Clear-Site-Data: \"cookies\"   (ends the DBSC session)");
    let mut out = HeaderMap::new();
    out.insert(header::SET_COOKIE, HeaderValue::from_str(&del).unwrap());
    out.insert(
        HeaderName::from_static("clear-site-data"),
        HeaderValue::from_static("\"cookies\""),
    );
    let html = "<!doctype html><meta charset=\"utf-8\"><title>Logged out</title>\
        <body style=\"font:15px/1.5 system-ui;max-width:720px;margin:40px auto;padding:0 16px\">\
        <h1>Logged out</h1><p>DBSC session revoked (server binding deleted, bound cookie cleared).\
        </p><p><a href=\"/\">&larr; back</a></p></body>";
    (StatusCode::OK, out, Html(html)).into_response()
}

// ---------------------------------------------------------------------------
// JWT helpers (compact JWS parse + ES256 verification)
// ---------------------------------------------------------------------------

/// Pull the DBSC proof JWT from either the `Secure-Session-Response` header or the body
/// (implementations differ on which they use).
fn jwt_from(headers: &HeaderMap, body: &str) -> Option<String> {
    if let Some(v) = headers
        .get("secure-session-response")
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    let b = body.trim();
    (!b.is_empty()).then(|| b.to_string())
}

/// Split a compact JWT into (header JSON, claims JSON, signing-input, signature-b64).
/// signing-input is `header.payload` — the exact bytes the signature covers.
fn decode_jwt(jwt: &str) -> Option<(Value, Value, String, String)> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).ok()?).ok()?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    Some((header, claims, signing_input, parts[2].to_string()))
}

/// Extract an EC P-256 public key from a JWT header's `jwk` (used at registration).
fn pubkey_from_jwk(jwt_header: &Value) -> Option<PubKey> {
    let jwk = jwt_header.get("jwk")?;
    Some(PubKey {
        x: jwk.get("x")?.as_str()?.to_string(),
        y: jwk.get("y")?.as_str()?.to_string(),
    })
}

/// Verify an ES256 (P-256 + SHA-256) JWS signature over `signing_input` using `key`.
fn verify_sig(signing_input: &str, sig_b64: &str, key: &PubKey) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let (Ok(x), Ok(y)) = (URL_SAFE_NO_PAD.decode(&key.x), URL_SAFE_NO_PAD.decode(&key.y)) else {
        return false;
    };
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    // Uncompressed SEC1 point: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    // A JWS ES256 signature is raw r||s (64 bytes), not DER.
    let Some(sig) = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .ok()
        .and_then(|b| Signature::from_slice(&b).ok())
    else {
        return false;
    };
    vk.verify(signing_input.as_bytes(), &sig).is_ok()
}

const INDEX_HTML: &str = r#"<!doctype html>
<html>
<head><meta charset="utf-8"><title>DBSC hello-world</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 720px; margin: 40px auto; padding: 0 16px; }
  button { font-size: 15px; padding: 8px 14px; margin-right: 8px; cursor: pointer; }
  pre { background: #111; color: #b7f; padding: 12px; border-radius: 8px; white-space: pre-wrap; }
  code { background: #eee; padding: 1px 4px; border-radius: 4px; }
</style>
</head>
<body>
  <h1>DBSC hello-world</h1>
  <p>Open <b>DevTools &rarr; Network</b>, then:</p>
  <ol>
    <li><b>Start session</b> submits a form to <code>/start-form</code>; the browser then
        automatically POSTs <code>/dbsc/register</code> and later <code>/dbsc/refresh</code>.
        Watch the terminal.</li>
    <li><b>Call protected</b> checks whether the device-bound cookie rode the request —
        <code>authenticated=true</code> once a session is registered.</li>
  </ol>
  <p>
    <!-- This is a real form-POST navigation (the page then shows /start-form's 200) ON PURPOSE.
         The Secure-Session-Registration header must ride the response to a top-level NAVIGATION;
         Chrome silently IGNORES it on a fetch()/XHR response, so don't switch this to fetch().
         In a real app this is just your normal login response (a 200, like the Chrome docs). -->
    <form method="POST" action="/start-form" style="display:inline">
      <button type="submit">Start session</button>
    </form>
    <button onclick="callProtected()">Call protected</button>
    <a href="/logout"><button type="button">Logout (revoke)</button></a>
  </p>
  <pre id="log">(server log is in your terminal; browser log here)</pre>
<script>
const log = (m) => { document.getElementById('log').textContent =
  new Date().toLocaleTimeString() + '  ' + m + '\n' + document.getElementById('log').textContent; };

async function callProtected() {
  const r = await fetch('/api/protected');
  const j = await r.json();
  log('GET /api/protected -> authenticated=' + j.authenticated);
}
</script>
</body>
</html>
"#;
