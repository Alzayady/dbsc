//! DBSC (Device Bound Session Credentials) hello-world.
//!
//! A small HTTPS server that makes the DBSC handshake *visible* so you can learn it.
//! Each request/response pair is logged to stdout as a numbered FLOW (1-5). See README.md: what
//! DBSC is, the required Chrome flags, the sequence diagram, and what works vs. not.
//!
//! Endpoints (see README for the flow):
//!   GET  /               – the demo page (Start session / Call protected buttons)
//!   POST /start-form     – 303 redirect carrying `Secure-Session-Registration` (starts DBSC)
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
        Arc, Mutex,
    },
};

const ORIGIN: &str = "https://localhost:3000";
const HOST: &str = "localhost";
const COOKIE_NAME: &str = "auth_cookie";
/// Deliberately short so you can watch Chrome auto-refresh it.
const COOKIE_MAX_AGE_SECS: u64 = 20;

/// An EC P-256 public key (base64url X/Y coordinates), as carried in a device JWT's `jwk`.
#[derive(Clone)]
struct PubKey {
    x: String,
    y: String,
}

/// In-memory store: session_identifier -> the device public key bound at registration.
/// Cleared on restart (so sessions persisted in the browser become "unknown" — see refresh).
#[derive(Clone, Default)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, PubKey>>>,
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Unique, short, alphanumeric id/challenge for the demo (NOT cryptographically strong).
/// Chrome is picky about the challenge, so we avoid underscores / huge values.
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

#[tokio::main]
async fn main() {
    let state = AppState::default();
    let app = Router::new()
        .route("/", get(index))
        .route("/start-form", post(start_form))
        .route("/dbsc/register", post(register))
        .route("/dbsc/refresh", post(refresh))
        .route("/api/protected", get(protected))
        .with_state(state);

    // rustls 0.23 needs a process-wide crypto provider chosen explicitly.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring provider");

    // DBSC only engages over real TLS. These are the files mkcert produces:
    //   mkcert localhost 127.0.0.1 ::1
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        "localhost+2.pem",
        "localhost+2-key.pem",
    )
    .await
    .expect(
        "TLS certs not found. In this dir run:\n  \
         brew install mkcert && mkcert -install\n  \
         mkcert localhost 127.0.0.1 ::1",
    );

    let addr: std::net::SocketAddr = "127.0.0.1:3000".parse().unwrap();
    println!("\n=== DBSC hello-world (HTTPS) ===");
    println!("Open  {ORIGIN}  in Chrome (with the DBSC flags from README enabled).");
    println!("Keep DevTools -> Network open to watch the Secure-Session-* handshake.\n");
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Serve the page. The registration invite is NOT emitted here — Chrome ignores it on
/// a plain GET navigation; it must ride on the form-POST 303 (see `start_form`).
async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Build the `Secure-Session-Registration` response header that invites Chrome to
/// begin device-bound registration.
///
/// WIRE FORMAT (structured field): (algs); path="..."; challenge="..."; authorization="..."
/// `path` = where Chrome will POST its signed proof; `challenge` is echoed back in the JWT.
fn registration_header() -> (HeaderName, HeaderValue) {
    let challenge = nonce("chal");
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

/// Step 1: the page's HTML <form> POSTs here. We reply with a 303 redirect back to `/`
/// carrying `Secure-Session-Registration` plus a correlation cookie. This specific
/// response shape (form POST → 303) is what Chrome acts on to start registration.
async fn start_form() -> Response {
    let (reg_name, reg_value) = registration_header();
    let reg_id = nonce("regid");
    let set_cookie = format!("dbsc-registration-sessions-id={reg_id}; Path=/; Max-Age=3600");

    flow_header(1, "TRIGGER  (POST /start-form)");
    println!("  REQUEST : POST /start-form   (HTML form submit; no body)");
    println!("  RESPONSE: 303 See Other");
    println!("            Location: /");
    println!("            Secure-Session-Registration: {}", reg_value.to_str().unwrap_or("?"));
    println!("            Set-Cookie: {set_cookie}");

    let mut headers = HeaderMap::new();
    headers.insert(reg_name, reg_value);
    headers.insert(header::LOCATION, HeaderValue::from_static("/"));
    headers.insert(header::SET_COOKIE, HeaderValue::from_str(&set_cookie).unwrap());
    (StatusCode::SEE_OTHER, headers, "").into_response()
}

/// Step 2: Chrome POSTs its signed proof here. The JWT embeds the device PUBLIC key in
/// its `jwk` header; we verify the signature (proof-of-possession), store the key against
/// a new session, and return the session config + a short-lived bound cookie.
async fn register(State(state): State<AppState>, headers: HeaderMap, body: String) -> Response {
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
    let jti = claims.get("jti").and_then(|j| j.as_str()).unwrap_or("?");
    println!("  REQUEST : POST /dbsc/register");
    println!("            Secure-Session-Response (JWT): {jwt}");
    println!("            decoded -> jwk=<device public key>, jti={jti}, ES256 verified={verified}");
    // A production server would also check jti == the challenge it issued and
    // authorization == its auth code, and REJECT if !verified. We log & continue.

    let session_id = nonce("sess");
    state.sessions.lock().unwrap().insert(session_id.clone(), pubkey);

    session_response(&session_id)
}

/// Step 3: Chrome calls this automatically when the bound cookie needs refreshing.
/// First call has no proof -> we reply 403 + a challenge; Chrome re-signs (with the SAME
/// device key) and retries -> we verify against the STORED key and re-mint the cookie.
async fn refresh(State(state): State<AppState>, headers: HeaderMap, body: String) -> Response {
    // Session id arrives in `Sec-Secure-Session-Id` on refresh.
    let session_id = headers
        .get("sec-secure-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Reject sessions we don't know (e.g. persisted in the browser from a previous run).
    // Without this we'd blindly re-mint forever -> a refresh storm. 404 tells Chrome to
    // drop the stale session.
    let stored_key = state.sessions.lock().unwrap().get(&session_id).cloned();
    let Some(stored_key) = stored_key else {
        flow_header(3, "REFRESH — CHALLENGE  (POST /dbsc/refresh)");
        println!("  REQUEST : POST /dbsc/refresh");
        println!("            Sec-Secure-Session-Id: {session_id}  (unknown to server)");
        println!("  RESPONSE: 404 Not Found   (tells Chrome to drop the stale session)");
        println!("            body: unknown session");
        return (StatusCode::NOT_FOUND, "unknown session").into_response();
    };

    let Some(jwt) = jwt_from(&headers, &body) else {
        // No proof yet: demand one with a challenge. Status MUST be 403 (Chrome re-signs
        // on 403, not 401). Format: "<challenge>";id="<session_id>".
        let challenge = nonce("refchal");
        let value = format!("\"{challenge}\";id=\"{session_id}\"");
        flow_header(3, "REFRESH — CHALLENGE  (POST /dbsc/refresh, no proof)");
        println!("  REQUEST : POST /dbsc/refresh");
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

    // Proof provided: the refresh JWT has NO embedded key — verify it against the key we
    // stored at registration. That's the whole point: only this device can re-sign.
    flow_header(4, "REFRESH — PROOF  (POST /dbsc/refresh, signed JWT)");
    let (jti, verified) = match decode_jwt(&jwt) {
        Some((jwt_header, claims, signing_input, sig_b64)) => {
            let es256 = jwt_header.get("alg").and_then(|a| a.as_str()) == Some("ES256");
            let v = es256 && verify_sig(&signing_input, &sig_b64, &stored_key);
            let jti = claims.get("jti").and_then(|j| j.as_str()).unwrap_or("?").to_string();
            (jti, v)
        }
        None => ("?".to_string(), false),
    };
    println!("  REQUEST : POST /dbsc/refresh");
    println!("            Sec-Secure-Session-Id: {session_id}");
    println!("            Secure-Session-Response (JWT): {jwt}");
    println!("            decoded -> jti={jti}, no jwk, verified vs STORED key={verified}");
    session_response(&session_id)
}

/// Build the DBSC session-config JSON + `Set-Cookie` shared by register/refresh.
fn session_response(session_id: &str) -> Response {
    let cookie_value = nonce("cookie");

    let config = json!({
        "session_identifier": session_id,
        "refresh_url": "/dbsc/refresh",
        // Scope = which requests Chrome manages the bound cookie for. include_site:false
        // = this origin only; the single include rule covers all paths. The refresh_url
        // is auto-excluded by the browser.
        "scope": {
            "origin": ORIGIN,
            "include_site": false,
            "scope_specification": [
                { "type": "include", "domain": HOST, "path": "/" }
            ]
        },
        // The cookie Chrome treats as device-bound. Host-only (no Domain) + Secure +
        // HttpOnly, matching the production reference lib (report-uri/dbsc-php). A fresh
        // value is minted every register/refresh (re-using the old value makes Chrome
        // think "no refresh happened" and drop the session).
        "credentials": [{
            "type": "cookie",
            "name": COOKIE_NAME,
            "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax"
        }]
    });

    // SameSite=Lax (not Strict): matches the Chrome docs + both reference libs. Lax keeps the
    // cookie working when the user arrives via an external top-level link; Strict would drop it
    // on that first navigation (login-UX cost) for no real gain on a hardware-bound cookie.
    let set_cookie = format!(
        "{COOKIE_NAME}={cookie_value}; Path=/; Max-Age={COOKIE_MAX_AGE_SECS}; Secure; HttpOnly; SameSite=Lax"
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

/// A "protected" endpoint: reports whether the device-bound cookie was sent with the request.
async fn protected(headers: HeaderMap) -> Response {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let authed = cookie
        .split(';')
        .any(|c| c.trim().starts_with(&format!("{COOKIE_NAME}=")));
    flow_header(5, "PROTECTED  (GET /api/protected)");
    println!("  REQUEST : GET /api/protected");
    println!("            Cookie: {cookie:?}");
    println!("  RESPONSE: 200 OK");
    println!("            body: {{\"authenticated\":{authed},\"cookie_header\":{cookie:?}}}");
    Json(json!({ "authenticated": authed, "cookie_header": cookie })).into_response()
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
    <li><b>Call protected</b> checks whether the device-bound cookie was delivered.
        (On the macOS software-keys test setup this stays <code>false</code> — see README.)</li>
  </ol>
  <p>
    <!-- This is a real form-POST navigation (so the page reloads) ON PURPOSE. The
         Secure-Session-Registration header must ride the response to a POST navigation;
         Chrome silently IGNORES it on a fetch()/XHR response, so don't "fix" the reload by
         switching to fetch(). In a real app this is just your normal login POST → redirect. -->
    <form method="POST" action="/start-form" style="display:inline">
      <button type="submit">Start session</button>
    </form>
    <button onclick="callProtected()">Call protected</button>
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
