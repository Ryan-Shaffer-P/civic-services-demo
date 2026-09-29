// Civic Services demo: static site gated by session login, backed by D1.
// Passwords: PBKDF2-SHA256 (WebCrypto). Sessions: random token in an HttpOnly
// cookie; only the SHA-256 of the token is stored in D1.

const enc = new TextEncoder();

const SESSION_SECONDS = 7 * 24 * 60 * 60;
const PBKDF2_ITERATIONS = 100000; // Workers' maximum for PBKDF2
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const INVALID_LOGIN = "Incorrect email or password.";
const VERIFY_FAILED = "Verification failed. Complete the check and try again.";

// Reachable without signing in
const PUBLIC_PATHS = new Set(["/login", "/login.html", "/signup", "/signup.html", "/styles.css", "/auth.js", "/favicon.ico"]);
const AUTH_PAGES = new Set(["/login", "/signup"]);

const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

// Login and signup pages also load the Turnstile widget (script + iframe)
const AUTH_CSP_PATHS = new Set(["/login", "/login.html", "/signup", "/signup.html"]);
const AUTH_CSP =
  "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; " +
  "frame-src https://challenges.cloudflare.com; img-src 'self' data:; " +
  "base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const SECURITY_HEADERS = {
  "Content-Security-Policy":
    "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (path.startsWith("/api/")) {
        return withSecurity(await handleApi(request, env, url));
      }

      const user = await getUser(request, env);

      if (PUBLIC_PATHS.has(path)) {
        if (user && AUTH_PAGES.has(path)) return withSecurity(redirect("/"));
        return withSecurity(await env.ASSETS.fetch(request), {
          csp: AUTH_CSP_PATHS.has(path) ? AUTH_CSP : undefined,
        });
      }
      if (!user) return withSecurity(redirect("/login"));
      return withSecurity(await env.ASSETS.fetch(request), { noStore: true });
    } catch (err) {
      console.error(err);
      return withSecurity(json({ error: "Something went wrong. Try again." }, 500));
    }
  },
};

/* ---------- API ---------- */

async function handleApi(request, env, url) {
  const path = url.pathname;

  if (path === "/api/me" && request.method === "GET") {
    const user = await getUser(request, env);
    return user ? json({ name: user.name, email: user.email }) : json({ error: "Not signed in." }, 401);
  }

  const routes = ["/api/signup", "/api/login", "/api/logout"];
  if (request.method !== "POST" || !routes.includes(path)) {
    return json({ error: "Not found." }, 404);
  }

  // CSRF defense in depth (the cookie is also SameSite=Lax)
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) return json({ error: "Bad origin." }, 403);

  if (path === "/api/logout") return logout(request, env, url);

  const body = await readJson(request);
  if (!body) return json({ error: "Invalid request." }, 400);
  const ip = request.headers.get("CF-Connecting-IP") || "";
  return path === "/api/signup" ? signup(body, env, url, ip) : login(body, env, url, ip);
}

async function signup(body, env, url, ip) {
  const name = String(body.name ?? "").trim();
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");

  if (!name || name.length > 80) return json({ error: "Enter your name (80 characters max)." }, 400);
  if (!EMAIL_RE.test(email) || email.length > 254) return json({ error: "Enter a valid email address." }, 400);
  if (password.length < 10 || password.length > 128) {
    return json({ error: "Password must be 10 to 128 characters." }, 400);
  }

  // Verify before the expensive password hash
  if (!(await verifyTurnstile(env, body["cf-turnstile-response"], "signup", ip))) {
    return json({ error: VERIFY_FAILED }, 403);
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, PBKDF2_ITERATIONS);

  let userId;
  try {
    const res = await env.DB.prepare(
      "INSERT INTO users (email, name, pw_salt, pw_hash, pw_iter, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    ).bind(email, name, b64(salt), b64(hash), PBKDF2_ITERATIONS, now()).run();
    userId = res.meta.last_row_id;
  } catch (err) {
    if (String(err && err.message).includes("UNIQUE")) {
      return json({ error: "An account with that email already exists." }, 409);
    }
    throw err;
  }

  const cookie = await createSession(env, userId, url);
  return json({ ok: true }, 201, { "Set-Cookie": cookie });
}

async function login(body, env, url, ip) {
  const email = String(body.email ?? "").trim().toLowerCase();
  const password = String(body.password ?? "");
  if (!email || !password || password.length > 128) return json({ error: INVALID_LOGIN }, 401);

  if (!(await verifyTurnstile(env, body["cf-turnstile-response"], "login", ip))) {
    return json({ error: VERIFY_FAILED }, 403);
  }

  const user = await env.DB.prepare(
    "SELECT id, pw_salt, pw_hash, pw_iter FROM users WHERE email = ?1"
  ).bind(email).first();

  if (!user) {
    // Do the same work so response time doesn't reveal which emails exist
    await derive(password, new Uint8Array(16), PBKDF2_ITERATIONS);
    return json({ error: INVALID_LOGIN }, 401);
  }

  const attempt = await derive(password, unb64(user.pw_salt), user.pw_iter);
  if (!safeEqual(attempt, unb64(user.pw_hash))) return json({ error: INVALID_LOGIN }, 401);

  await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?1").bind(now()).run();
  const cookie = await createSession(env, user.id, url);
  return json({ ok: true }, 200, { "Set-Cookie": cookie });
}

async function logout(request, env, url) {
  const token = getCookie(request, "session");
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(await sha256hex(token)).run();
  }
  return json({ ok: true }, 200, { "Set-Cookie": cookieString("", url, 0) });
}

/* ---------- Turnstile ---------- */

// Server-side siteverify. Fails closed: any error, missing config, wrong action
// or unexpected hostname rejects the request. Tokens are single-use.
async function verifyTurnstile(env, token, expectedAction, ip) {
  const hostnames = new Set(
    String(env.TURNSTILE_HOSTNAMES ?? "").split(",").map((h) => h.trim()).filter(Boolean)
  );
  if (!env.TURNSTILE_SECRET || hostnames.size === 0) {
    console.error("Turnstile is not configured: set the TURNSTILE_SECRET secret and TURNSTILE_HOSTNAMES var");
    return false;
  }
  if (typeof token !== "string" || token.length === 0 || token.length > 2048) return false;

  try {
    const form = new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: token });
    if (ip) form.set("remoteip", ip);
    const res = await fetch(TURNSTILE_VERIFY_URL, {
      method: "POST",
      body: form,
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`siteverify ${res.status}`);
    const result = await res.json();
    return result.success === true && result.action === expectedAction && hostnames.has(result.hostname);
  } catch (err) {
    console.error("Turnstile siteverify failed:", err && err.message);
    return false;
  }
}

/* ---------- Sessions ---------- */

async function createSession(env, userId, url) {
  const token = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const t = now();
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)"
  ).bind(await sha256hex(token), userId, t + SESSION_SECONDS, t).run();
  return cookieString(token, url, SESSION_SECONDS);
}

async function getUser(request, env) {
  const token = getCookie(request, "session");
  if (!token || token.length > 100) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.email, u.name
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?1 AND s.expires_at > ?2`
  ).bind(await sha256hex(token), now()).first();
  return row || null;
}

function cookieString(value, url, maxAge) {
  const secure = url.protocol === "https:" ? "; Secure" : "";
  return `session=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/* ---------- Crypto helpers ---------- */

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

async function sha256hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const b64 = (bytes) => btoa(String.fromCharCode(...bytes));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const now = () => Math.floor(Date.now() / 1000);

/* ---------- Response helpers ---------- */

async function readJson(request) {
  try {
    const text = await request.text();
    if (text.length > 4096) return null;
    const body = JSON.parse(text);
    return body && typeof body === "object" ? body : null;
  } catch {
    return null;
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { Location: location, "cache-control": "no-store" } });
}

function withSecurity(res, { noStore = false, csp } = {}) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  if (csp) out.headers.set("Content-Security-Policy", csp);
  if (noStore) out.headers.set("Cache-Control", "private, no-store");
  return out;
}
