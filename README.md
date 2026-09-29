# Civic Services Demo

Service request site for a fictional "Department of Civic Services", with
signup and login built on Cloudflare Workers + D1.

- `public/` static pages (dashboard, login, signup), CSS and JS
- `src/index.js` Worker: session gate, `/api/signup`, `/api/login`, `/api/logout`, `/api/me`
- `schema.sql` D1 tables (`users`, `sessions`)
- `wrangler.jsonc` Worker config (static assets + D1 binding)

## One-time setup

```bash
npm install
npx wrangler login
npx wrangler d1 create civic-services-db
```

Copy the `database_id` it prints into `wrangler.jsonc`, then create the tables:

```bash
npm run db:remote     # production database
npm run db:local      # local database used by `wrangler dev`
```

## Run locally

```bash
npm run dev           # http://localhost:8787
```

## Turnstile (bot protection on login and signup)

- Widget sitekey is in `public/auth.js` (public by design)
- Server-side check: `verifyTurnstile()` in `src/index.js` calls siteverify and requires
  `success`, the expected action (`login` or `signup`) and an approved hostname
- Config: `TURNSTILE_HOSTNAMES` (plain var in `wrangler.jsonc`, production hostnames only)
  and `TURNSTILE_SECRET` (a Worker **secret**, never committed)
- Add the secret in the dashboard: Worker, Settings, Variables and Secrets, Add, type Secret,
  name `TURNSTILE_SECRET`, value = the widget's secret key (Turnstile page in the dashboard)
- The widget's hostname list must include your production hostname
- For local dev, put `TURNSTILE_SECRET=...` in `.dev.vars` (gitignored) and set
  `TURNSTILE_HOSTNAMES` to `localhost`; the widget's hostname list must include `localhost`

## Deploy

```bash
npm run deploy
```

If you deploy from GitHub (Workers Builds), commit `wrangler.jsonc` with the
real `database_id` and make sure `name` matches your existing Worker. Run
`npm run db:remote` once before the first login attempt.

## How auth works

- Passwords: PBKDF2-SHA256, 100,000 iterations (the Workers maximum), random salt per user
- Sessions: 256-bit random token in an HttpOnly, SameSite=Lax, Secure cookie;
  only the SHA-256 of the token is stored in D1; 7-day expiry; logout deletes the row
- Every request except `/login`, `/signup`, `/styles.css` and `/auth.js` requires a valid session
- POSTs are rejected if the `Origin` header doesn't match the site
- Login and signup require a valid Turnstile token (single-use); the check fails closed
- Responses carry a strict CSP, `X-Frame-Options: DENY` and `nosniff`

Not included (worth adding for anything real): rate limiting (use a WAF rule),
email verification, password reset.
