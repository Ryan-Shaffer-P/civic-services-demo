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
- Responses carry a strict CSP, `X-Frame-Options: DENY` and `nosniff`

Not included (worth adding for anything real): rate limiting, email
verification, password reset, Turnstile on the forms.
