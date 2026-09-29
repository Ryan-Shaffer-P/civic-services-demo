# Civic Services Demo

Single-page demo of a service request form for city infrastructure problems
(potholes, streetlights, water leaks, and so on) for a fictional
"Department of Civic Services".

- Static site: one self-contained `index.html`, no build step
- Nothing is submitted anywhere; requests live in the page's memory only
- Hosted on Cloudflare Pages at https://demo.shaffernet.net

## Deploy

Cloudflare Pages, connected to this repo:

- Framework preset: None
- Build command: (empty)
- Build output directory: `/`
- Production branch: `main`

Every push to `main` redeploys.

## Local preview

```bash
python3 -m http.server 8000
# open http://localhost:8000
```
