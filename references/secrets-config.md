# Secrets, headers, CORS & deployment configuration

Two jobs here: (1) never let credentials or keys escape the server, and (2) make the browser-side posture (headers, CSP, CORS, cookies) an actual barrier instead of a default no-op. These are OWASP A02/A05 territory — individually small, collectively the difference between "one bug" and "full compromise."

> Upstream credit: client-env exposure and key hygiene merged from `raroque/vibe-security-skill` (MIT); header/CORS/cookie checklist from `izaurogabriel-hash/cyberseguranca` (MIT) and `bridge-mind/BridgeSecurity` (MIT). See `/ATTRIBUTION.md`.

---

## Secrets hygiene

### Where AI-built apps leak keys

- **Client env prefixes:** anything under `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_` is compiled **into the browser bundle** — public by construction. Server-only keys (Stripe secret, OpenAI/Anthropic, Supabase `service_role`, DB URLs) must never appear under them.
- **Hardcoded** keys in source, config files, READMEs, examples, test fixtures — a key in a committed test file is a leaked key.
- **`.env` committed to git** (missing from `.gitignore`; `git rm --cached .env` and rotate).
- **Secrets in logs and errors:** `console.log('sending with key', apiKey)`, stack traces and driver errors returned raw to clients.
- **Secrets in client-visible payloads:** an API response that includes the user's own API key where it isn't needed, or admin tokens sent to non-admin clients.
- **CI/CD:** secrets echoed in build logs, pinned in workflow YAML instead of the platform's secret store; fork-PR workflows that would receive secrets if misconfigured.

### The rules

1. Secrets live in env vars (or a secret manager) on the server only.
2. The client gets, at most, publishable keys (Stripe publishable, Supabase anon, Maps embed key) — and if a key must be domain-restricted, restrict it in the provider console (referrer allow-lists, key restrictions). Assume any client-visible value is public forever.
3. **Rotation is part of the fix.** If a secret ever reached a bundle, repo, or log: rotate first, then clean up. Removing it from HEAD does not remove it from history (and history is scraped by bots within minutes of a push).
4. Scan before pushing: `gitleaks`/`trufflehog` in pre-commit or CI; a high-entropy string in a diff is a stop-the-line event.
5. Logs: structured server-side logging with PII/secret redaction; generic errors to the client with a correlation id, detail in the server log only.

## Security headers

The baseline set (any real framework has a helmet-equivalent — use it, then tune):

| Header | What it buys you | Notes |
| --- | --- | --- |
| `Content-Security-Policy` | Real XSS mitigation | Start with `default-src 'self'`, loosen per actual need; a CSP you never tighten is decoration |
| `Strict-Transport-Security` | Forces HTTPS | `max-age=31536000`; preload list only when stable |
| `X-Content-Type-Options: nosniff` | Stops MIME confusion | Free win |
| `X-Frame-Options: DENY` / CSP `frame-ancestors` | Anti-clickjacking | DENY unless you embed yourself |
| `Referrer-Policy: strict-origin-when-cross-origin` | Less leakage in links | |
| `Permissions-Policy` | Locks camera/geo/mic defaults | Deny what the app doesn't use |

CSP notes for AI-built apps: inline scripts and `unsafe-eval` are how every AI-generated dashboard boots — that's also how CSP becomes a no-op. Prefer nonces/hashes over `unsafe-inline`, and treat `'unsafe-eval'` as a temporary exception with a comment saying why.

## CORS

- The dangerous combo is `origin: '*'` **with** `credentials: true` — browsers block it, and devs then "fix" it by reflecting the request origin, which is worse (any site, with cookies). Never reflect arbitrary origins.
- Allow-list exact origins (`https://app.example.com`), only the methods and headers each surface needs, and short `max-age`.
- Non-browser clients (curl, servers, mobile apps) ignore CORS — CORS protects browsers from *other sites*, it is not authentication. Pair it with real auth on the endpoint.

## Cookies

- `HttpOnly` (no JS access), `Secure` (HTTPS only), `SameSite=Lax|Strict` (CSRF layer), `__Host-`/`__Secure-` prefix.
- Session cookie: small, opaque id into server state (or a properly signed JWT — see `auth-access.md`).
- CSRF: `SameSite` covers most; add token-based CSRF protection for state-changing endpoints if you support old browsers or cross-site POSTs from partners.

## Deployment configuration

- **Environment separation:** dev/staging/prod secrets are different secrets; no cross-env reuse (a leaked staging key must not open prod).
- **Source maps:** shipping production source maps publicly is shipping your server logic (and any accidentally-inlined config) — restrict or delete them.
- **Framework flags:** Next.js `output: 'standalone'` vs default, debug modes off, `NODE_ENV=production`, error overlays off; Django `DEBUG=False` with `ALLOWED_HOSTS`; Express trust proxy set correctly behind your LB (or `req.ip` is spoofable and your rate limits are theater).
- **Platform config:** Vercel/Netlify env vars are the right place for keys — check they're scoped server-side, and that preview deployments don't inherit prod secrets unless intended.
- **Containers/infra** (when present): non-root user, no `privileged`, pinned base images, no docker.sock mount, `latest` is not a version.
- **Expose only what's needed:** database, Redis, admin ports on private networks; security groups closed to 0.0.0.0/0 except the public entry points.

## AI/LLM integration specifics

AI-built apps almost always embed an LLM call; those have their own leak paths:

- Provider keys server-side; browser calls route through your own `/api/ai` endpoint or a purpose-built edge function with a publishable-but-restricted key — never the secret key in the client.
- **Usage caps per user/IP** before the first token is spent — an unmetered endpoint is a bill-draining orifice (OWASP LLM04-family abuse).
- Treat model output as untrusted input when you render it (`innerHTML` on LLM output = stored XSS with a convincing author) or hand it to tools/executors (prompt injection).
- Don't send secrets/PII into prompts they don't need; prompt logs are logs (redact them too).
