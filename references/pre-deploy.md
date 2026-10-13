# Pre-deploy gate — the release checklist

A gate, not a guide: every change going to production passes this, and failing one Critical/High item means not deploying. Sized for AI-built web apps (the defaults: some BaaS, some LLM calls, some payments or auth).

> Upstream credit: gate structure and release-blocking discipline adapted from `izaurogabriel-hash/cyberseguranca`'s pre-deploy checklist (MIT); RLS-test and secret-scan items reinforced from `raroque/vibe-security-skill` (MIT). See `/ATTRIBUTION.md`.

---

## 1. Code & tests

- [ ] CI green: lint + typecheck + tests + SAST/secret scan (Semgrep/CodeQL + gitleaks) on the diff
- [ ] Tests cover the changed behavior, including an E2E pass on the critical flow (login, checkout, or whatever losing money looks like)
- [ ] **RLS/rules test** passed if any schema or policy changed (a policy test that inserts as user A and reads as user B, expecting denial)
- [ ] Staging smoke test with representative data
- [ ] No `console.log`/logging of PII or secrets; no unresolved TODO/FIXME on security paths
- [ ] Rollback plan (feature flag or revert path) for large changes

## 2. Schema / DB changes

- [ ] Migration tested on staging with representative data
- [ ] **RLS enabled** (`ENABLE ROW LEVEL SECURITY`, `FORCE` where applicable) on every new table — and the catch-all loop run for tables added since the last pass
- [ ] Policies reviewed: owner-scoped `USING`, `WITH CHECK` on write policies, no `true` policies
- [ ] Indexes on columns used by policies/filters (an unindexed policy is a DoS invitation via slow queries)
- [ ] Backup verified working **before** migrating; rollback migration written

## 3. Secrets & config

- [ ] No secrets in the diff (gitleaks clean); nothing new hardcoded
- [ ] Secrets set via the platform's env/secret store — not in committed config, not in `wrangler.toml`-style files
- [ ] `.env*` in `.gitignore` and absent from the repo (including history for anything that ever leaked — rotate if so)
- [ ] Dev/staging/prod use distinct secrets; preview deployments don't inherit prod secrets unintentionally
- [ ] Client env prefixes (`NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_`) contain only publishable values

## 4. Headers, CSP, CORS, cookies

- [ ] Security headers present (CSP, HSTS, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`)
- [ ] CSP actually enforced — no console violations in a real browsing session; nonces/hashes instead of blanket `unsafe-inline` where feasible
- [ ] CORS: exact-origin allow-list; no wildcard-with-credentials, no origin reflection
- [ ] Cookies: `HttpOnly` + `Secure` + `SameSite`; `__Host-`/`__Secure-` prefixes where applicable

## 5. Auth & authorization

- [ ] Authorization check in **every** new endpoint/action (in the handler, not just the page)
- [ ] JWT validation pins `alg`, verifies `iss`/`aud`/`exp`; role derived server-side only
- [ ] Session rotation on login/privilege change; logout invalidates server-side
- [ ] Login/reset/MFA endpoints rate-limited; failures are generic (no account enumeration)
- [ ] No client-supplied role/admin header trusted anywhere

## 6. Input & output

- [ ] Strict schema validation (Zod `.strict()` / Pydantic `extra='forbid'`) on all external input
- [ ] Parameterized queries everywhere raw SQL exists; no new string-built interpreters
- [ ] Output encoding correct for context (HTML/JS/URL); no new `innerHTML`/`v-html` on user data
- [ ] Uploads (if any): type sniffed server-side, size caps, stored outside the app origin or served with safe headers
- [ ] SSRF guard on any outbound fetch of user-supplied URLs

## 7. Payments / metered resources (when present)

- [ ] Prices/quantities derived server-side; nothing money-shaped accepted from the request
- [ ] Webhook signatures verified with the raw body; handlers idempotent
- [ ] Rate limits / usage caps on LLM and other metered calls, per user and per IP
- [ ] Entitlements read from server-owned state

## 8. AI/LLM integration (when present)

- [ ] Provider keys server-side only; client goes through your endpoint
- [ ] Usage caps enforced before spend
- [ ] Model output treated as untrusted input wherever rendered or executed
- [ ] Prompt/logs redacted of PII and secrets

## 9. Observability & response

- [ ] Structured logs on auth events, payment events, and admin actions (no PII)
- [ ] Error tracking wired (Sentry-class) with release tagging — you want to know before the users do
- [ ] Alerts on error-rate/error-budget spikes and on unusual 401/403 patterns
- [ ] A written "who do we call / what do we rotate" note for the top two failure scenarios

---

**Gate semantics:** Critical/High items (2, 3, 5, and the money items in 7) are blocking. Medium/Low items may ship with a tracked follow-up. The checklist is the floor, not the ceiling — an app holding health or financial data adds its regulatory gates (LGPD/GDPR/HIPAA as applicable) on top.
