# The top classes AI-built apps actually ship

Ranked by how often they appear in AI-generated web apps, not by textbook order. Each entry: what the agent does wrong, how to spot it, the fix pattern, and the standards anchor. This is the map for write-secure, audit, and hack-me modes alike — when you only have budget to check five things, check the top five.

> Upstream credit: ranking and class selection merged from `kulchankas/paranoid`'s vibe-coded top 10 and `raroque/vibe-security-skill`'s audit areas (both MIT); CWE/OWASP anchors from `bridge-mind/BridgeSecurity` and `UnitOneAI/SecuritySkills` (both MIT). See `/ATTRIBUTION.md`.

---

### 1. Broken access control / IDOR (CWE-639, CWE-862/863 — OWASP A01)

The endpoint authenticates the user ("are you logged in?") but never authorizes the object ("is this row *yours*?"). The most common one of all.

```js
// ✗ any logged-in user can read any invoice
app.get('/api/invoices/:id', auth, async (req, res) => {
  const inv = await db.invoice.findUnique({ where: { id: req.params.id } });
  res.json(inv);
});
// ✓ scope every lookup to the caller
const inv = await db.invoice.findFirst({
  where: { id: req.params.id, userId: req.user.id },
});
if (!inv) return res.sendStatus(404);
```

**Spot:** any query keyed on a client-supplied id without the caller's id in the `where`; `findById`-style calls under an authenticated route. **Fix:** ownership in the query itself; `404` on miss (a `403` confirms the id exists — a leak of its own).
→ `auth-access.md`

### 2. Missing authentication on endpoints (CWE-306 — OWASP A07)

New route ships with no auth because "the frontend never calls it that way." Attackers call it directly.

**Spot:** route/handler/server-action with no auth middleware or session check; admin or internal routes guessable by name; API routes that assume the UI's nav guard is the security. **Fix:** deny by default — a shared `requireAuth` wrapper on everything, and public routes are the annotated exception.
→ `auth-access.md`

### 3. Trusting the client (CWE-602 / CWE-915 — OWASP A01/A04)

Permission checks, prices, roles, quotas, or feature gates enforced only in the browser; the server accepts whatever arrives.

```js
// ✗ client sends the price
await charge(req.body.amountCents);
// ✓ server derives it
const price = await priceFor(req.body.sku);
```

**Spot:** `if (user.isAdmin)` in frontend code with no server twin; amounts, roles, `isAdmin`, or `tier` read from the request body; plan limits enforced in the UI only. **Fix:** the server re-derives and re-checks everything that costs money or grants power.
→ `auth-access.md`, `secrets-config.md`

### 4. Injection: SQL / command / XSS / path (CWE-89, 78, 79, 22 — OWASP A03)

String-built queries and commands, unescaped HTML, user input in file paths.

```js
db.query(`SELECT * FROM users WHERE email = '${email}'`);  // ✗ SQLi
db.query('SELECT * FROM users WHERE email = $1', [email]); // ✓
element.innerHTML = comment;                                // ✗ XSS
element.textContent = comment;                              // ✓
fs.readFile(`/data/${req.query.name}`);                     // ✗ ../../etc/passwd
```

**Spot:** template strings or `+` around SQL, shell, HTML, or paths; `innerHTML`, `dangerouslySetInnerHTML`, `v-html`; `exec`/`eval` with dynamic input; ORM `raw`/`Unsafe`/`literal` APIs. **Fix:** parameterize, use `textContent`, pass argv arrays not shell strings, allow-list + `path.basename` for file names.
→ `injection.md`

### 5. Insecure database / BaaS rules (CWE-732 / CWE-284 — OWASP A01/A05)

Supabase table with RLS off; Firebase rules `allow read, write: if true`. The anon key is public by design — so the rules *are* the security, and they're open.

**Spot:** RLS disabled on a table with real data; any policy that resolves to `true` or merely `auth.uid() IS NOT NULL` for broad operations; a service-role key used from the client. **Fix:** RLS on with `FORCE`, deny-by-default policies scoped to `auth.uid()` (with `WITH CHECK`), service keys server-side only.
→ `auth-access.md`

### 6. Leaked secrets (CWE-798 — OWASP A02/A07)

API keys hardcoded in source, `.env` committed, keys inlined into the client bundle via `NEXT_PUBLIC_…` / `VITE_…`, secrets echoed in error responses or logs.

**Spot:** high-entropy strings in source; `.env*` tracked by git; server keys under a client-exposed env prefix; tokens in log lines. **Fix:** env only, server only, rotate anything that ever shipped, pre-commit secret scanning.
→ `secrets-config.md`

### 7. SSRF — server fetches a user-supplied URL (CWE-918 — OWASP A10)

Webhook testers, link previews, image proxies, "import from URL." The server fetches attacker-chosen URLs and can be pointed at cloud metadata (`169.254.169.254`) or internal services.

**Spot:** `fetch`/`axios`/`requests` where the URL (or host) comes from the user, including indirect paths (URL stored in DB by a user). **Fix:** allow-list schemes and hosts, resolve DNS and block private/link-local ranges, disable redirects into them, cap response size.
→ `injection.md`

### 8. Weak authn/session crypto (CWE-327/330/916, CWE-384 — OWASP A02/A07)

`Math.random()` for tokens, MD5/SHA-1 for passwords, JWT `alg: none` or unsigned acceptance, plaintext password compare, sessions not rotated on login, predictable reset tokens, tokens in `localStorage`.

**Spot:** the functions above; `bcrypt` cost < 12; `===` on HMAC digests (timing); JWT verified without pinning the algorithm and issuer/audience. **Fix:** Argon2id/bcrypt ≥ 12, `crypto.randomUUID()`/`randomBytes` for tokens, `alg` allow-list, `HttpOnly`+`SameSite`+`Secure` cookies, constant-time compares, session rotation on privilege change.
→ `auth-access.md`, `secrets-config.md`

### 9. Unvalidated input / mass assignment / business-logic gaps (CWE-20, CWE-915 — OWASP A03/A04)

Whole request body spread onto a model update (users set `isAdmin: true`); missing schema validation; negative quantities; unchecked state transitions; missing rate limits on login and expensive AI calls (CWE-770, OWASP A04/A07).

**Spot:** `{...req.body}` into an update; schemas without `.strict()`; endpoints that spend money or call LLMs with no per-user cap. **Fix:** schema-validate at the boundary (Zod/Pydantic, strict), allow-list updatable fields, server-side rate limits keyed on user + IP, quotas on metered resources.
→ `injection.md`, `pre-deploy.md`

### 10. Missing headers, misconfigured CORS, verbose errors (CWE-16 / CWE-209 — OWASP A05)

No CSP/HSTS; `Access-Control-Allow-Origin: *` with credentials; stack traces and raw driver errors returned to clients; PII in logs.

**Spot:** response headers absent; `cors({ origin: '*', credentials: true })`; `catch (e) { res.json(e) }`. **Fix:** helmet-style headers, CSP that actually blocks inline where feasible, CORS allow-list of exact origins, generic client errors with server-side structured logging of the detail.
→ `secrets-config.md`, `pre-deploy.md`

---

## Honorable mentions (check when the surface exists)

- **Webhook signature skipped** (Stripe/GitHub) — replay and forged events (CWE-347).
- **File upload trust** — content-type from the client believed, uploads served from the app origin, no size cap (CWE-434).
- **Open redirects** — `redirect(req.query.next)` (CWE-601).
- **LLM integration abuse** — exposed provider keys, no usage caps, prompt injection flowing into rendered output or tool calls (OWASP LLM Top 10 alignment).
- **Dependency risk** — unpinned versions, typosquats, install-scripts running in CI (OWASP A06).
- **GraphQL** — unbounded depth/batching, unauthenticated resolvers.
- **Race conditions** — double-submit on checkout/claim flows; TOCTOU on limits.

Use the OWASP Top 10:2021 category names (A01–A10) in user-facing reports, plus the CWE anchor when precision helps; when a finding fits none cleanly, say the concrete class instead of forcing a bucket.
