# Auth & access — IDOR, BaaS rules, sessions, JWT, mass assignment

Broken access control is the #1 class in AI-built apps (OWASP A01, and classes 1–3 of the top-10). This file is the deep treatment: object-level authorization, BaaS (Supabase/Firebase) specifically, session and token hygiene, and mass assignment.

> Upstream credit: BaaS/RLS knowledge merged from `raroque/vibe-security-skill` (MIT); ownership-in-query and deny-by-default doctrine from `kulchankas/paranoid` (MIT); JWT/session checks from `bridge-mind/BridgeSecurity` (MIT); provider guidance adapted from `izaurogabriel-hash/cyberseguranca` (MIT). See `/ATTRIBUTION.md`.

---

## Object-level authorization (the IDOR discipline)

Rule: **every query keyed on a client-supplied id includes the caller's scope in the `where`.** Authentication ("logged in") is not authorization ("this row is yours").

```javascript
// Next.js / any ORM — the pattern generalizes
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  const inv = await db.invoice.findFirst({
    where: { id: req.params.id, userId: req.user.id },
  });
  if (!inv) return res.sendStatus(404);
  res.json(inv);
});
```

- Return `404`, not `403` — a `403` confirms the id exists, which is itself information.
- Same rule for `PATCH`/`DELETE` — the classic leak is ownership checked on `GET` and forgotten on write paths.
- Admin routes get **role checks in the handler or middleware**, never a UI nav guard; role comes from the server-side session/token, never from a header or body field the client sets.
- Multi-tenant: every query carries the tenant scope (`where: { id, tenantId: req.tenant.id }`), and the tenant id comes from the authenticated principal, not the request.

## Route-level authentication: deny by default

- A shared `requireAuth` middleware wraps **everything**; public routes are an explicit, annotated exception (`// PUBLIC: pricing data, no user context`).
- Server Actions and API routes in Next.js / Remix-style frameworks need an `auth()` call **in the action** — a page-level check does nothing when the action is POSTed directly.
- Admin/internal routes: unguessable names are not access control. Check the role server-side.

## Supabase (PostgREST + RLS)

The anon key is public by design — **RLS is the security**. Tables created via SQL editor or migrations have RLS **disabled by default**; a table without RLS is fully readable and writable by anyone holding the anon key.

Enable on every table (run in migrations; the loop catches tables added later):

```sql
DO $$ DECLARE r RECORD;
BEGIN
  FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public'
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY;', r.tablename);
  END LOOP;
END $$;
```

**Dangerous policies** (equivalent to no RLS for the authenticated role):

```sql
-- ✗ any logged-in user reads/writes every row
CREATE POLICY "all" ON documents FOR SELECT TO authenticated USING (true);
-- ✗ same thing, disguised
CREATE POLICY "logged" ON documents FOR SELECT TO authenticated USING (auth.uid() IS NOT NULL);

-- ✓ owner-scoped
CREATE POLICY "own_select" ON documents FOR SELECT TO authenticated
  USING ((SELECT auth.uid()) = user_id);
```

**`WITH CHECK` on INSERT/UPDATE** — without it, users reassign ownership:

```sql
-- ✓ prevents UPDATE user_id to someone else / inserting rows as another user
CREATE POLICY "own_update" ON documents FOR UPDATE TO authenticated
  USING  ((SELECT auth.uid()) = user_id)
  WITH CHECK ((SELECT auth.uid()) = user_id);
```

**Privileged fields** (a `profiles` row a user can UPDATE must not let them set `is_admin`, `credits`, `tier`):

- Column-level privileges, or
- Move sensitive fields to a non-exposed schema behind `SECURITY DEFINER` functions, or
- A trigger that pins protected columns to their old values on user-role updates.

**Keys:** `anon` client-side; `service_role` server-side only — it bypasses all RLS. If it ever appeared in client code, rotate it.

**Service-role code paths** (cron, admin jobs) still check the caller's authorization at the function level — RLS doesn't apply to them, so discipline must.

## Firebase

- Firestore rules `allow read, write: if true` on real data is an open database — same class as RLS-off.
- Scope rules to the request auth: `request.auth != null && request.auth.uid == resource.data.ownerId`; on `create`, `request.resource.data.ownerId == request.auth.uid`.
- Storage rules count too: default wide-open buckets serve any file to anyone who can guess a path.
- Admin SDK (service account) bypasses rules — server-side only, same discipline as `service_role`.

## Sessions, JWT, tokens

- **Cookies over localStorage** for session tokens: `HttpOnly` + `SameSite=Lax` (or `Strict`) + `Secure` + `__Host-`/`__Secure-` prefixes.
- Rotate the session id on login and on privilege change (fixation, CWE-384); invalidate on logout server-side, not just by deleting the cookie.
- JWT: pin the algorithm server-side (reject `alg: none`; HS256/RS256 confusion), verify `iss`/`aud`/`exp`, and put the **role inside the verified token or a server-side lookup** — never trust a client-supplied role header/claim echo.
- Reset/password tokens: `randomBytes(32)`-class randomness, single-use, short expiry, hashed at rest if stored; never `Math.random()` (CWE-330/338).
- Passwords: Argon2id or bcrypt cost ≥ 12; reject on breach lists where possible; compare with the library's verify (constant-time), never `===` on digests.
- Rate-limit login, reset, and MFA endpoints (see `pre-deploy.md`), and use generic failure messages ("invalid credentials") so the response can't enumerate accounts.

## Mass assignment (CWE-915)

Never spread a request body onto a record:

```javascript
// ✗ POST /api/profile { "isAdmin": true }
await db.user.update({ where: { id }, data: req.body });
// ✓ explicit allow-list
const { name, avatarUrl } = profileSchema.parse(req.body); // .strict() rejects extras
await db.user.update({ where: { id: req.user.id }, data: { name, avatarUrl } });
```

Validate at the boundary with a **strict** schema (Zod `.strict()`, Pydantic `extra='forbid'`), then pass only named fields. The same discipline applies to query filters built from user input — allow-list which fields can be filtered/sorted.

## Payments (client-trust, the money version)

- Prices, plans, quantities verified **server-side**: look up the stored `priceId`/plan row; never accept `amountCents` from the request.
- Webhooks: verify the provider signature **before** parsing/trusting the body (Stripe `constructEvent` with raw body, tolerance window); make handlers idempotent (replays are normal).
- Subscription/entitlement state read from the provider or a server-owned table — never from a client claim like `plan: 'pro'`.
- Race-safe checkout: one in-flight session per cart; re-check stock/limits at fulfillment time, not only at session creation.

## What an audit of this surface checks, in order

1. Every route/handler/server-action: is there an auth check **in** it? (class 2)
2. Every object read/write by id: is the caller's scope in the query? (class 1)
3. BaaS: RLS/rules on every table/collection, no `true` policies, service keys server-side. (class 5)
4. Writes: allow-listed fields, strict schemas. (mass assignment)
5. Sessions/tokens: cookie flags, rotation, JWT pinning, token randomness, login rate limits. (class 8)
6. Money: server-derived prices, signature-verified webhooks, idempotency. (class 3)
