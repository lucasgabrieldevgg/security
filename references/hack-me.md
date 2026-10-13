# Hack-me — proving vulnerabilities against your own running app

The audit *tells* the user their code has an IDOR; hack-me *shows* it, against their own app on localhost, then patches it and shows the exploit dying. Findings backed by a request the user can re-run themselves are a different currency from findings backed by reasoning.

> Upstream credit: the complete probe → patch → re-verify → sweep workflow, scope rules, and the "fixed, not separately proven" honesty standard are merged from `kulchankas/paranoid`'s `/hack-me` command (MIT). See `/ATTRIBUTION.md`.

---

## Scope — read first, enforce always

- **Target must be local:** `localhost`, `127.0.0.1`, `::1`, or a `*.localhost` / private dev host the user names. If a target resolves to a public IP or a domain the user doesn't own — **stop and say why**.
- **Non-destructive proofs only:** prove a read bug by reading one record that shouldn't be readable; prove a write bug by writing a throwaway/seeded record. Never delete data, never mass-mutate, never exfiltrate real user data; redact anything sensitive surfaced as proof.
- **No DoS:** demonstrate a missing rate limit with a small bounded burst (~20 requests) and describe the risk — never actually flood.
- **Authorized testing of the user's own code.** Not for third-party systems, detection evasion, or persistent tooling. If the request drifts there, decline.

Say the scope back to the user and get a "go" before the first request.

## Workflow

### 1. Map

Find the app's routes/handlers and how it runs (framework, port, start command, seed/test users). Ask the user for the base URL and, if useful, two test accounts (attacker + victim) — local dev logins, never real credentials. Where routes and auth live per stack (Next.js, FastAPI, Express, Django, Rails, Flask, Spring Boot, Laravel, Phoenix, Go, NestJS, ASP.NET Core): the framework's router/middleware directory — locate the auth wrapper and the entry-point list before probing anything.

### 2. Prioritize

Pick the classes from `the-top-10.md` this app is actually exposed to, ordered by likelihood × impact. Broken access control and missing auth first — most common, and the easiest to prove.

### 3. Probe, one class at a time

Craft the **minimal request that succeeds only if the bug exists**. `curl` against localhost; show the actual request and (redacted) response so it's undeniable:

- **IDOR:** log in as user A, request user B's object id → B's data back = real.
- **Missing auth:** call the endpoint with no session/token → data back = real.
- **Client trust:** replay the request with `amount` / `role` / `isAdmin` edited → server honors it = real.
- **Injection:** one benign marker on a *seeded* row (`' OR '1'='1`, `<b>xss</b>` reflected) — enough to show the sink, never a destructive payload.
- **SSRF:** point a user-URL field at `http://127.0.0.1:<internal>` or a metadata IP → it fetches = real.
- **Rate limit:** a bounded burst, then the gap measurement; describe, don't demolish.

### 4. Report each finding

What you sent, what came back (redacted), why it's a vulnerability, which top-10 class it is. Lead with the scariest confirmed finding — concrete, not alarmist.

### 5. Patch

Apply the fix from the matching reference (`auth-access.md`, `injection.md`, `secrets-config.md`…). Keep the diff small; explain it.

### 6. Re-verify

Re-run the **exact same probe** and show it now failing (`401`/`403`/`404`/validation error). A finding isn't closed until the original exploit fails.

### 7. Sweep for the same bug elsewhere

The step everyone skips, and where fixes leak. A passing re-verify proves *the request you sent* is dead — not that the class is gone. Search the code for the same pattern on paths no probe touched:

- Sibling branches in the same function (second DB backend, second content type, an `if/else` building the same query twice)
- The same resource under a different method (ownership checked on GET, forgotten on DELETE)
- Duplicated handlers (`/api/v1` and `/api/v2`, admin and public copies)
- Non-HTTP entry points (CLI, cron, queue consumers, webhooks) reaching the same sink while bypassing the route's auth

Fix what the sweep finds. Then be precise about evidence: a path fixed but not reachable by a probe is **"same pattern, fixed, not separately proven"** — never report it as verified. That distinction is the whole point of this workflow.

### 8. Summarize

A short table — finding · class · severity · status (`proven & closed` / `same pattern fixed, not separately proven` / `needs-owner-decision`) — plus anything you couldn't safely test locally.

## Output style

Lead with the scariest confirmed finding, with its request/response. Be concrete, not alarmist — every claim is backed by a request the user can re-run themselves.
