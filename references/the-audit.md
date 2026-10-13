# The audit — reviewing existing code

The repeatable review of a codebase, directory, or diff for security defects. The output contract: **severity-ranked findings, each with file:line, the concrete attacker story, and a before/after fix — and nothing speculative.** A wrong finding costs the user trust in every right one after it, so this file spends as much effort *not* reporting as reporting.

> Upstream credit: audit-area structure and severity report format merged from `raroque/vibe-security-skill` (MIT); OWASP/CWE grounding and precision gates from `UnitOneAI/SecuritySkills` (MIT); the 3-phase deep-scan (recon → batched taint → merge) from `utkusen/sast-skills` (MIT); category catalog from `bridge-mind/BridgeSecurity` (MIT). See `/ATTRIBUTION.md`.

---

## Step 0 — Scope and inventory

Establish the boundary before reading code:

1. **What's under review?** A single file (deep), a directory (recurse, prioritize entry points), a PR/diff (changed lines + surrounding context only), or the whole repo (warn about runtime; suggest splitting).
2. **Stack fingerprint:** language, framework, ORM, auth library, BaaS, template engine, deploy target — this picks which patterns from `injection.md` / `auth-access.md` / `secrets-config.md` apply.
3. **Entry-point catalog:** routes, handlers, server actions, webhooks, cron/queue consumers, CLI commands. Non-HTTP entry points count — they bypass route middleware.
4. **Trust boundaries:** where user-controlled data enters (params, bodies, uploads, webhooks, LLM output) and where the dangerous sinks are.
5. **Dependency manifests:** `package.json` / lockfile / `requirements.txt` etc. — for a component-risk pass (outdated majors, known-vulnerable pins, typosquat smells).

## Step 1 — Category scan (the standard pass)

Walk the top-10 classes from `references/the-top-10.md` in rank order, grep + read for each. Skip categories with no surface present (no payments code → skip payments). For OWASP-aligned reporting, map findings to A01–A10 names + CWE anchors; when nothing fits cleanly, name the concrete class.

### The precision gate (apply to every candidate finding)

1. **Confirmed code path required.** Specific file, line, and vulnerable pattern — or it isn't a finding. "This library *could* be misused" is not a finding.
2. **Verify reachability.** Dead code, commented-out code, test fixtures, and disabled features with compensating controls are not findings.
3. **Distinguish risk from vulnerability.** A grep match is a lead, not a result — read 10–20 lines of context:
   - `Math.random()` driving a UI animation is not a crypto failure.
   - `innerHTML = '<b>hi</b>'` with a static literal is not XSS.
   - `req.params.id` through an ORM with an ownership `where` is not IDOR.
   - `exec('ls')` with a hardcoded string is not command injection.
4. **One finding per distinct bug.** Consolidate variants (the same injection in two branches) into one finding with all locations listed.
5. **Severity proportional to real impact.** Infrastructure observations without an exploitable path (missing header on a static page, absent tooling) are Informational or omitted — don't inflate.

### Severity rubric

| Severity | Means |
| --- | --- |
| **Critical** | Exposed secrets/service keys, auth bypass, RCE, full-database exposure, client-controlled money. Fix before anything else ships. |
| **High** | IDOR on sensitive data, injection with a real path, open BaaS rules on user data, SSRF into metadata. |
| **Medium** | Missing rate limits on sensitive endpoints, weak token practices, mass assignment on non-privileged fields, header gaps on dynamic pages. |
| **Low / Info** | Defense-in-depth gaps, hardening opportunities, hygiene items. |

## Step 2 — Deep scan (optional, for security-critical surfaces)

When the surface justifies it (payments, auth, multi-tenant, admin), run the three-phase method on the injection family and object access:

**Phase 1 — Recon (structural):** list every *dangerous construction site* — dynamically built SQL/shell/HTML/paths, raw/unsafe ORM calls, dynamic identifiers, `fetch` with variable URLs, reads by client id without caller scope. Output: a numbered site list with file, function, construction pattern, and the interpolated variable(s). Do not trace origins yet.

**Phase 2 — Verify (taint):** for each site, walk the dynamic variable back to its origin — direct input, indirect flow (helpers, class state, branches), second-order (DB reads → find the write site), or server-side constant. Check guards along the way (parameterization, allow-lists, real type constraints). Classify: **Vulnerable / Likely vulnerable / Not vulnerable / Needs manual review** — the last one when helpers are opaque; when torn between "not vulnerable" and "manual review", choose manual review: false negatives are worse than false positives.

**Phase 3 — Merge:** one consolidated report, findings grouped by classification, executive summary with counts. Delete intermediate files.

This is also where diff-scoped reviews live: for a PR, Phase 1 covers only the changed lines' constructions — but if a changed line *calls* a helper, trace the helper too (the vuln often lives one hop away from the diff).

## Step 3 — The report

Structure (skip empty severities; end with the summary):

```markdown
## Critical

**`lib/supabase.ts:3` — service_role key in the client bundle** (OWASP A05, CWE-798)
The service_role key bypasses all RLS. Anyone can read, modify, or delete every row.

```typescript
// Before
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_KEY!)
// After — anon key client-side; service_role stays server-side
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)
```

## High
…

## Summary (prioritized)
1. service_role exposed (Critical) — rotate now, move server-side
2. client-controlled price (High) — server-side lookup
```

Per finding: **file:line, the class + CWE/OWASP anchor, the attacker story in one concrete sentence (what they can actually do), before/after fix, and — if it's a class-level bug — the other locations the sweep found.** Report genuine issues only; style belongs to a code review, not a security audit. Flag Critical findings at the very top of the response — never buried under Medium hygiene notes.

## Step 4 — Fix-the-class sweep (after any fix)

A finding that gets fixed is a *request* that now fails — not proof the class is gone. Before closing:

- Sibling branches in the same function (second backend, second content type, the `if/else` that builds the same query twice)
- The same resource under other methods (ownership checked on GET, missing on PATCH/DELETE)
- Duplicated handlers (`/api/v1` vs `/api/v2`, admin vs public copies)
- Non-HTTP entry points reaching the same sink (CLI, cron, queue consumers, webhooks)
- Label anything you fixed but could not exercise: **"same pattern, fixed, not separately proven."**

## Scope & honesty notes

- Report what you checked **and** what you didn't (no payments module read? say so).
- If deployment details are unknown (is there a WAF? is the DB public?), state the assumption instead of inventing a topology.
- Tooling assists (`npm audit`, `semgrep`, `gitleaks`) are inputs, not verdicts — a clean `npm audit` says nothing about your IDORs.
