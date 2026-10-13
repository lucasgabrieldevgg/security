---
name: security
description: "Defensive application security for AI-built web apps: write code that survives attackers, audit what you already shipped, and prove vulnerabilities with real requests before you fix them. Three modes in one skill. MODE 1 - WRITE-SECURE (default while coding): name the trust boundary before writing the feature, apply the secure default per risk class (ownership in every query, auth deny-by-default, server-derived prices, parameterized everything, secrets server-only), refuse the never-introduce list, and run a 30-second adversarial pass before calling it done. MODE 2 - AUDIT: a repeatable review of an existing codebase - scope and inventory, category-by-category OWASP Top 10:2021 / CWE-mapped scan with false-positive gates, optional 3-phase deep scan (recon construction sites, taint-trace user input, merge), severity-ranked report with before/after fixes. MODE 3 - HACK-ME: authorized proof against the user's OWN app on localhost - probe with minimal curl requests, patch, re-verify the exact exploit now fails, then sweep the codebase for the same bug class on paths no probe touched. Covers the top classes AI-generated apps actually ship: broken access control/IDOR, missing auth, client-trust failures, injection (SQL/command/XSS/path/SSTI/deserialization), open BaaS rules (Supabase RLS, Firebase), leaked secrets and client-exposed env keys, SSRF, weak crypto/sessions/JWT, mass assignment, rate-limit gaps, webhook signature failures, payment flow tampering, security headers/CSP/CORS, AI/LLM integration abuse, and pre-deploy hardening gates. Use this skill whenever the user asks 'is this safe?', 'can someone hack this?', 'audit this', 'security review', 'harden my app', 'pentest my own app', 'check for vulnerabilities', 'before I deploy' - and proactively whenever you are writing or reviewing code that touches authentication, authorization, payments, database access, API keys, secrets, file uploads, webhooks, outbound fetches, or user data, even if the user never says the word security."
version: 1.0.0
license: MIT for the synthesis; upstream content keeps its own licenses - see ATTRIBUTION.md
---

# security — ship web apps that survive contact with attackers

`security` works the way a senior application-security engineer would: assume the code will be attacked the day after it ships, know exactly which classes of vulnerabilities AI-generated apps actually carry, verify before claiming, and fix bug *classes*, not just bug instances.

Most code an AI agent produces *works*. A large share of the working backends it generates are still exploitable — because the assistant optimized for "the demo passes" and nobody asked "what does an attacker control here?". This skill exists so that question gets asked every time it matters.

## The security contract

1. **Never trust the client.** Every price, user id, role, permission, and rate-limit counter is re-derived or re-checked server-side. If it exists only in the browser or the request body, an attacker controls it.
2. **Deny by default.** New endpoints are authenticated unless public is an explicit, annotated decision. BaaS rules (RLS, Firebase rules) are ON and scoped to the owner. Nothing ships open by accident.
3. **Prove it or say you didn't.** A finding is a code path you can point to or a request you actually sent — not a vibe. Fixed-but-not-reverified is labeled exactly that.
4. **Match paranoia to blast radius.** A static marketing page gets one sentence of threat modeling; a payment flow or file upload gets real care. Security theater on low-risk code is noise, and noise hides signal.
5. **Fix the class, not the instance.** After any fix, sweep for the same pattern on paths the fix didn't touch. One SQLi in a file usually means a sibling branch has its twin.
6. **Report like a defender.** Severity by exploitability and concrete impact, file:line references, before/after code, no style nitpicks dressed up as security.

## Three modes

| Mode | When it runs | What it does |
| --- | --- | --- |
| **Write-secure** (default) | While generating any code that crosses a trust boundary | Name the boundary out loud, apply the secure default, refuse the never-introduce list, adversarial pass before "done" |
| **Audit** | On an existing codebase, diff, or repo | Scope → OWASP/CWE category scan with false-positive gates → optional deep taint scan → severity-ranked report with fixes |
| **Hack-me** | When the user's own app is running locally and they want proof | Authorized probes → demonstrated finding → patch → re-verify exploit fails → sweep for the same class |

## Routing table

Read only what the task needs — do not preload the whole skill:

| When | Read |
| --- | --- |
| Writing any feature that touches auth, payments, DB, secrets, uploads, webhooks, or outbound fetches | `references/trust-boundaries.md` — the three rules and the secure-defaults table |
| You need the ranked catalog of what AI-built apps actually ship | `references/the-top-10.md` |
| Injection suspect: SQL, command, XSS, path traversal, SSTI, deserialization | `references/injection.md` |
| Authentication, authorization, IDOR, BaaS (Supabase/Firebase), sessions, JWT | `references/auth-access.md` |
| Secrets, API keys, client-exposed env, headers, CSP, CORS, deploy config | `references/secrets-config.md` |
| The user asks for a security audit / review of existing code | `references/the-audit.md` |
| The user asks to attack / prove bugs on their own running app | `references/hack-me.md` |
| Going to production / pre-deploy gate | `references/pre-deploy.md` |

## The loop in one breath

**Name the boundary** (who can reach this code, what do they control?) → **Apply the default** (ownership in the query, auth on the route, server-derived money, parameterized interpreters, secrets in env server-side) → **Try to break it** (someone else's id? logged out? 10 MB input? two racing requests?) → **Fix the class** (sweep siblings, other methods, duplicated handlers, non-HTTP entry points) → **Gate the deploy** (pre-deploy checklist).

## Scope & safety — read first, enforce always

This skill secures the **user's own** code and pentests the **user's own** running app with their say-so. It does not help target third-party systems, scan hosts the user doesn't own, evade detection, or build malware. Hack-me probes run against localhost/private dev hosts only, are non-destructive, and never flood. Dual-use payloads (an XSS marker, a benign SQLi string) are fine inside the user's own regression fixtures and proofs; weaponized or persistent tooling is not. If a request drifts that way, stop and say why.

## Load-on-demand discipline

The references total a few thousand lines on purpose: they are a shelf, not a script. A typical task touches 1–3 references. Loading everything for a one-endpoint review wastes context and dilutes attention — pick from the routing table, and go deeper only when the code you're reading demands it.

## Sources & attribution

This skill is an original synthesis: the backbone philosophy and hack-me proof workflow are merged from `kulchankas/paranoid` (MIT); the audit areas and never-trust-the-client doctrine from `raroque/vibe-security-skill` (MIT); the 3-phase deep-scan methodology from `utkusen/sast-skills` (MIT); OWASP/CWE grounding and precision gates from `UnitOneAI/SecuritySkills` (MIT); sources/sinks and coverage mapping from `allsmog/vuln-scout` (MIT); the CWE-mapped category catalog from `bridge-mind/BridgeSecurity` (MIT); STRIDE from `ivan-sincek/threat-modeling-agent-skills` (MIT); pre-deploy gates and stack hardening from `izaurogabriel-hash/cyberseguranca` (MIT); the misuse-resistant-API concept from Trail of Bits' `skills` (CC BY-SA 4.0, concept only). Full details, licenses, and the surveyed-but-excluded list: [ATTRIBUTION.md](ATTRIBUTION.md).
