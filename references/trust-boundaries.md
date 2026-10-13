# Trust boundaries — the mental model

Everything in this skill reduces to one discipline: **know where the attacker's control ends, and never let it cross silently.** This file is the write-time brain: read it before writing any feature that touches auth, payments, database rows, secrets, uploads, webhooks, or outbound requests.

> Upstream credit: the three-rules structure and secure-defaults table are merged from `kulchankas/paranoid` (MIT); "never trust the client" from `raroque/vibe-security-skill` (MIT); STRIDE from `ivan-sincek/threat-modeling-agent-skills` (MIT); sources/sinks from `allsmog/vuln-scout` (MIT). See `/ATTRIBUTION.md`.

---

## Sources and sinks

Think in dataflow, not files.

- **Sources** — where attacker-controlled data enters: query params, path params, headers, cookies, request bodies, file uploads, webhook payloads, database reads (second-order), messages from a queue, even LLM output when the prompt includes user text.
- **Sinks** — where controlled data becomes dangerous: SQL/shell/HTML/path interpreters, `eval`-family calls, deserializers, template engines, outbound `fetch`, redirect targets, log lines, error responses.

A vulnerability is a path from a source to a sink with no effective guard between them. When you write code, you are either (a) creating such a path — so guard it — or (b) nowhere near one — so relax.

## The three rules, in order

### 1. Name the trust boundary before you write the feature

One sentence, out loud in the chat, before the first line of code:

> *"This endpoint takes a `postId` from the client. Anyone logged in can call it, so the query must check the post belongs to the caller before returning it."*

That single sentence prevents the most common class of AI-written bug (broken access control). If you cannot say who the caller is and what they can forge, stop and ask the user — do not guess.

Scale the sentence to the blast radius:

| Feature | Threat modeling budget |
| --- | --- |
| Static marketing page, public read-only content | One sentence, or none |
| CRUD on user-owned rows | One sentence + ownership in every query |
| Auth flows, payments, file uploads, webhooks, admin actions | A real pass: entry points, who reaches each, what they control, what an abuse looks like |
| Multi-tenant data, crypto, secrets handling | The above + read the matching reference in full |

### 2. Apply the secure default for each risk class you cross

| If the code… | Non-negotiable default |
| --- | --- |
| Reads/writes a record by client-supplied id | Ownership check **in the query** (`where: { id, userId: caller }`), not after; return `404` on miss, not `403` |
| Adds an API route / server action / handler | Authenticated and authorized by default; public is an explicit, annotated exception |
| Runs on a client the user controls (browser, mobile bundle) | Holds no secrets and enforces no security decisions; the server re-checks everything |
| Builds SQL, a shell command, HTML, or a file path | Never by string concatenation — parameterize, escape by context, or allow-list |
| Fetches a URL the user gave you | Treat as hostile: allow-list schemes/hosts, resolve DNS and block private + link-local ranges, no redirects into them (SSRF) |
| Uses Supabase / Firebase / any BaaS | Row-Level Security / rules ON, deny-by-default, scoped to `auth.uid()`; service keys never client-side |
| Receives a webhook (Stripe, GitHub, …) | Verify the signature **before** trusting the body |
| Accepts a request body into an update | Allow-list fields; never spread the whole body onto the record (mass assignment) |
| Handles secrets / config | Env only, never hardcoded, never returned to the client, never logged |
| Returns errors, sets CORS, or logs | Generic errors to clients, no PII in logs, CORS is an allow-list — never `*` together with credentials |
| Calls an LLM with user text in the prompt | Treat model output as untrusted input when rendered or executed (prompt injection) |
| Charges money | Amount derived server-side from a stored price/plan, never accepted from the request |

### 3. Try to break it before calling it done

A 30-second adversarial pass on anything that crossed a boundary — and say what you checked:

- What happens if I pass **someone else's id**? A **negative / huge / non-numeric** id?
- If I call this endpoint **logged out**? As a **different user**? **Ten times a second**?
- If the input is **10 MB**? Contains `../`, `<script>`, `'; DROP`, a `file://` or `169.254.169.254` URL?
- If **two requests race** (double-submit, double-charge, TOCTOU on a counter)?
- If the client **replays the request with `isAdmin: true` or `amount: 1` edited in**?

## The hard "never introduce" list

Refuse to write these even when asked casually — say why, offer the safe version:

- An auth/permission check that lives **only** in the frontend.
- `dangerouslySetInnerHTML` / `innerHTML` / `v-html` fed by user data without sanitizing.
- SQL built with template strings or `+` around anything dynamic.
- `eval`, `exec`, `child_process` with a string containing user input (pass argv arrays, not shell strings).
- A secret, private key, or admin token in code shipped to the browser — including `NEXT_PUBLIC_` / `VITE_` env exposure of server keys.
- A database rule of `allow read, write: if true` (or RLS disabled) on real data.
- Disabled TLS verification, or `Access-Control-Allow-Origin: *` combined with credentials.
- A webhook handler that reads the body before verifying the signature.
- A price, quota, or role taken from the request body.

## STRIDE — when the blast radius justifies a real model

For payment, multi-tenant, or admin surfaces, decompose first: components, entry points, data flows, identities/roles, existing controls. Then walk the six categories per component and write down plausible abuse cases, not generic fears:

| Category | Ask | Control that answers it |
| --- | --- | --- |
| **S**poofing | Can someone pretend to be a user/service? | Authentication |
| **T**ampering | Can data in transit/at rest be altered unnoticed? | Integrity (signatures, TLS, constraints) |
| **R**epudiation | Can an actor deny what they did? | Audit logging |
| **I**nformation Disclosure | Can someone read what isn't theirs? | Authorization + encryption |
| **D**enial of Service | Can cheap requests exhaust expensive resources? | Rate limits, caps, timeouts |
| **E**levation of Privilege | Can a normal user reach admin powers? | Server-side role checks |

Findings from this model feed the same fixing loop as everything else: name the path (source → sink), fix with the default from the table above, sweep for the class.

## Designing so the safe path is the easy path (sharp edges)

The cheapest security is an API where the wrong thing is hard to write. When you design a function boundary, prefer signatures that make misuse impossible:

- A `chargeUser(userId, planId)` that looks up the price is safer than `chargeUser(userId, amountCents)` — the dangerous argument cannot be supplied.
- A `safeFetch(url, { allowHosts })` wrapper beats scattering hand-rolled SSRF checks.
- A `requireAuth` / `requireOwnership` middleware composes; scattered `if (token)` blocks rot.
- Defaults matter more than options: if the library lets you pick `alg`, pin it where only you call it.

If the easy path and the safe path diverge, developers (and the AIs writing code for them) will take the easy one every time. Move them back together.
