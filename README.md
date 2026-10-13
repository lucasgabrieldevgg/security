# security

A big skill for **defensive application security** — the kind AI-built web apps actually need. Born from merging the best security skills found on GitHub (the vibe-coded-app auditors, the SAST skill packs, the OWASP-grounded reviewers, and the "hack your own app" provers) into one discipline: write secure by default, audit with precision, prove with real requests.

```
Most code an AI agent produces works. A large share of the working
backends it generates are still exploitable — because nobody asked
"what does an attacker control here?" This skill asks it every time.
```

## What's inside

| Piece | What it does |
| --- | --- |
| **The security contract** (`SKILL.md`) | Six rules: never trust the client, deny by default, prove it or say you didn't, match paranoia to blast radius, fix the class not the instance, report like a defender |
| **Trust boundaries** (`references/trust-boundaries.md`) | The write-time brain: sources/sinks, the three rules, the secure-defaults table per risk class, the never-introduce list, the 30-second adversarial pass, STRIDE when the blast radius justifies it |
| **The top 10** (`references/the-top-10.md`) | The vulnerability classes AI-built apps actually ship, ranked by real frequency — spot + fix pattern + CWE/OWASP anchor each |
| **Injection** (`references/injection.md`) | SQL/command/XSS/path/SSTI/deserialization/SSRF: what each IS and is NOT, per-stack fix patterns, the taint-tracing method |
| **Auth & access** (`references/auth-access.md`) | IDOR discipline, route deny-by-default, Supabase RLS deep-dive (dangerous policies, WITH CHECK, privileged fields), Firebase rules, sessions/JWT hygiene, mass assignment, payments |
| **Secrets & config** (`references/secrets-config.md`) | Client env prefixes, key hygiene and rotation, security headers, CSP, CORS, cookies, deploy configuration, AI/LLM integration specifics |
| **The audit** (`references/the-audit.md`) | The repeatable review: scope & inventory → category scan → precision gates (false-positive discipline) → optional 3-phase deep scan → severity-ranked report with before/after fixes |
| **Hack-me** (`references/hack-me.md`) | Proof workflow against your own localhost app: probe with minimal requests, patch, re-verify the exact exploit fails, sweep for the same class elsewhere |
| **Pre-deploy gate** (`references/pre-deploy.md`) | The release-blocking checklist: RLS tests, secret scans, auth checks, headers/CSP/CORS, webhook signatures, rate limits, observability |

Plus a Cursor rules export at `exports/security.mdc`.

## Install

**Claude Code / GLM / any SKILL.md host:**
```bash
git clone https://github.com/lucasgabrieldevgg/security.git ~/.claude/skills/security
```

**Cursor:** copy `exports/security.mdc` to `.cursor/rules/security.mdc`.

**ClawHub / skills.sh:** the folder is standard skill layout — publish as-is.

## The three modes (the center of mass)

**Write-secure** runs by default while coding: name the trust boundary before writing the feature, apply the secure default per risk class (ownership in every query, auth deny-by-default, server-derived prices, parameterized interpreters, secrets server-only), refuse the never-introduce list even when asked casually, and run a 30-second adversarial pass before calling it done. **Audit** reviews what already exists — category-by-category with OWASP/CWE grounding and hard false-positive gates, optional three-phase deep scan (recon dangerous construction sites, taint-trace user input, merge), severity-ranked with before/after fixes. **Hack-me** turns findings into proof against the user's own running localhost app — then patches, re-verifies the exact exploit now fails, and sweeps the codebase for the same bug class on paths no probe touched.

The references are a shelf, not a script: a typical task loads 1–3 of them. Loading everything for a one-endpoint review wastes context and dilutes attention.

## Scope & safety

This skill secures your own code and pentests your own running app with your say-so. It does not target third-party systems, evade detection, or build malware. That boundary is stated in the skill itself and enforced by its evals.

## Collection

Part of the skill collection: **theskill** (meta-router: craftsmanship, design, research…), **research**, **motion**, **video**, and this one — each a big skill built the same way: survey the ecosystem, merge the best, credit everything.

## Attribution

`security` is an original synthesis (MIT) merging upstream material from `kulchankas/paranoid` (MIT), `raroque/vibe-security-skill` (MIT), `utkusen/sast-skills` (MIT), `UnitOneAI/SecuritySkills` (MIT), `allsmog/vuln-scout` (MIT), `bridge-mind/BridgeSecurity` (MIT), `ivan-sincek/threat-modeling-agent-skills` (MIT), and `izaurogabriel-hash/cyberseguranca` (MIT), with concept inspiration from Trail of Bits' `skills` (CC BY-SA 4.0, concept only). 13 candidate repos were cloned and studied; 5 were merged, the rest are documented and credited in [`ATTRIBUTION.md`](ATTRIBUTION.md).

## License

MIT for this repo's original content. Upstream material retains its own licenses — see ATTRIBUTION.md.
