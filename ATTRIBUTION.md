# Attribution & Sources

`security` is an original synthesis commissioned for this repo: the defensive philosophy, the three-mode architecture (write-secure / audit / hack-me), the ranked top-10 taxonomy, and all wording are original merges. Upstream material retains its original license; the synthesis itself is MIT. Every license below was read directly from the upstream repo's LICENSE file on 2026-10-13.

## Upstream skills (merged)

| Source | What was merged | License |
| --- | --- | --- |
| `kulchankas/paranoid` | The backbone: "review every line as if a bored attacker reads it tomorrow", the three rules (name the trust boundary → secure defaults per risk class → try to break it before done), the secure-defaults table, the hard never-introduce list, the 30-second adversarial pass, the /hack-me proof workflow with its scope rules and the "same pattern, fixed, not separately proven" honesty standard, the sweep-for-the-class step, the scope & safety doctrine | MIT |
| `raroque/vibe-security-skill` (by Chris Raroque) | "Never trust the client" as the core principle, the audit-area decomposition (secrets/env, database access control, authn/authz, rate limiting, payments, AI/LLM integration, deployment, data access), load-only-relevant-references discipline, the severity-ranked output format with before/after fixes, proactive consultation while generating, the Supabase RLS knowledge (enable-every-table loop, dangerous `USING (true)` policies, `WITH CHECK`, sensitive-fields problem, service_role exposure) | MIT |
| `utkusen/sast-skills` | The 3-phase deep-scan methodology (structural recon of dangerous construction sites → batched taint-tracing of user input to each site → merged report), the is/is-not discipline per vulnerability class, the four-way classification (Vulnerable / Likely / Not / Needs-manual-review), "false negatives are worse than false positives", per-stack vulnerable-vs-secure patterns | MIT |
| `UnitOneAI/SecuritySkills` | OWASP Top 10:2021 operationalization with CWE anchors, the precision gate (confirmed code path, reachability, context-read of 10–20 lines, one finding per distinct bug, severity proportional to impact), ASVS/CWE-Top-25 grounding of the review process | MIT |
| `allsmog/vuln-scout` | The sources/sinks dataflow model, the OWASP coverage-mapping discipline (use official category names in reports; CWE + concrete class when no bucket fits) | MIT |
| `bridge-mind/BridgeSecurity` (by bridgemind) | The CWE-mapped category catalog structure (injection, access control, crypto, SSRF, path, deserialization, XSS, auth/session, secrets, cloud/container misconfig), JWT/session/crypto spot-checks (alg pinning, weak hashes, `===` on HMACs, `rejectUnauthorized: false`) | MIT |
| `ivan-sincek/threat-modeling-agent-skills` (by Ivan Sincek) | The STRIDE threat-modeling structure (decompose into trust boundaries/components/data flows, then the six categories with their security-control answers) | MIT |
| `izaurogabriel-hash/cyberseguranca` | The pre-deploy gate checklist structure (release-blocking semantics, RLS-test item, secret-scan item, header/cookie/CORS gates), stack-specific hardening orientation (Supabase provider posture, wrangler-style config checks); content translated and adapted to English | MIT |

## Concept inspiration (pointed, no text merged)

| Source | What was taken | License |
| --- | --- | --- |
| `trailofbits/skills` — sharp-edges | The misuse-resistant-API design concept ("pit of success": if the easy path and the safe path diverge, developers take the easy one; make safe usage the path of least resistance). Concept only — no text, tables, or examples copied, to keep this repo's MIT synthesis free of CC share-alike obligations. Read their original skill for the full treatment. | CC BY-SA 4.0 |

## Standards referenced

- **OWASP Top 10:2021** — category names (A01–A10) used for report alignment; © OWASP Foundation, CC BY-SA 4.0; identifiers and category names referenced, no creative content reproduced.
- **CWE** (Common Weakness Enumeration, CWE-79/89/22/78/287/639/798/798/915/918…) — MITRE identifiers referenced for precision.
- **STRIDE** — the public threat-classification framework originated at Microsoft; used via the `ivan-sincek` skill above.

## Surveyed and excluded (13 candidate repos cloned and studied, 2026-10-13)

- `mukul975/Anthropic-Cybersecurity-Skills` (Apache-2.0) — 817 structured skills for SOC/blue/red teams mapped to MITRE ATT&CK, NIST CSF, ATLAS, D3FEND. Impressive corpus, but its center of gravity is detection engineering, DFIR, and cloud/IAM ops — not hardening AI-built web apps. No content merged.
- `SnailSploit/Claude-Red` (MIT) — offensive-security skill library. Out of this skill's defensive scope by design.
- `zhaoxuya520/reverse-skill` (MIT) — reverse-engineering/authorized-pentest router pack; offensive focus, excluded.
- `mukul975/Threatswarm` (MIT) — full pentest kill-chain agent framework; offensive, excluded.
- `Security-Phoenix-demo/security-skills-claude-code` (MIT) — pipeline/plugin collection; its 0day-scanner's diff-scoped review modes (light/standard/deep) are a good idea, but MCP-dependent and not merged.
- `eth0izzle/security-skills` (MIT) — CrowdStrike Falcon Fusion SOAR workflow builders; security-teams tooling, not appsec knowledge for the code you're writing.
- `dweinstein/mobile-security-skills` (no LICENSE file) — mobile appsec testing skills; out of web-app scope and license-unverified, so nothing merged.
- `hardw00t/ai-security-arsenal` (no LICENSE file) — skills/agents/commands for security researchers; license-unverified, nothing merged.
- `Pantheon-Security/medusa` (AGPL-3.0) — AI-first security scanner incl. Claude Code compromise detection; copyleft makes merging untenable here. Usable as an external tool on your own machine.
- `NVIDIA/SkillSpector` (Apache-2.0), `Tencent/AI-Infra-Guard` (Apache-2.0), `highflame-ai/ramparts` (Apache-2.0), `gl0di/clawseccheck` (MIT) — scanners for the *agent toolchain itself* (skills/MCP servers). Adjacent domain: they audit the tools you install, while this skill audits the app you build. Pointed as complementary, not merged.
- `affaan-m/ECC` (MIT) — agent-harness performance system; its security module is not a security skill in this sense. Not merged.

## Verification work (original to this repo)

- **Landscape survey:** 12 GitHub API queries across security-skill phrasing, 79 unique repositories ranked, 13 cloned and studied in full before synthesis (2026-10-13). Exclusion decisions above.
- **License verification:** every merged/pointed source's LICENSE file read directly from the clone — 11 MIT, 1 Apache-2.0 (surveyed), 1 CC BY-SA 4.0 (concept only), plus the no-LICENSE cases documented as such.
- **The synthesis itself:** the three-mode architecture, the security contract, the routing table, all reference-file structure, the top-10 ranking as merged-and-reordered here, the pre-deploy gate as adapted, and every code example written fresh for this repo (standard secure-coding patterns; any resemblance to upstream examples is the nature of the fixes, not copying).

## Individual credits

- **kulchankas** — paranoid is the philosophical backbone of this skill; its "prove it with a request" honesty standard shaped everything.
- **Chris Raroque** — vibe-security-skill mapped exactly what AI assistants get wrong and supplied the audit skeleton and BaaS knowledge.
- **Utku Sen** — sast-skills supplied the recon/taint/merge methodology that makes audits verifiable instead of vibes.
- **unitoneai** (UnitOneAI) — the standards grounding (OWASP/CWE/ASVS) and the false-positive discipline.
- **allsmog** — the sources/sinks mental model and coverage mapping.
- **bridgemind** (bridge-mind) — the CWE-mapped category catalog.
- **Ivan Sincek** — clean, framework-faithful STRIDE skills.
- **izaurogabriel** (izaurogabriel-hash) — the PT-BR cyberseguranca skill; its release-gate checklist discipline survives here in English, and its LGPD awareness is why the pre-deploy gate mentions regulatory layers.
- **Trail of Bits** — for publishing sharp-edges and the sharp-edges way of thinking about API design; go read the original.

Any errors in the merged synthesis are this repo's, not theirs.
