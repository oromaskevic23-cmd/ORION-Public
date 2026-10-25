# ORION — Federated Collective Intelligence Advisory Reference v0.1

**Owner and Final Architectural Decision Authority:** Alexander Romaskevich — RomaskevicH  
**Ecosystem:** IMPERIAL Core / independent ORION component  
**Classification:** PUBLIC, first-party synthetic source; no private project code copied here  
**Maturity:** E2 source and locally tested E3 reference. E4 federated integration, E5 runtime and E6 production **NOT VERIFIED**.

## Canonical boundary

ORION performs collective advisory analysis and contradiction visibility. It does **not** replace HANTER, ASTRA, VELEON or domain-specific orchestrators; it is **not** a global dispatcher and has no implicit privileged access.

Proposed *integration* (not running here):

\`Architect → HANTER → explicitly authorized domain orchestrator → Nano Core Agent → signed domain advisory → ORION (read-only report) → independent human review → external Approval Gateway/Audit Ledger where applicable\`.

Maintain Federated Multi-Orchestrator Architecture; AI Passport, Enterprise Skills, Guardian Core, Approval Gateway, ProofGraph and Audit Ledger are required at their respective trust boundaries. Identity ≠ Authority; Capability ≠ Approval; Reasoning ≠ Decision. The Public/Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary remain intact.

## Implemented code and scoped controls

- \`src/orion-advisory.mjs\`: Ed25519 public-key verification of advisory statements from 2–32 explicitly preconfigured domain identities. Each domain must use a distinct key; **key possession is not proof of an authorized human organization**.
- Strict allowlisted claims: mission ID, domain ID, NCA identity, claim key, \`FOR\`/\`AGAINST\`/\`UNSURE\`, 1–5 purported SHA-256 evidence digests, bounded summary, issue/expiry timestamps, nonce. A signed envelope confers no task or tool permissions.
- Bounded 5-minute validity; expiry/clock-skew validation, in-process anti-replay and duplicate submission rejection. Admission capped at 2–2048 records and audit capped at 4096 events per instance; limits default to 256/4096.
- \`report(mission)\` returns a deterministic hash-addressed advisory report with \`CONTRADICTION_NEEDS_REVIEW\`, \`INSUFFICIENT_INDEPENDENT_DOMAINS\`, or \`UNCONTESTED_SIGNED_SUBMISSIONS\`. Only positions **for the same exact claim ID** are compared. Raw text is never emitted; no semantic entailment or real-world evidence verification occurs.
- \`halt()\` stops admission; an in-memory hash-chained audit records generic accept/deny operations without raw external content.
- All reports assert \`truth_verified:false\`, \`human_review_required:true\`, \`execution:DENIED\`, \`task_dispatch:DENIED\`, \`approval:NOT_GRANTED\`, \`release:DENIED\`.

## Reproducible reference

Requires Node.js 22; no installation, credentials, network access, browser, third-party runtime or subscription.

\`\`\`bash
npm run verify
\`\`\`

This runs syntax checks, unit/adversarial tests and a synthetic two-domain contradiction example. Tests generate temporary Ed25519 keys inside the test process; no private owner signing key is bundled.

The signed claims schema is \`imperial_orion_advisory_v1\` with these exact fields:
\`schema\`, \`mission_id\`, \`domain_id\`, \`agent_id\`, \`claim_id\`, \`stance\`, \`evidence_sha256\`, \`summary\`, \`issued_at\`, \`expires_at\`, \`nonce\`. Timestamps are Unix milliseconds; \`signature\` is base64url Ed25519 over \`canonicalAdvisoryBytes(claims)\`. Never treat a sample or synthetic signed claim as a real owner permit.

## Security and completion blockers

1. Real trust provisioning, signer onboarding/rotation/revocation, external mission admission and Approval Gateway owner-approval provenance: **NOT INTEGRATED**. Unique keys do not prove organizational independence.
2. ProofGraph, Proof Passport, durable Audit Ledger, multi-host replay prevention and recovery after restart: **NOT IMPLEMENTED**. Current memory-only state is not an enterprise audit ledger.
3. Semantic reasoning, evidence integrity verification, counterfactual engines, inference by VELEON, real LLM calls and expert independent QA: **NOT VERIFIED**.
4. End-to-end integration with HANTER/LEGION/NCA runtime and lawful authorized external browsers/tools: **NOT VERIFIED**. There are no customer orders, no production decisions and no measured billion-agent capacity.
5. ORION does not autonomously execute tasks, pay out funds, modify wallets, assign NCA or approve release. This API must remain advisory-only.
6. Security tests are *scoped*. Real production hardening, signed releases, third-party security audit and independent authorization are still mandatory.

**Decision:** SOURCE / LOCAL TEST REFERENCE ONLY; production release **DENIED**. Preserve existing historical authorship. No third-party code or protected material is included; repository licensing requires owner decision.

**Build software. Verify everything.**
