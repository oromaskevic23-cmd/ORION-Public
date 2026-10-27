# IMPERIAL Core — Enterprise Engineering Gate (2026-10-27)

**Status:** Governance baseline proposed for review. This document does NOT certify Enterprise readiness, security, runtime availability or CI PASS.

## Required release controls
1. Protect the default branch; require peer-reviewed pull requests and passing repository-specific CI.
2. Define CODEOWNERS and minimum reviewer independence; owner approval is required for privileged deployment, payments and publication.
3. Use least-privilege GitHub Actions permissions; pin third-party actions to full commit SHAs and disable persisted checkout credentials.
4. Run dependency, secret and static security scans; remediate verified findings without disclosing secrets.
5. Record test commands, reproducible build artifacts, commit SHA, hashes and a signed or independently verified release evidence package.
6. Enforce Zero Trust: agent identity is not authority, capability is not owner approval, and execution is denied by default.
7. Document runtime boundaries, data retention, incident response, backup/recovery, and rollback.
8. Protect private code, credentials, customer data and unreleased IP; do not copy them into public repositories.
9. Use FREE_ONLY infrastructure until explicit owner approval; do not enable billing, publication or privileged operations.
10. Require product-specific functional, integration and security tests before marking any capability IMPLEMENTED.

## Acceptance
- `SPECIFIED`: control documented, not enforced.
- `IMPLEMENTED`: code/config exists and is reviewable.
- `TESTED`: passing tests and logs verified at a precise commit.
- `RELEASED`: independently approved deployment evidence exists.

**Current status: SPECIFIED ONLY.** Follow-up engineering must implement controls separately for this repository. This file does not alter settings, grant agent permissions, or assert Enterprise certification.
