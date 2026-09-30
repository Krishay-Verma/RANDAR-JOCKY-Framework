# RANDAR v3.0.0 Final

RANDAR v3.0.0 is the final integrated forensic release built from the V2.9 persistence-hardening baseline.

## Scope

- JOCKY v1.5 investigation DSL and signed bytecode/toolchain
- Transformation and reproducibility metadata
- Windows/Linux forensic collectors and network evidence
- Memory and driver forensic detection
- Persistence-forensics hardening and expanded Windows persistence coverage
- Deterministic finding IDs and collector evidence hashes
- Report integrity, coverage/elevation honesty, and forensic timeline
- Software/security-product context and kernel-component evidence
- Privacy-bounded clipboard metadata and browser history/cookie metadata

## Safety boundary

RANDAR is a read-only forensic and research platform. It does not implement security-control bypass, vulnerable-driver exploitation, kernel subversion, stealth injection, process hollowing, reflective injection, API unhooking, or covert transport/domain-fronting behavior. Those SIH26148 topics are represented as defensive detection/research boundaries in the documentation.

## Verification

- Regression tests: **165 passed, 0 failed**
- Python compilation: passed
- Release ZIP integrity: verified
- Frontend production Vite build: not claimed in this environment because dependency retrieval is unavailable.
