# RANDAR Security Model

## 1. Security objective

RANDAR's security model is designed around:

1. controlled forensic execution;
2. reduced endpoint modification;
3. explicit capability boundaries;
4. authenticated API access;
5. tamper-evident bytecode;
6. protected report transfer;
7. evidence/report integrity metadata.

RANDAR is not designed to evade or disable security controls.

---

## 2. Trust boundaries

```text
Analyst
   │
   │ bearer token
   ▼
FastAPI
   │
   ├── JOCKY validation
   │
   ├── capability registries
   │
   ├── interpreter
   │
   └── report/storage
            │
            ▼
      endpoint evidence
```

The key security boundary is the transition from a JOCKY identifier to a registered implementation.

---

## 3. DSL isolation

JOCKY cannot directly invoke:

- Python;
- shell commands;
- PowerShell;
- arbitrary Windows APIs;
- arbitrary executables;
- arbitrary process manipulation.

A script can only reference registered collectors/rules and bounded language constructs.

---

## 4. Authentication

The API uses a bearer token.

Only the token's SHA-256 digest is stored in configuration.

Verification uses:

```text
provided token
     ↓
SHA-256
     ↓
constant-time comparison
     ↓
allow / deny
```

Server startup validates that authentication is configured before binding.

For production multi-user environments, this should evolve to a proper identity and authorization model.

---

## 5. Remote-agent authentication

Agents receive per-agent tokens.

The server stores the token digest, not the plaintext.

Agents can be:

- registered;
- monitored through heartbeat;
- revoked.

Jobs use:

- nonce;
- expiry;
- per-agent job identity;
- HMAC-derived job signature.

The current agent architecture is designed for controlled deployments rather than untrusted Internet exposure.

---

## 6. Signed bytecode

JOCKY bytecode is signed using HMAC-SHA256.

The signing key:

- is supplied at runtime;
- is not embedded in the bytecode;
- has a minimum configured length;
- is required for verification.

Verification checks the signature before parsing/executing the body.

This provides integrity against unauthorized modification by parties that do not possess the signing key.

It does **not** establish authorship or public verifiability by itself; HMAC is a shared-secret mechanism.

---

## 7. Report encryption

The current implementation uses:

- AES-256-GCM for report encryption;
- RSA public-key wrapping;
- OAEP with SHA-256;
- minimum 2048-bit RSA key size.

The report is authenticated by GCM.

The investigator private key is not stored by the server.

The current prototype stores the active public key only in process memory.

---

## 8. Evidence persistence and integrity

Each successful collector result can receive an SHA-256 evidence digest.

The report receives a SHA-256 report digest.

The report builder also assigns deterministic finding IDs based on rule, summary, evidence and index.

This gives investigators several integrity anchors:

```text
source script
     ↓ SHA-256
script identity

collector evidence
     ↓ SHA-256
evidence identity

final report
     ↓ SHA-256
report identity
```

These mechanisms support integrity verification but do not constitute a certified legal chain of custody.

---

## 9. Endpoint safety model

### Read-only design

The advanced Windows collectors do not:

- write process memory;
- suspend/resume threads;
- inject DLLs;
- create remote threads;
- execute collected PE files.

### Bounded design

Collectors use explicit limits for:

- process counts;
- thread counts;
- memory regions;
- module counts;
- PE files;
- imports/exports;
- event records;
- network evidence;
- collector runtime.

### Unsupported platforms

Windows-only collectors return explicit unsupported status on non-Windows systems.

They do not silently emulate Windows behavior.

---

## 10. Report language

Findings are intentionally written as indicators.

Example:

```text
Observed:
private executable memory + thread correlation

Not asserted:
"malware has been confirmed"
```

This distinction is a security and forensic-quality feature.

---

## 11. Deployment recommendations

For a controlled deployment:

- bind locally unless remote access is required;
- place remote deployments behind TLS;
- protect `.env`;
- rotate API tokens when needed;
- protect bytecode signing keys;
- use a dedicated investigator key pair;
- restrict endpoint privileges to the minimum required;
- maintain controlled Windows test hosts;
- back up the SQLite case database;
- avoid exposing the prototype directly to the public Internet.

---

## 12. Security review checklist

Before a release:

- [ ] All new collectors are registered explicitly.
- [ ] All new rules are registered explicitly.
- [ ] No new arbitrary command execution path exists.
- [ ] Windows telemetry remains read-only.
- [ ] Runtime bounds are preserved.
- [ ] Bytecode verification occurs before execution.
- [ ] API routes requiring authentication remain protected.
- [ ] Secrets are not logged.
- [ ] Report integrity remains deterministic.
- [ ] Unsupported-platform behavior is explicit.
- [ ] Regression tests cover the new boundary.

---

## 13. Prototype-to-production gaps

The following are recognized production hardening areas:

- centralized identity and RBAC;
- external key management;
- durable distributed job queue;
- stronger agent transport identity;
- immutable/WORM evidence storage;
- multi-operator case isolation;
- centralized telemetry retention;
- deployment signing and packaging;
- formal threat modeling;
- external security assessment.

These are engineering hardening directions, not claims about current functionality.
