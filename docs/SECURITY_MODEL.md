# JOCKY Security Model

## 1. Security objective

JOCKY is designed to make forensic investigations **controlled, auditable, bounded and low-impact**.

It is not designed to defeat endpoint security products.

The phrase “without triggering security solutions” in the SIH problem statement is therefore addressed through minimizing invasive endpoint actions and using explicit forensic capabilities, not by disabling or evading security controls.

---

## 2. Trust boundaries

```text
                    Analyst Browser
                          │
                   Bearer token
                          │
                          ▼
                    JOCKY API
                    /         \
                   /           \
            local engine      agent API
                 │                 │
                 ▼                 ▼
             endpoint         remote endpoint
```

Important boundaries:

- Browser ↔ API
- API ↔ local execution engine
- API ↔ remote agent
- DSL ↔ registered capabilities
- Report encryption ↔ investigator private key

---

## 3. DSL isolation

The JOCKY DSL cannot directly execute arbitrary Python or operating-system commands.

Capability resolution is registry-based:

```text
collect X
   │
   ▼
collector registry
   │
   ├── known → execute registered function
   └── unknown → reject
```

The same pattern applies to analysis rules.

This provides a strong and easy-to-audit extension boundary.

---

## 4. Authentication

Protected API routes require a bearer token.

The token is hashed server-side rather than stored as plaintext configuration.

The frontend stores the active token in `sessionStorage`, so normal browser session termination removes it.

`/api/health` is intentionally public and returns only a liveness response.

---

## 5. Remote-agent authentication

Agents use per-agent tokens.

The server stores token digests and uses constant-time comparison for authentication.

Agents are restricted to their own job endpoints.

The agent does not receive a privileged arbitrary-command channel; it executes JOCKY scripts through the same language pipeline.

TLS verification is enabled by default.

Disabling TLS verification is explicitly treated as a development/test-only operation.

---

## 6. Signed bytecode

JOCKY bytecode uses HMAC-SHA256 with a local signing key.

Before execution:

1. signature is verified;
2. wire-format/header checks are performed;
3. the representation is reconstructed into IR;
4. the ordinary interpreter executes it.

The bytecode path therefore inherits the source-language capability boundary.

---

## 7. Report encryption

Reports use hybrid encryption:

```text
Report
  │
  ▼
AES-256-GCM encryption
  │
  └── fresh AES key + nonce
              │
              ▼
       RSA-OAEP wrapping
       with public key
```

The investigator's private key is not required by the server.

The public key registration is held in memory for the current server session.

---

## 8. Evidence persistence

The stored report JSON is treated as immutable evidence output.

Case metadata is stored separately so changing a case title, status or notes does not rewrite the evidence document.

This is a logical immutability model; production deployments should additionally protect the database file with OS permissions, backups, and access controls appropriate to the environment.

---

## 9. Endpoint safety model

Collectors should be read-only and bounded.

The Windows injection collectors specifically:

- do not inject DLLs;
- do not create remote threads;
- do not suspend threads;
- do not write process memory;
- do not read arbitrary process-memory contents;
- do not disable AV/EDR;
- do not modify security configuration.

---

## 10. Report and finding language

JOCKY deliberately uses language such as:

- indicator
- review recommended
- anomaly
- lead
- correlation

rather than automatically asserting:

- malware
- attacker
- compromise

This is important because forensic evidence often requires contextual validation.

---

## 11. Deployment recommendations

For any environment beyond a local laboratory:

- bind the API behind an authenticated TLS reverse proxy;
- restrict network exposure;
- protect `.env` and signing keys;
- protect the SQLite database with OS permissions;
- use dedicated service accounts where appropriate;
- rotate API/agent credentials according to organizational policy;
- back up investigations securely;
- avoid disabling TLS verification;
- test collectors on representative endpoints before broad deployment.

---

## 12. Security review checklist

Before a production-style deployment, review:

- authentication and authorization
- reverse-proxy/TLS configuration
- database file permissions
- secret storage
- agent token lifecycle
- job replay/expiry requirements
- input-size limits
- API rate limiting
- audit logging
- report retention
- endpoint privilege requirements
- collector resource bounds
- supply-chain pinning for dependencies
