# SIH26148 Alignment

The supplied SIH26148 problem statement asks for a new language/toolchain for computer and network forensics while also describing polymorphism, in-memory execution, BYOVD/kernel manipulation, and cloud/CDN routing.

RANDAR's final product separates those themes into three tracks:

### Product / defensive implementation

- JOCKY language and compiler/runtime
- deterministic transformation research
- endpoint/network evidence acquisition
- persistence forensics
- memory/driver detection
- multi-system investigation management
- provenance and reproducibility

### Controlled research boundary

The product can record and analyze observable artifacts associated with in-memory execution, process hollowing, reflective loading, thread manipulation, and vulnerable-driver exposure. It does not implement stealth injection, kernel tampering, security-control disabling, or security-product bypass.

### Why this still addresses the forensic objective

The central forensic requirement is to systematically collect and correlate evidence. JOCKY provides a declarative execution layer, while RANDAR provides collectors, analysis rules, provenance, and reports. Research behaviors can therefore be studied through their observable artifacts without turning the production product into an evasion framework.
