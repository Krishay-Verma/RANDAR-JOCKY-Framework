# RANDAR Documentation

**Current implementation:** v1.9.2  
**Project:** RANDAR  
**Language/runtime:** JOCKY  
**SIH 2026 Problem Statement:** SIH26148

This documentation set describes the **implemented repository state**. Capability counts and names are derived from the live collector/analysis registries where applicable.

## Documentation index

| Document | Primary audience | Coverage |
|---|---|---|
| [`SIH_2026_TECHNICAL_BRIEF.md`](SIH_2026_TECHNICAL_BRIEF.md) | Judges, reviewers, technical evaluators | Problem, architecture, novelty, implementation and boundaries |
| [`PRODUCT_GUIDE.md`](PRODUCT_GUIDE.md) | Investigators, judges, new developers | Product workflow and mental model |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Developers, architects | System components and data flow |
| [`DFIR_CAPABILITIES.md`](DFIR_CAPABILITIES.md) | DFIR/security reviewers | Collector and rule matrix |
| [`DSL_REFERENCE.md`](DSL_REFERENCE.md) | Developers, investigators | JOCKY language |
| [`SECURITY_MODEL.md`](SECURITY_MODEL.md) | Security reviewers | Trust boundaries and controls |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Operators | Setup and deployment |
| [`PROJECT_STRUCTURE.md`](PROJECT_STRUCTURE.md) | Contributors | Repository and extension points |
| [`DEMO_PLAYBOOK.md`](DEMO_PLAYBOOK.md) | SIH presenters | Demonstration workflow |
| `V1_*_RELEASE.md` | Maintainers | Historical release notes |

## Documentation principles

1. **Implemented behavior first.** Historical roadmap language is not used as evidence that a capability exists.
2. **Explicit boundaries.** Read-only, bounded and unsupported-platform behavior is documented where it matters.
3. **Evidence over verdicts.** Findings are investigation indicators and must be interpreted in context.
4. **Capability registries are authoritative.** The engine registry is the source of truth for executable collectors and analysis rules.
5. **JOCKY is the language; RANDAR is the platform.** The internal Python package remains `jocky/` for implementation continuity.
