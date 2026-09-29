# JOCKY DSL Reference

**Language:** JOCKY  
**Platform:** RANDAR  
**Current implementation:** v1.9.2

JOCKY is a constrained domain-specific language for composing forensic investigations.

It is intentionally **not** a general-purpose programming language and **not** a shell.

---

## 1. Minimal script

```text
investigation "Endpoint Triage" {
    collect system_info;
    collect processes;
    collect network_connections;

    analyze missing_paths;
    analyze suspicious_processes;
    analyze process_network_correlation;

    report "endpoint_triage";
}
```

---

## 2. Investigation declaration

```text
investigation "Name" {
    ...
}
```

The body contains zero or more statements.

---

## 3. Collect

```text
collect processes;
```

The collector name must exist in the live collector registry.

Unknown collectors are rejected during validation.

---

## 4. Analyze

```text
analyze suspicious_processes;
```

Analysis rules consume already-collected evidence.

A rule may optionally contain a condition:

```text
analyze high_connection_processes where network_connections.count > 10;
```

The exact available properties are exposed by the backend catalog.

---

## 5. Report

```text
report "windows_triage";
```

The report declaration sets the requested report name in the resulting investigation.

---

## 6. Variables

```text
let connection_limit = 10;
let expected_host = "LAB-PC";
```

Supported literal types are intentionally small:

- integer;
- string;
- boolean.

Variables can be used in conditions.

---

## 7. Evidence properties

Evidence properties use:

```text
collector.property
```

Examples:

```text
processes.count
network_connections.count
system_info.hostname
```

Only properties exposed by the interpreter's allowlist are valid.

---

## 8. Conditions

Comparison operators:

```text
>
<
>=
<=
==
!=
```

Boolean operators:

```text
and
or
not
```

Example:

```text
if processes.count > 100 and network_connections.count > 20 {
    analyze high_connection_processes;
}
```

---

## 9. Conditional execution

```text
if network_connections.count > 10 {
    analyze high_connection_processes;
} else {
    analyze process_network_correlation;
}
```

The parser limits nesting depth and the interpreter applies runtime limits.

---

## 10. Analyst-authored rules

JOCKY supports a bounded rule declaration:

```text
rule "Many Connections" {
    when network_connections.count > 20;
    severity medium;
}
```

The rule language remains constrained to evidence expressions. It does not contain arbitrary executable code.

---

## 11. Boolean expression grammar

Conceptually:

```text
condition
    := or_condition

or_condition
    := and_condition ("or" and_condition)*

and_condition
    := not_condition ("and" not_condition)*

not_condition
    := "not" not_condition
     | expression comparison_operator expression

comparison_operator
    := ">" | "<" | ">=" | "<=" | "==" | "!="
```

Expressions are:

```text
integer
string
true
false
identifier
identifier "." identifier
```

---

## 12. Complete Windows example

```text
investigation "Windows Injection Review" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    collect pe_metadata;

    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;

    report "windows_injection_review";
}
```

---

## 13. Network investigation example

```text
investigation "Network Threat Hunt" {
    collect system_info;
    collect network_artifacts;
    collect network_connections;
    collect processes;

    analyze suspicious_dns_queries;
    analyze dns_entropy;
    analyze rare_domains;
    analyze dns_tunneling_indicators;
    analyze dns_beaconing;
    analyze network_beaconing;
    analyze port_scan;
    analyze horizontal_scan;
    analyze service_discovery;
    analyze process_network_correlation;

    report "network_threat_hunt";
}
```

---

## 14. Validation model

JOCKY execution passes through:

```text
Source
  ↓
Lexer
  ↓
Parser
  ↓
IR
  ↓
Semantic/capability validation
  ↓
Interpreter
```

Validation checks include:

- grammar;
- known collectors;
- known analysis rules;
- evidence properties;
- variable references;
- severity values;
- condition structure;
- bounded nesting.

---

## 15. Bytecode relationship

A valid investigation can be compiled into signed JOCKY bytecode.

Current opcode families include:

```text
COLLECT
ANALYZE
REPORT
LET
IF
USER_RULE
```

The bytecode contains:

- magic identifier;
- format version;
- investigation name;
- command count;
- opcode body;
- HMAC-SHA256 signature.

The signing key is not embedded in the bytecode.

Verification occurs before disassembly or execution.

Most importantly:

> **Bytecode does not create a second unrestricted execution engine.**

It is reconstructed into the same controlled investigation model.

---

## 16. Safety limits

The implementation intentionally constrains:

- parser nesting;
- integer literal size;
- bytecode operation count;
- investigation runtime;
- collector runtime;
- collector output;
- evidence volume;
- Windows metadata traversal.

These controls are part of the language/runtime design rather than optional conventions.

---

## 17. Design principles

Future JOCKY features should preserve:

1. explicit capability registration;
2. bounded execution;
3. deterministic semantics where practical;
4. evidence/analysis separation;
5. inspectability before execution;
6. compatibility with the IR;
7. bytecode verification;
8. no arbitrary command execution.
