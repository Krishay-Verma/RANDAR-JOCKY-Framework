# JOCKY DSL Reference

## 1. Purpose

The JOCKY language is a deliberately small domain-specific language for describing forensic collection and analysis.

It is **not** a general-purpose programming language and it is **not** a shell.

Its job is to answer:

> Which approved evidence sources should run, which approved analysis rules should consume that evidence, and what report should be produced?

---

## 2. Minimal script

```text
investigation "Basic Triage" {
    collect system_info;
    collect processes;
    analyze missing_paths;
    report "basic_triage";
}
```

---

## 3. Statements

### Investigation declaration

```text
investigation "Name" {
    ...
}
```

### Collect

```text
collect processes;
```

The name must exist in the collector registry.

### Analyze

```text
analyze suspicious_processes;
```

The name must exist in the analysis-rule registry.

### Report

```text
report "report_name";
```

The report name is stored with the investigation result.

### Variable

```text
let threshold = 10;
```

Variables are immutable bindings within an investigation.

### Conditional

```text
if network_connections.count > threshold {
    analyze high_connection_processes;
}
```

### Else

```text
if processes.count > 100 {
    analyze suspicious_processes;
} else {
    analyze process_network_correlation;
}
```

---

## 4. Grammar

Current grammar:

```text
investigation := 'investigation' STRING '{' statement* '}'
statement     := 'collect' IDENT ';'
               | 'analyze' IDENT ';'
               | 'report' STRING ';'
               | 'let' IDENT '=' expr ';'
               | 'if' expr op expr '{' statement* '}' ('else' '{' statement* '}')?
op            := '>' | '<' | '>=' | '<=' | '==' | '!='
expr          := INTEGER | STRING | 'true' | 'false' | IDENT | IDENT '.' IDENT
```

Line comments begin with `//`.

Identifiers use:

```text
[a-z_][a-z0-9_]*
```

---

## 5. Evidence properties

Conditions may reference allowlisted properties.

Current properties include:

```text
processes.count
network_connections.count
logged_in_users.count
file_hash.count
scheduled_tasks.count
startup_items.count
open_files.count
local_users.count
modules.count
threads.count
memory_regions.count
system_info.hostname
system_info.platform
system_info.cpu_count
```

If a referenced collector was not executed or failed, the interpreter uses a safe zero/empty-style fallback for supported count properties so the condition does not crash the entire investigation.

---

## 6. Complete Windows injection example

```text
investigation "Windows Injection Forensics" {
    collect system_info;
    collect processes;
    collect modules;
    collect threads;
    collect memory_regions;
    collect network_connections;

    analyze suspicious_module_loads;
    analyze dll_sideloading;
    analyze process_hollowing_indicators;
    analyze reflective_load_indicators;
    analyze thread_hijacking_indicators;
    analyze injection_correlation;

    report "windows_injection_forensics";
}
```

---

## 7. Safety limits

The current implementation enforces limits on:

- script size
- `if` nesting depth
- number of variables
- integer literal length
- known collector/rule names

Malformed scripts fail during validation before endpoint collection begins.

---

## 8. How scripts execute

```text
Source text
   ↓
Tokens
   ↓
AST/IR dataclasses
   ↓
Interpreter
   ↓
Allowlisted collector/rule resolution
   ↓
Evidence + findings
```

A source script never becomes Python code and is never passed to `eval()` or a shell.

---

## 9. Bytecode relationship

The bytecode path is another representation of the same controlled investigation plan.

```text
JOCKY source
    ↓
parse
    ↓
IR
    ↓
bytecode serialization
    ↓
HMAC-SHA256 signature
    ↓
verification
    ↓
IR reconstruction
    ↓
ordinary interpreter
```

The bytecode system therefore does not grant capabilities beyond the source interpreter.

---

## 10. Design principles for future language features

New language features should preserve:

1. explicit capabilities;
2. deterministic parsing;
3. bounded resource use;
4. no arbitrary OS command execution;
5. inspectable IR;
6. clear provenance;
7. predictable failure behavior.
