# RANDAR SIH 2026 Demo Playbook

**Objective:** demonstrate the implemented technical architecture, not only the interface.

---

## 1. Opening statement

Use a concise framing:

> RANDAR turns a forensic investigation into a controlled executable artifact. JOCKY defines the investigation, the runtime restricts what that script can do, collectors acquire evidence, deterministic rules correlate it, and the resulting case retains provenance and integrity metadata.

---

## 2. Show the architecture

```text
JOCKY
  ↓
IR
  ↓
Controlled execution
  ↓
Collectors
  ↓
Evidence
  ↓
Analysis
  ↓
Findings
  ↓
Case + report
```

Explain that the same model is used for local and remote execution.

---

## 3. Show the language

Open the JOCKY editor and demonstrate a small script:

```text
investigation "Endpoint Network Review" {
    collect system_info;
    collect processes;
    collect network_connections;
    analyze process_network_correlation;
    report "endpoint_network_review";
}
```

The key point is that the script describes **investigative intent** rather than arbitrary operating-system commands.

---

## 4. Validate before execution

Demonstrate validation.

Explain:

- syntax is checked;
- collector/rule names are checked;
- unsupported capabilities are rejected;
- the script can be inspected before evidence collection.

---

## 5. Show IR / bytecode

Use the bytecode/IR view to demonstrate that:

```text
source
  ↓
IR
  ↓
signed representation
```

The important architectural point:

> Bytecode is not an unrestricted second runtime. It is verified and mapped back into the same controlled investigation model.

---

## 6. Run an investigation

Choose an evidence set appropriate to the demonstration machine.

Review:

- collector status;
- record counts;
- truncation;
- execution time;
- findings;
- evidence references.

Do not claim that every endpoint will expose identical evidence; permissions and platform state matter.

---

## 7. Demonstrate Windows advanced telemetry

On a controlled Windows system, show:

```text
modules
threads
memory_regions
pe_metadata
```

Then explain how these evidence sources can be correlated into:

- module-loading leads;
- DLL sideloading leads;
- private executable memory leads;
- thread/memory correlations;
- PE import/entropy/signature findings.

Explicitly state that the collectors do not modify processes.

---

## 8. Explain a finding

For every finding, use:

```text
What was observed?
        ↓
Which evidence supports it?
        ↓
Why is it interesting?
        ↓
What should the analyst check next?
```

Avoid presenting a heuristic as proof of maliciousness.

---

## 9. Demonstrate reporting

Show:

- HTML report;
- JSON report;
- integrity verification;
- encrypted export if prepared.

Point out:

- script hash;
- evidence hashes;
- finding IDs;
- execution status;
- timeline;
- collector results.

---

## 10. Demonstrate remote execution only if stable

If the agent demonstration is reliable:

1. register an authorized agent;
2. show capability status;
3. dispatch a bounded investigation;
4. show polling;
5. show completion/result;
6. explain revocation.

Do not make the remote feature the central demonstration if endpoint networking is unreliable.

---

## 11. Closing statement

A strong technical close is:

> RANDAR is not simply a collection of forensic scripts. It provides a language, execution boundary, evidence layer, analysis layer, integrity model, reporting pipeline and remote execution architecture around the investigation itself.

Then show the repository structure and tests if time permits.

---

## 12. What not to claim

Do not claim:

- complete EDR replacement;
- complete memory forensics;
- automatic malware attribution;
- certified chain of custody;
- arbitrary security-control bypass;
- full enterprise-scale SOC functionality.

The implemented prototype is stronger when its boundaries are stated clearly.
