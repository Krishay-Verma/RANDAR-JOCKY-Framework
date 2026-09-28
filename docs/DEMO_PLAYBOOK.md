# JOCKY SIH Demo Playbook

## Objective

Demonstrate the complete JOCKY value proposition in a short, reproducible workflow:

```text
New investigation
      ↓
Write JOCKY script
      ↓
Validate
      ↓
Inspect IR
      ↓
Run on Windows endpoint
      ↓
Collect process/network/module/thread/memory evidence
      ↓
Correlate indicators
      ↓
Review evidence
      ↓
Export protected report
```

---

## 1. Open the console

Start JOCKY and sign in.

Show:

- Dashboard
- Investigations
- DLL / injection navigation item
- Endpoint agents
- Bytecode
- Report encryption

Avoid spending the demonstration on generic dashboard animations. The product value is the investigation pipeline.

---

## 2. Show the problem

Explain that traditional triage can require a collection of independent commands and tools.

Then introduce JOCKY's model:

> “The investigation itself becomes executable, reviewable code.”

---

## 3. Show the language

Open **New investigation** and paste:

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

Explain that this is not Python, PowerShell, or a shell command. It is JOCKY's purpose-built investigation language.

---

## 4. Validate before execution

Use **Validate**.

Point out:

- lexer/parser validation occurs first;
- malformed scripts fail before collection;
- the engine knows only explicitly registered capabilities.

---

## 5. Show IR/bytecode

Use the bytecode/IR view to show:

```text
Source
 ↓
Tokens
 ↓
IR
 ↓
Signed bytecode
```

The important demonstration point is that the language is implemented as an actual execution pipeline rather than a text box that launches shell commands.

---

## 6. Run the investigation

After execution, open the investigation detail page.

Highlight:

- endpoint identity
- execution duration
- script hash
- collector counts
- findings
- evidence

Then open **DLL / injection**.

---

## 7. Explain the Windows injection telemetry

Show the three evidence families:

```text
Loaded Modules
      +
Threads
      +
Virtual Memory Regions
      ↓
Injection Correlation
```

Emphasize that JOCKY is observing forensic indicators rather than performing injection.

---

## 8. Explain a finding

Choose one indicator and walk through:

```text
Technique
Process
Module / memory evidence
Why it was flagged
Severity
Related evidence
```

Always state that an indicator is a lead for human review, not an automatic malware verdict.

---

## 9. Demonstrate reporting

Generate the HTML report.

Show that the report contains:

- investigation identity
- timing
- script hash
- collector output
- findings
- injection analysis
- evidence context

Then demonstrate encrypted export if time permits.

---

## 10. Closing statement

The strongest closing message is:

> **JOCKY turns forensic investigation logic into secure, repeatable, executable code.**

The product is not simply another process viewer. Its core innovation is the combination of:

- a purpose-built forensic language;
- controlled execution;
- modular collectors;
- evidence-driven analysis;
- Windows advanced telemetry;
- provenance and signed bytecode;
- remote endpoint execution;
- protected reporting.
