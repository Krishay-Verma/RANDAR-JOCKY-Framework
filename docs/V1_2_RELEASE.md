# RANDAR V1.2 — Network Threat Hunting

## Release status

**Version:** 1.2.0  
**Scope:** Network Threat Hunting  
**Baseline:** V1.1 Network Evidence

V1.2 turns the normalized network evidence introduced in V1.1 into explainable investigation leads. The hunting layer is passive: it analyzes supplied Zeek/PCAP/PCAPNG metadata and current endpoint connection/process evidence. It does not perform active scanning, DNS resolution, packet capture, exploitation, or payload retention.

## Implemented capabilities

### DNS

- `suspicious_dns_queries`
- `dns_entropy`
- `rare_domains`
- `suspicious_tld_patterns`
- `dns_bursts`
- `unusual_query_types`
- `long_random_labels`
- `dns_tunneling_indicators`

DNS findings use language such as **Possible DNS tunneling indicator** rather than claiming proof.

### DNS beaconing

`dns_beaconing` measures repeated source/domain queries and records:

- count
- mean interval
- relative interval jitter
- first seen
- last seen

### Network beaconing

`network_beaconing` groups normalized non-DNS connections by source, destination, destination port and protocol, then evaluates repeated timing and jitter.

### Network scanning analysis

- `port_scan` — one source touching many ports on one target.
- `horizontal_scan` — one source touching one service across many hosts.
- `service_discovery` — systematic contact with common infrastructure ports.
- `udp_scan` — repeated UDP destination/port combinations inferred from supplied metadata.

No active probes are generated.

### Network classification

`network_classification` classifies observed IP addresses as:

- loopback
- private
- link-local
- multicast
- public
- unknown

The result is descriptive and does not imply risk.

### Process-to-network correlation

`process_network_correlation` links:

```text
Process
  ↓ PID
Active network connection
  ↓
Destination / port
  ↓
Matching DNS context where available
```

## DSL

V1.2 uses the existing controlled `analyze` command and allowlisted rule registry. Example:

```text
investigation "Network Threat Hunt" {
    collect network_artifacts;
    collect processes;
    collect network_connections;

    analyze suspicious_dns_queries;
    analyze dns_entropy;
    analyze rare_domains;
    analyze suspicious_tld_patterns;
    analyze dns_bursts;
    analyze unusual_query_types;
    analyze long_random_labels;
    analyze dns_tunneling_indicators;
    analyze dns_beaconing;

    analyze network_beaconing;
    analyze port_scan;
    analyze horizontal_scan;
    analyze service_discovery;
    analyze udp_scan;
    analyze network_classification;

    analyze process_network_correlation;

    report "network_threat_hunt";
}
```

## Thresholds and interpretation

V1.2 uses conservative deterministic defaults. They are implementation thresholds, not threat-intelligence verdicts:

| Analysis | Default trigger |
|---|---|
| DNS burst | 10+ same-domain queries in 60 seconds |
| DNS beaconing | 5+ events, mean interval 5–3600 seconds, relative jitter ≤ 0.25 |
| Network beaconing | 5+ events, mean interval 5–3600 seconds, relative jitter ≤ 0.25 |
| Vertical scan | 10+ destination ports on one target |
| Horizontal scan | 10+ hosts on one destination port |
| UDP scan | 10+ distinct UDP destination/port combinations per source |
| Rare domain | single occurrence when the evidence contains at least 5 distinct domains |
| Long label | 40+ characters |
| Random-looking label | 12+ characters and entropy ≥ 4.0 bits/character |

These values are deliberately documented so an analyst can understand exactly why a rule fired.

## Safety and evidence boundaries

- Analysis is pure over already-collected evidence.
- No active network scanning is implemented.
- Packet payloads remain excluded under the V1.1 evidence policy.
- Findings are indicators for human review, not definitive malware determinations.
- Endpoint connection visibility depends on operating-system permissions.
- V1.2 does not add PowerShell, Windows Event Log, Sysmon, PE analysis, or injection implementation; those remain later roadmap versions.

## UI and reporting

- Network evidence import remains available from **Network Forensics**.
- Investigation details expose the actual V1.2 hunting findings, per-finding supporting evidence, scan/beaconing/DNS result counts, and normalized network evidence.
- Findings use human-readable labels while preserving machine rule names; the Network Forensics tab shows the generated findings directly rather than only an indicator count.
- HTML reports include a dedicated Network Threat Hunting section.
- JSON reports contain the same findings and evidence references used by the UI.

## Validation

The release regression suite covers:

- all V1.0/V1.1 behavior
- all V1.2 rules being registered and DSL-addressable
- DNS entropy and label analysis
- DNS tunneling indicator composition
- DNS beaconing
- vertical and horizontal scan analysis
- service discovery
- UDP scan analysis
- network address classification
- process/network/DNS correlation
- full V1.2 DSL validation

After the final UI/correlation fixes, the Python regression suite passes **42/42** tests in the provided environment.

The frontend production build remains environment-dependent because npm package installation requires the configured npm registry/cache; the source changes are included in the release.

## Final V1.2 maintenance fixes

- Added a route-level React error boundary so a rendering failure in one console view no longer produces an unexplained blank content area; the operator receives Retry and Reload actions instead.
- Fixed React hook ordering in Investigation Detail by keeping all hooks unconditional; this prevents React error #310 when investigation data transitions between loading, error, and loaded states.
- Expanded the investigation Network Forensics tab to show every V1.2 finding with severity, rule, observed pattern, and expandable supporting evidence.
- Added process/network correlation to the V1.2 network-results view and HTML hunting section.
- Added an IPv6-safe local endpoint extraction path for process/network/DNS correlation.
- Added regression coverage for the IPv6 correlation case.
