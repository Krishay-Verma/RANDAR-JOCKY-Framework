# RANDAR V1.1 — Network Evidence

## Scope

V1.1 makes network evidence a first-class JOCKY capability. It supports normalized network artifacts from Zeek `conn.log`, Zeek `dns.log`, Zeek JSON-lines, classic PCAP, and PCAPNG.

## NetworkArtifact

Each artifact contains:

- timestamp
- source
- destination
- protocol
- source_port
- destination_port
- process (currently null for imported network files)
- metadata

Imported PCAP/PCAPNG data is metadata-only. Packet payloads are not retained.

## Workflow

1. Open **Network Forensics**.
2. Import a supported source file.
3. Select that source when creating an investigation.
4. Use `collect network_artifacts;`.
5. JOCKY normalizes the evidence and calculates statistics.
6. The report records the source filename and SHA-256.

## Supported Zeek formats

- `conn.log` TSV
- `dns.log` TSV
- JSON-lines representations of connection/DNS records

## Supported packet formats

- classic PCAP Ethernet/RAW IP metadata
- PCAPNG Ethernet/RAW IP metadata
- IPv4 and IPv6
- TCP and UDP ports
- DNS query metadata when UDP/TCP traffic uses port 53

## Statistics

JOCKY calculates:

- connection/artifact count
- unique sources
- unique destinations
- unique domains
- protocol counts
- first seen
- last seen

## DSL

```text
investigation "Network Evidence Intake" {
    collect network_artifacts;
    report "network_evidence";
}
```

The collector remains allowlisted and zero-argument. The selected source is supplied by the controlled console/API context rather than by the script itself.

## Limits

- maximum source size: 20 MiB
- maximum normalized artifacts retained per source: 100,000
- payload bytes are not retained
- process ownership is not inferred from imported network files

These are deliberate V1.1 boundaries. Threat hunting, beaconing, scanning detection, and endpoint/network correlation remain V1.2 scope.
