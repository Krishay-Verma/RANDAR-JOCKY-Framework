"""Pure V1.2 network threat-hunting rules.

These rules consume normalized V1.1 network evidence only. They do not touch
network sockets, send probes, resolve domains, or otherwise perform active
network operations. Findings are investigation leads, not verdicts.
"""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable

from jocky.analysis.finding import Finding, SEVERITY_INFO, SEVERITY_REVIEW

# Conservative defaults are intentionally explicit and testable.
_DNS_BURST_COUNT = 10
_DNS_BURST_WINDOW = 60.0
_BEACON_MIN_EVENTS = 5
_BEACON_MAX_INTERVAL = 3600.0
_BEACON_MAX_JITTER = 0.25
_RARE_DOMAIN_MIN_DISTINCT = 5
_LONG_LABEL_LENGTH = 40
_RANDOM_LABEL_MIN_LENGTH = 12
_RANDOM_LABEL_ENTROPY = 4.0
_SCAN_MIN_PORTS = 10
_SCAN_MIN_HOSTS = 10
_SERVICE_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443}
_SUSPICIOUS_TLDS = {"zip", "mov", "click", "country", "gq", "tk", "ml", "cf", "ga", "top", "xyz", "work", "support", "download", "cam", "rest", "icu", "buzz"}
_UNUSUAL_QTYPES = {"ANY", "NULL", "AXFR", "IXFR", "MAILA", "MAILB"}


def _artifacts(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    data = evidence.get("network_artifacts") or {}
    return list(data.get("artifacts") or [])


def _dns(arts: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [a for a in arts if isinstance((a.get("metadata") or {}).get("domain"), str) and (a.get("metadata") or {}).get("domain")]


def _domain(a: dict[str, Any]) -> str:
    return str((a.get("metadata") or {}).get("domain") or "").strip().rstrip(".").lower()


def _timestamp(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, OverflowError):
        try:
            return float(value)
        except (ValueError, TypeError):
            return None


def _intervals(items: list[dict[str, Any]]) -> list[float]:
    times = sorted(t for t in (_timestamp(a.get("timestamp")) for a in items) if t is not None)
    return [b - a for a, b in zip(times, times[1:]) if b > a]


def _jitter(intervals: list[float]) -> tuple[float | None, float | None]:
    if not intervals:
        return None, None
    mean = statistics.fmean(intervals)
    if mean <= 0:
        return mean, None
    return mean, statistics.pstdev(intervals) / mean if len(intervals) > 1 else 0.0


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _labels(domain: str) -> list[str]:
    return [x for x in domain.split(".") if x]


def _base_domain(domain: str) -> str:
    labels = _labels(domain)
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def _finding(rule: str, summary: str, reason: str, evidence: dict[str, Any], severity: str = SEVERITY_REVIEW) -> Finding:
    return Finding(rule_name=rule, severity=severity, summary=summary, reason=reason, related_evidence=evidence)


def rule_suspicious_dns_queries(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    for a in _dns(_artifacts(evidence)):
        domain = _domain(a)
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        qtype = str((a.get("metadata") or {}).get("qtype") or "").upper()
        if tld in _SUSPICIOUS_TLDS or qtype in _UNUSUAL_QTYPES:
            findings.append(_finding(
                "suspicious_dns_queries",
                f"DNS query matches a configured review pattern: {domain}",
                "The query uses a configured uncommon/suspicious TLD pattern or uncommon DNS query type. This is an investigation lead, not proof of malicious activity.",
                {"source": a.get("source"), "destination": a.get("destination"), "domain": domain, "qtype": qtype, "timestamp": a.get("timestamp")},
            ))
    return findings


def rule_dns_entropy(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    seen = set()
    for a in _dns(_artifacts(evidence)):
        domain = _domain(a)
        labels = _labels(domain)
        if not labels:
            continue
        label = max(labels, key=len)
        if len(label) < _RANDOM_LABEL_MIN_LENGTH:
            continue
        ent = _entropy(label)
        key = (a.get("source"), domain)
        if ent >= _RANDOM_LABEL_ENTROPY and key not in seen:
            seen.add(key)
            findings.append(_finding(
                "dns_entropy",
                f"High-entropy DNS label observed: {domain}",
                f"The longest label has Shannon entropy {ent:.2f} bits/character over {len(label)} characters. High entropy can occur with generated identifiers, CDNs, tracking, or DNS tunneling and requires context.",
                {"source": a.get("source"), "domain": domain, "label": label, "entropy": round(ent, 4)},
            ))
    return findings


def rule_rare_domains(evidence: dict[str, Any]) -> list[Finding]:
    dns = _dns(_artifacts(evidence))
    counts = Counter(_domain(a) for a in dns)
    if len(counts) < _RARE_DOMAIN_MIN_DISTINCT:
        return []
    findings = []
    for domain, count in sorted(counts.items()):
        if count == 1:
            sample = next(a for a in dns if _domain(a) == domain)
            findings.append(_finding(
                "rare_domains",
                f"Rare DNS domain observed: {domain}",
                "This domain appears once in the supplied DNS evidence set. Rarity is contextual and does not indicate maliciousness by itself.",
                {"domain": domain, "count": count, "source": sample.get("source"), "timestamp": sample.get("timestamp")},
                SEVERITY_INFO,
            ))
    return findings


def rule_suspicious_tld_patterns(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    seen = set()
    for a in _dns(_artifacts(evidence)):
        domain = _domain(a)
        tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
        key = (a.get("source"), domain)
        if tld in _SUSPICIOUS_TLDS and key not in seen:
            seen.add(key)
            findings.append(_finding(
                "suspicious_tld_patterns",
                f"DNS domain uses a configured review TLD: .{tld}",
                "The top-level domain is included in JOCKY's configurable review list because it is often useful during threat-hunting triage. Legitimate services also use these TLDs.",
                {"source": a.get("source"), "domain": domain, "tld": tld},
            ))
    return findings


def rule_dns_bursts(evidence: dict[str, Any]) -> list[Finding]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for a in _dns(_artifacts(evidence)):
        groups[(str(a.get("source") or "unknown"), _domain(a))].append(a)
    findings = []
    for (source, domain), items in groups.items():
        times = sorted(t for t in (_timestamp(a.get("timestamp")) for a in items) if t is not None)
        if len(times) < _DNS_BURST_COUNT:
            continue
        max_count = 0
        left = 0
        for right, t in enumerate(times):
            while t - times[left] > _DNS_BURST_WINDOW:
                left += 1
            max_count = max(max_count, right - left + 1)
        if max_count >= _DNS_BURST_COUNT:
            findings.append(_finding(
                "dns_bursts",
                f"DNS burst observed for {domain}",
                f"Source {source} issued at least {max_count} queries for the same domain within {_DNS_BURST_WINDOW:.0f} seconds. Bursts can be caused by normal applications as well as automated activity.",
                {"source": source, "domain": domain, "max_queries_in_window": max_count, "window_seconds": _DNS_BURST_WINDOW},
            ))
    return findings


def rule_unusual_query_types(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    seen = set()
    for a in _dns(_artifacts(evidence)):
        qtype = str((a.get("metadata") or {}).get("qtype") or "").upper()
        if qtype in _UNUSUAL_QTYPES:
            key = (a.get("source"), _domain(a), qtype)
            if key not in seen:
                seen.add(key)
                findings.append(_finding(
                    "unusual_query_types",
                    f"Unusual DNS query type observed: {qtype}",
                    "The query type is uncommon in routine endpoint DNS telemetry and is surfaced for analyst review. Some infrastructure and diagnostic workflows legitimately use it.",
                    {"source": a.get("source"), "domain": _domain(a), "qtype": qtype, "timestamp": a.get("timestamp")},
                ))
    return findings


def rule_long_random_labels(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    seen = set()
    for a in _dns(_artifacts(evidence)):
        domain = _domain(a)
        label = max(_labels(domain), key=len, default="")
        ent = _entropy(label)
        if len(label) >= _LONG_LABEL_LENGTH or (len(label) >= _RANDOM_LABEL_MIN_LENGTH and ent >= _RANDOM_LABEL_ENTROPY):
            key = (a.get("source"), domain)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding(
                "long_random_labels",
                f"Long/random-looking DNS label observed: {domain}",
                f"A label is {len(label)} characters long with entropy {ent:.2f}. Long or generated-looking labels can be legitimate, but they are useful evidence when investigating encoded DNS data.",
                {"source": a.get("source"), "domain": domain, "label": label, "label_length": len(label), "entropy": round(ent, 4)},
            ))
    return findings


def rule_dns_tunneling_indicators(evidence: dict[str, Any]) -> list[Finding]:
    dns = _dns(_artifacts(evidence))
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for a in dns:
        groups[(str(a.get("source") or "unknown"), _base_domain(_domain(a)))].append(a)
    findings = []
    for (source, base), items in groups.items():
        domains = {_domain(a) for a in items}
        long_count = sum(1 for a in items if len(max(_labels(_domain(a)), key=len, default="")) >= _LONG_LABEL_LENGTH)
        high_entropy_count = sum(1 for a in items if _entropy(max(_labels(_domain(a)), key=len, default="")) >= _RANDOM_LABEL_ENTROPY and len(max(_labels(_domain(a)), key=len, default="")) >= _RANDOM_LABEL_MIN_LENGTH)
        txt_count = sum(1 for a in items if str((a.get("metadata") or {}).get("qtype") or "").upper() == "TXT")
        burst = len(items) >= _DNS_BURST_COUNT
        signals = []
        if len(domains) >= 8: signals.append("many unique subdomains")
        if long_count: signals.append("long labels")
        if high_entropy_count: signals.append("high-entropy labels")
        if txt_count >= 3: signals.append("repeated TXT queries")
        if burst: signals.append("high query volume")
        if len(signals) >= 2:
            findings.append(_finding(
                "dns_tunneling_indicators",
                f"Possible DNS tunneling indicator for {base}",
                "Multiple DNS characteristics associated with tunneling are present together: " + ", ".join(signals) + ". These patterns can also occur in legitimate telemetry, CDNs, software updates, and tracking systems.",
                {"source": source, "base_domain": base, "query_count": len(items), "unique_domains": len(domains), "long_label_count": long_count, "high_entropy_count": high_entropy_count, "txt_query_count": txt_count, "signals": signals},
            ))
    return findings


def rule_dns_beaconing(evidence: dict[str, Any]) -> list[Finding]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for a in _dns(_artifacts(evidence)):
        groups[(str(a.get("source") or "unknown"), _domain(a))].append(a)
    findings = []
    for (source, domain), items in groups.items():
        if len(items) < _BEACON_MIN_EVENTS:
            continue
        ints = _intervals(items)
        if len(ints) < _BEACON_MIN_EVENTS - 1:
            continue
        mean, jitter = _jitter(ints)
        if mean is not None and jitter is not None and 5 <= mean <= _BEACON_MAX_INTERVAL and jitter <= _BEACON_MAX_JITTER:
            findings.append(_finding(
                "dns_beaconing",
                f"Possible DNS beaconing: {domain}",
                f"The same source queried the same domain {len(items)} times with a mean interval of {mean:.1f}s and relative jitter of {jitter:.2f}. Periodicity is an indicator for review, not proof of command-and-control activity.",
                {"source": source, "domain": domain, "count": len(items), "mean_interval_seconds": round(mean, 3), "jitter": round(jitter, 4), "first_seen": min(a.get("timestamp") for a in items if a.get("timestamp")), "last_seen": max(a.get("timestamp") for a in items if a.get("timestamp"))},
            ))
    return findings


def _network_groups(arts: list[dict[str, Any]]) -> dict[tuple[str, str, Any, str], list[dict[str, Any]]]:
    groups = defaultdict(list)
    for a in arts:
        if (a.get("metadata") or {}).get("domain"):
            continue
        key = (str(a.get("source") or "unknown"), str(a.get("destination") or "unknown"), a.get("destination_port"), str(a.get("protocol") or "unknown").lower())
        groups[key].append(a)
    return groups


def rule_network_beaconing(evidence: dict[str, Any]) -> list[Finding]:
    findings = []
    for (source, dest, port, proto), items in _network_groups(_artifacts(evidence)).items():
        if len(items) < _BEACON_MIN_EVENTS:
            continue
        ints = _intervals(items)
        if len(ints) < _BEACON_MIN_EVENTS - 1:
            continue
        mean, jitter = _jitter(ints)
        if mean is not None and jitter is not None and 5 <= mean <= _BEACON_MAX_INTERVAL and jitter <= _BEACON_MAX_JITTER:
            findings.append(_finding(
                "network_beaconing",
                f"Possible network beaconing to {dest}:{port}",
                f"Repeated {proto.upper()} connections show a mean interval of {mean:.1f}s with relative jitter {jitter:.2f}. Periodic network activity can be benign or automated and should be correlated with process and DNS evidence.",
                {"source": source, "destination": dest, "destination_port": port, "protocol": proto, "count": len(items), "mean_interval_seconds": round(mean, 3), "jitter": round(jitter, 4)},
            ))
    return findings


def rule_port_scan(evidence: dict[str, Any]) -> list[Finding]:
    groups: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for a in _artifacts(evidence):
        if a.get("source") and a.get("destination") and a.get("destination_port") is not None:
            groups[str(a["source"])][str(a["destination"])].add(a["destination_port"])
    findings = []
    for source, targets in groups.items():
        for target, ports in targets.items():
            if len(ports) >= _SCAN_MIN_PORTS:
                findings.append(_finding(
                    "port_scan",
                    f"Possible vertical port scan: {source} → {target}",
                    f"One source contacted {len(ports)} distinct destination ports on one target. The evidence is consistent with a port-scan pattern, but can also reflect service discovery or application behavior.",
                    {"source": source, "destination": target, "unique_destination_ports": sorted(ports)},
                ))
    return findings


def rule_horizontal_scan(evidence: dict[str, Any]) -> list[Finding]:
    groups: dict[tuple[str, Any], set[str]] = defaultdict(set)
    for a in _artifacts(evidence):
        if a.get("source") and a.get("destination") and a.get("destination_port") is not None:
            groups[(str(a["source"]), a["destination_port"])].add(str(a["destination"]))
    findings = []
    for (source, port), hosts in groups.items():
        if len(hosts) >= _SCAN_MIN_HOSTS:
            findings.append(_finding(
                "horizontal_scan",
                f"Possible horizontal scan from {source} on port {port}",
                f"One source contacted {len(hosts)} distinct hosts on the same destination port. This pattern is consistent with horizontal service discovery or scanning and requires context.",
                {"source": source, "destination_port": port, "unique_destinations": sorted(hosts)},
            ))
    return findings


def rule_service_discovery(evidence: dict[str, Any]) -> list[Finding]:
    groups: dict[str, set[tuple[str, int]]] = defaultdict(set)
    for a in _artifacts(evidence):
        if a.get("source") and a.get("destination") and a.get("destination_port") in _SERVICE_PORTS:
            groups[str(a["source"])].add((str(a["destination"]), int(a["destination_port"])))
    findings = []
    for source, pairs in groups.items():
        distinct_ports = {p for _, p in pairs}
        if len(distinct_ports) >= 5 or len(pairs) >= _SCAN_MIN_HOSTS:
            findings.append(_finding(
                "service_discovery",
                f"Possible service discovery from {source}",
                f"The source contacted {len(pairs)} destination/port combinations across {len(distinct_ports)} common infrastructure ports. This can be normal inventory or discovery traffic as well as scanning.",
                {"source": source, "connection_pairs": len(pairs), "common_ports": sorted(distinct_ports)},
            ))
    return findings


def rule_udp_scan(evidence: dict[str, Any]) -> list[Finding]:
    groups: dict[str, set[tuple[str, Any]]] = defaultdict(set)
    for a in _artifacts(evidence):
        if str(a.get("protocol") or "").lower() == "udp" and a.get("source") and a.get("destination"):
            groups[str(a["source"])].add((str(a["destination"]), a.get("destination_port")))
    findings = []
    for source, pairs in groups.items():
        if len(pairs) >= _SCAN_MIN_HOSTS:
            findings.append(_finding(
                "udp_scan",
                f"Possible UDP scan from {source}",
                f"The source produced {len(pairs)} distinct UDP destination/port combinations. UDP scanning is inferred only from supplied metadata; packet payloads and probe success are not required or retained.",
                {"source": source, "unique_udp_targets": len(pairs)},
            ))
    return findings


def classify_address(address: Any) -> str:
    try:
        ip = ipaddress.ip_address(str(address))
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "public"
    return "unknown"


def rule_network_classification(evidence: dict[str, Any]) -> list[Finding]:
    counts = Counter()
    examples: dict[str, list[str]] = defaultdict(list)
    for a in _artifacts(evidence):
        for field in ("source", "destination"):
            address = a.get(field)
            if not address:
                continue
            category = classify_address(address)
            counts[category] += 1
            if len(examples[category]) < 5 and str(address) not in examples[category]:
                examples[category].append(str(address))
    if not counts:
        return []
    return [_finding(
        "network_classification",
        "Network address classification completed",
        "Normalized network endpoints were classified as loopback, private, link-local, multicast, public, or unknown using local address properties. Classification is descriptive and does not imply risk.",
        {"counts": dict(sorted(counts.items())), "examples": dict(examples)},
        SEVERITY_INFO,
    )]


def rule_process_network_correlation(evidence: dict[str, Any]) -> list[Finding]:
    processes = {p.get("pid"): p for p in (evidence.get("processes") or {}).get("processes", []) if p.get("pid") is not None}
    conns = (evidence.get("network_connections") or {}).get("connections", [])
    findings = []
    for c in conns:
        pid = c.get("pid")
        if pid is None or pid not in processes or not c.get("remote_ip"):
            continue
        proc = processes[pid]
        destination = c.get("remote_ip")
        local_endpoint = str(c.get("local_address") or "")
        local_source = local_endpoint.rsplit(":", 1)[0] if ":" in local_endpoint else local_endpoint
        matching_dns = [a for a in _dns(_artifacts(evidence)) if str(a.get("source") or "") == local_source and a.get("destination") == destination]
        findings.append(_finding(
            "process_network_correlation",
            f"Process '{proc.get('name')}' linked to {destination}:{c.get('remote_port')}",
            "Correlated a running process PID with an active network connection and, where available, matching DNS evidence. This provides investigation context only.",
            {"pid": pid, "process_name": proc.get("name"), "executable": proc.get("exe_path"), "destination": destination, "destination_port": c.get("remote_port"), "protocol": c.get("protocol"), "dns_domains": sorted({_domain(a) for a in matching_dns})},
            SEVERITY_INFO,
        ))
    return findings
