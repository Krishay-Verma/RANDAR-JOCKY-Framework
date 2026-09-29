"""Bounded network-evidence ingestion for JOCKY V1.1.

Supported sources:
- Zeek conn.log / dns.log in TSV form
- Zeek JSON-lines
- classic PCAP
- PCAPNG

Only connection/DNS metadata is retained. Packet payload bytes are never
returned as evidence. The collector is zero-argument to preserve the JOCKY
collector contract; the API selects a source through a request-scoped context.
"""
from __future__ import annotations

import contextvars
import ipaddress
import json
import math
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jocky.storage.network_sources import get_network_source

_MAX_ARTIFACTS = 100_000
_MAX_FILE_BYTES = 20 * 1024 * 1024
_NETWORK_SOURCE: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "jocky_network_source", default=None
)


def set_network_source(source_id: str | None):
    return _NETWORK_SOURCE.set(source_id)


def reset_network_source(token) -> None:
    _NETWORK_SOURCE.reset(token)


def get_active_network_source() -> str | None:
    return _NETWORK_SOURCE.get()


def collect_network_artifacts() -> dict:
    source_id = get_active_network_source()
    if not source_id:
        raise RuntimeError(
            "No network evidence source selected. Upload or register a Zeek/PCAP source first."
        )
    source = get_network_source(source_id)
    if source is None:
        raise RuntimeError(f"Network evidence source '{source_id}' was not found.")
    path = Path(source["path"])
    if not path.is_file():
        raise RuntimeError("The network evidence source file is no longer available.")
    if path.stat().st_size > _MAX_FILE_BYTES:
        raise RuntimeError("Network evidence source exceeds the 20 MiB ingestion limit.")

    fmt = source["format"]
    if fmt in {"zeek_conn", "zeek_dns", "zeek_jsonl"}:
        artifacts = _parse_zeek(path, fmt)
    elif fmt == "pcap":
        artifacts = _parse_pcap(path)
    elif fmt == "pcapng":
        artifacts = _parse_pcapng(path)
    else:
        raise RuntimeError(f"Unsupported network evidence format: {fmt}")

    artifacts = artifacts[:_MAX_ARTIFACTS]
    stats = _statistics(artifacts)
    return {
        "source": {
            "id": source["id"],
            "filename": source["filename"],
            "format": source["format"],
            "sha256": source["sha256"],
            "size_bytes": source["size_bytes"],
        },
        "count": len(artifacts),
        "truncated": len(artifacts) >= _MAX_ARTIFACTS,
        "artifacts": artifacts,
        "statistics": stats,
    }


def _parse_zeek(path: Path, fmt: str) -> list[dict]:
    if fmt == "zeek_jsonl":
        return _parse_jsonl(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    fields: list[str] | None = None
    separator = "\t"
    out: list[dict] = []
    mode = "conn" if fmt == "zeek_conn" else "dns"
    for raw in text.splitlines():
        if not raw or raw.startswith("#separator") or raw.startswith("#set_separator") or raw.startswith("#empty_field") or raw.startswith("#unset_field") or raw.startswith("#path") or raw.startswith("#open") or raw.startswith("#close"):
            continue
        if raw.startswith("#fields"):
            fields = raw.split("\t")[1:]
            continue
        if fields is None:
            continue
        vals = raw.split(separator)
        row = {fields[i]: vals[i] for i in range(min(len(fields), len(vals)))}
        if mode == "conn":
            item = _zeek_conn(row)
        else:
            item = _zeek_dns(row)
        if item:
            out.append(item)
        if len(out) >= _MAX_ARTIFACTS:
            break
    return out


def _parse_jsonl(path: Path) -> list[dict]:
    out=[]
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            row=json.loads(line)
        except json.JSONDecodeError:
            continue
        item = _zeek_dns(row) if any(k in row for k in ("query", "qname", "qtype", "qtype_name")) else _zeek_conn(row)
        if item: out.append(item)
        if len(out) >= _MAX_ARTIFACTS: break
    return out


def _looks_like_conn(row: dict) -> bool:
    return any(k in row for k in ("id.resp_p", "resp_p", "id.orig_p", "orig_p", "conn_state"))


def _zeek_conn(row: dict) -> dict | None:
    src=_first(row,"id.orig_h","orig_h","source")
    dst=_first(row,"id.resp_h","resp_h","destination")
    if not src or not dst: return None
    return {
        "timestamp": _timestamp(_first(row,"ts","timestamp")),
        "source": src,
        "destination": dst,
        "protocol": str(_first(row,"proto","protocol") or "unknown").lower(),
        "source_port": _int(_first(row,"id.orig_p","orig_p","source_port")),
        "destination_port": _int(_first(row,"id.resp_p","resp_p","destination_port")),
        "process": None,
        "metadata": {k: v for k,v in row.items() if k not in {"ts","id.orig_h","id.resp_h","id.orig_p","id.resp_p","proto"}},
    }


def _zeek_dns(row: dict) -> dict | None:
    src=_first(row,"id.orig_h","orig_h","source")
    dst=_first(row,"id.resp_h","resp_h","destination")
    query=_first(row,"query","domain","qname")
    if not src or not dst or not query: return None
    return {
        "timestamp": _timestamp(_first(row,"ts","timestamp")),
        "source": src,
        "destination": dst,
        "protocol": str(_first(row,"proto","protocol") or "udp").lower(),
        "source_port": _int(_first(row,"id.orig_p","orig_p","source_port")),
        "destination_port": _int(_first(row,"id.resp_p","resp_p","destination_port")),
        "process": None,
        "metadata": {
            "type": "dns",
            "domain": query.rstrip("."),
            "qtype": _first(row,"qtype_name","qtype"),
            "answers": _first(row,"answers"),
            "rtt": _float(_first(row,"rtt")),
            "rejected": _first(row,"rejected"),
        },
    }


def _parse_pcap(path: Path) -> list[dict]:
    data=path.read_bytes()
    if len(data)<24: raise RuntimeError("PCAP file is truncated.")
    magic=struct.unpack_from("<I",data,0)[0]
    if magic in (0xA1B2C3D4,0xA1B23C4D): endian="<"; ns=(magic==0xA1B23C4D)
    elif magic in (0xD4C3B2A1,0x4D3CB2A1): endian=">"; ns=(magic==0x4D3CB2A1)
    else: raise RuntimeError("Unsupported PCAP magic number.")
    network=struct.unpack_from(endian+"I",data,20)[0]
    pos=24; out=[]
    while pos+16<=len(data) and len(out)<_MAX_ARTIFACTS:
        sec,usec,caplen,origlen=struct.unpack_from(endian+"IIII",data,pos); pos+=16
        if caplen>_MAX_FILE_BYTES or pos+caplen>len(data): break
        packet=data[pos:pos+caplen]; pos+=caplen
        parsed=_packet_metadata(packet,network)
        if parsed:
            ts=sec + usec/(1_000_000_000 if ns else 1_000_000)
            parsed["timestamp"]=_epoch_to_iso(ts); out.append(parsed)
    return out


def _parse_pcapng(path: Path) -> list[dict]:
    data=path.read_bytes(); pos=0; endian="<"; links={}; resolutions={}; out=[]
    while pos+12<=len(data) and len(out)<_MAX_ARTIFACTS:
        btype,blen=struct.unpack_from(endian+"II",data,pos)
        if blen<12 or pos+blen>len(data): break
        body=data[pos+8:pos+blen-4]
        if btype==0x0A0D0D0A:
            if len(body)>=4:
                bom=struct.unpack_from("<I",body,0)[0]
                endian="<" if bom==0x1A2B3C4D else ">"
        elif btype==1 and len(body)>=8:
            link_id=struct.unpack_from(endian+"H",body,0)[0]
            links[link_id]=struct.unpack_from(endian+"H",body,2)[0]
            resolutions[link_id]=1_000_000
            # Interface Description Block options: code, length, value, padded to 32 bits.
            opt=8
            while opt+4<=len(body):
                code,olen=struct.unpack_from(endian+"HH",body,opt); opt+=4
                if code==0: break
                value=body[opt:opt+olen]; opt += (olen+3)&~3
                if code==9 and value:
                    v=value[0]
                    resolutions[link_id]=(1<<v) if (v & 0x80) else (10**v)
        elif btype==6 and len(body)>=20:
            iface,hi,lo,caplen=struct.unpack_from(endian+"IIII",body,0)
            packet=body[20:20+caplen]
            parsed=_packet_metadata(packet,links.get(iface,1))
            if parsed:
                # PCAPNG timestamps depend on interface resolution. Default microseconds is used.
                ts=((hi<<32)|lo)/resolutions.get(iface, 1_000_000)
                parsed["timestamp"]=_epoch_to_iso(ts); out.append(parsed)
        pos+=blen
    return out


def _packet_metadata(packet: bytes, linktype: int) -> dict | None:
    if linktype not in (1,101): return None
    offset=14 if linktype==1 else 0
    if len(packet)<offset+20: return None
    version=packet[offset]>>4
    if version==4:
        ihl=(packet[offset]&15)*4
        if len(packet)<offset+ihl: return None
        proto=packet[offset+9]
        src=str(ipaddress.ip_address(packet[offset+12:offset+16])); dst=str(ipaddress.ip_address(packet[offset+16:offset+20]))
        l4=offset+ihl
    elif version==6:
        if len(packet)<offset+40: return None
        proto=packet[offset+6]
        src=str(ipaddress.ip_address(packet[offset+8:offset+24])); dst=str(ipaddress.ip_address(packet[offset+24:offset+40])); l4=offset+40
    else: return None
    sp=dp=None; meta={}
    if proto in (6,17) and len(packet)>=l4+4:
        sp,dp=struct.unpack_from("!HH",packet,l4)
        if proto == 17 and (sp == 53 or dp == 53):
            dns=_parse_dns(packet,l4+8)
            if dns: meta.update(dns)
        elif proto == 6 and (sp == 53 or dp == 53) and len(packet) >= l4 + 20:
            tcp_header_len=((packet[l4+12] >> 4) & 0xF) * 4
            if tcp_header_len >= 20 and len(packet) >= l4 + tcp_header_len + 12:
                dns=_parse_dns(packet,l4+tcp_header_len)
                if dns: meta.update(dns)
    return {
        "timestamp": None, "source": src, "destination": dst,
        "protocol": {6:"tcp",17:"udp",1:"icmp",58:"icmpv6"}.get(proto,str(proto)),
        "source_port": sp, "destination_port": dp, "process": None,
        "metadata": meta,
    }


def _parse_dns(packet: bytes, offset: int) -> dict:
    if len(packet)<offset+12: return {}
    flags=struct.unpack_from("!H",packet,offset+2)[0]; qd=struct.unpack_from("!H",packet,offset+4)[0]
    if not qd: return {}
    pos=offset+12; labels=[]
    for _ in range(128):
        if pos>=len(packet): return {}
        n=packet[pos]; pos+=1
        if n==0: break
        if n&0xC0:
            if pos>=len(packet): return {}
            pos+=1; break
        if n>63 or pos+n>len(packet): return {}
        labels.append(packet[pos:pos+n].decode("utf-8","replace")); pos+=n
    if pos+4>len(packet): return {}
    qtype,qclass=struct.unpack_from("!HH",packet,pos)
    return {"type":"dns","domain":".".join(labels),"qtype":_dns_qtype(qtype),"qclass":qclass,"response":bool(flags&0x8000)}


def _dns_qtype(qtype:int)->str:
    return {1:"A",28:"AAAA",5:"CNAME",15:"MX",16:"TXT",12:"PTR",6:"SOA",33:"SRV"}.get(qtype,str(qtype))


def _statistics(items:list[dict])->dict:
    ts=[x["timestamp"] for x in items if x.get("timestamp")]
    domains={x.get("metadata",{}).get("domain") for x in items if x.get("metadata",{}).get("domain")}
    return {
        "connection_count":len(items),
        "unique_sources":len({x["source"] for x in items}),
        "unique_destinations":len({x["destination"] for x in items}),
        "unique_domains":len(domains),
        "protocol_counts":{p:sum(1 for x in items if x.get("protocol")==p) for p in sorted({x.get("protocol") for x in items})},
        "first_seen":min(ts) if ts else None,
        "last_seen":max(ts) if ts else None,
    }


def _first(row,*keys):
    for k in keys:
        if k in row and row[k] not in (None,"-",""): return row[k]
    return None

def _int(v):
    try:return int(v) if v not in (None,"-","") else None
    except (ValueError,TypeError):return None

def _float(v):
    try:return float(v) if v not in (None,"-","") else None
    except (ValueError,TypeError):return None

def _timestamp(v):
    try:
        return _epoch_to_iso(float(v))
    except (ValueError,TypeError):
        return v

def _epoch_to_iso(ts:float)->str:
    return datetime.fromtimestamp(ts,tz=timezone.utc).isoformat()
