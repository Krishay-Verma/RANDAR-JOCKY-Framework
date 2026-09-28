"""
Network connections collector.

Lists current network connections (local/remote address and port,
status, and owning PID where available). Read-only.
"""

import psutil


def collect_network_connections() -> dict:
    """Return a dict with a list of current network connections."""
    connections = []

    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return {
            "connections": [],
            "count": 0,
            "error": "Access denied: run with elevated privileges to view all connections",
        }

    for conn in conns:
        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
        connections.append({
            "protocol": "tcp" if conn.type == 1 else "udp",
            "local_address": local,
            "local_port": conn.laddr.port if conn.laddr else None,
            "remote_address": remote,
            "remote_ip": conn.raddr.ip if conn.raddr else None,
            "remote_port": conn.raddr.port if conn.raddr else None,
            "status": conn.status,
            "pid": conn.pid,
        })

    return {
        "connections": connections,
        "count": len(connections),
    }