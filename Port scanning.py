#!/usr/bin/env python3
"""
Port scanner (Python) — TCP connect scan + optional service banners

This file is divided into clear sections so you can reuse parts in other projects.
Save as `portscanner_divided_sections.py` and run: python3 portscanner_divided_sections.py --help

Ethical reminder: scan only systems you own or have explicit permission to test.
"""

# -----------------------------
# Section 1 — Imports & Constants
# -----------------------------
import socket
import argparse
import concurrent.futures
import time
import csv
import json
from typing import Optional, Tuple, List

# Default list of common ports (used when -p is omitted)
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,111,123,135,139,143,161,162,389,
    443,445,465,514,587,631,993,995,1433,1521,1723,3306,3389,5900,8080
]

# Gentle probes to elicit banners for select services
SERVICE_PROBES = {
    21: b"QUIT\r\n",
    22: None,  # SSH often sends banner on connect
    23: None,  # Telnet
    25: b"HELO example.com\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"QUIT\r\n",
    143: b". LOGOUT\r\n",
}

# -----------------------------
# Section 2 — Argument Parsing
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="TCP port scanner with optional banners (divided sections)")
    parser.add_argument("target", help="Target hostname or IP")
    parser.add_argument("-p", "--ports", help="Ports (comma separated) or ranges, e.g. 22,80,8000-8100. Default: common ports")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connect/recv timeout in seconds (default 1.0)")
    parser.add_argument("--banner", action="store_true", help="Attempt to read service banners / send gentle probes")
    parser.add_argument("--slowdown", type=float, default=0.0, help="Optional delay between scans per thread (seconds)")
    parser.add_argument("--json", type=str, help="Save results to JSON file")
    parser.add_argument("--csv", type=str, help="Save results to CSV file")
    return parser

# -----------------------------
# Section 3 — Port Parsing Utils
# -----------------------------

def parse_ports(port_str: Optional[str]) -> List[int]:
    if not port_str:
        return COMMON_PORTS
    ports = set()
    parts = port_str.split(',')
    for p in parts:
        p = p.strip()
        if '-' in p:
            a, b = p.split('-', 1)
            a = int(a); b = int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(p))
    return sorted([pt for pt in ports if 1 <= pt <= 65535])

# -----------------------------
# Section 4 — Network Helpers
# -----------------------------

def resolve_target(target: str) -> str:
    """Resolve a hostname to an IPv4 address (raises ValueError on failure)."""
    try:
        return socket.gethostbyname(target)
    except Exception as e:
        raise ValueError(f"Unable to resolve target '{target}': {e}")

# -----------------------------
# Section 5 — Banner Grabbing
# -----------------------------

def grab_banner(conn: socket.socket, port: int, timeout: float) -> str:
    """Try passive receive and then send a gentle probe when available."""
    conn.settimeout(timeout)
    banner = b""
    try:
        # passive recv (some services announce themselves on connect)
        try:
            part = conn.recv(1024)
            if part:
                banner += part
        except socket.timeout:
            pass
        probe = SERVICE_PROBES.get(port)
        if probe is not None:
            try:
                conn.sendall(probe)
            except Exception:
                pass
            try:
                more = conn.recv(2048)
                if more:
                    banner += more
            except socket.timeout:
                pass
    except Exception:
        pass

    try:
        return banner.decode('utf-8', errors='replace').strip()
    except Exception:
        return repr(banner)

# -----------------------------
# Section 6 — Port Scanning Logic
# -----------------------------

def scan_port(ip: str, port: int, timeout: float, want_banner: bool) -> Optional[Tuple[int, str]]:
    """Attempt to connect to a target TCP port. Return (port, banner_or_open) if open else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
    except (socket.timeout, ConnectionRefusedError, OSError):
        s.close()
        return None
    except Exception:
        s.close()
        return None

    result = ""
    if want_banner:
        try:
            result = grab_banner(s, port, timeout)
        except Exception:
            result = ""
    s.close()
    return (port, result if result else "open")

# -----------------------------
# Section 7 — Runner / Concurrency
# -----------------------------

def run_scan(ip: str, ports: List[int], threads: int, timeout: float, want_banner: bool, slowdown: float=0.0) -> List[Tuple[int, str]]:
    """Run threaded scans and return list of open ports with banners (if any)."""
    open_ports: List[Tuple[int, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(2, threads)) as exe:
        futures = {exe.submit(scan_port, ip, port, timeout, want_banner): port for port in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                open_ports.append(res)
            if slowdown:
                time.sleep(slowdown)
    return sorted(open_ports, key=lambda x: x[0])

# -----------------------------
# Section 8 — Output / Persistence
# -----------------------------

def save_json(results: List[Tuple[int, str]], filename: str, target: str, ip: str) -> None:
    payload = {
        'target': target,
        'ip': ip,
        'scan_time': int(time.time()),
        'results': [{'port': p, 'banner': b} for p, b in results]
    }
    with open(filename, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, indent=2)


def save_csv(results: List[Tuple[int, str]], filename: str, target: str, ip: str) -> None:
    with open(filename, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow(['target', 'ip', 'port', 'banner'])
        for p, b in results:
            writer.writerow([target, ip, p, b])

# -----------------------------
# Section 9 — CLI Main
# -----------------------------

def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        ip = resolve_target(args.target)
    except ValueError as e:
        print(e)
        return

    ports = parse_ports(args.ports)
    print(f"Scanning {args.target} ({ip}) — {len(ports)} ports — threads={args.threads} timeout={args.timeout}")
    start = time.time()

    results = run_scan(ip, ports, args.threads, args.timeout, args.banner, args.slowdown)

    elapsed = time.time() - start
    print(f"\nScan finished in {elapsed:.2f}s. Open ports: {len(results)}\n")
    if results:
        print("Summary:")
        for p, b in results:
            print(f"  - {p:5d}/tcp  {b}")

    if args.json:
        try:
            save_json(results, args.json, args.target, ip)
            print(f"Results saved to JSON: {args.json}")
        except Exception as e:
            print(f"Failed to save JSON: {e}")

    if args.csv:
        try:
            save_csv(results, args.csv, args.target, ip)
            print(f"Results saved to CSV: {args.csv}")
        except Exception as e:
            print(f"Failed to save CSV: {e}")

# -----------------------------
# Section 10 — Usage Examples & Improvements (comments)
# -----------------------------
# Example usage:
#   python3 portscanner_divided_sections.py example.com --banner
#   python3 portscanner_divided_sections.py 192.168.1.5 -p 1-1024 -t 200 --timeout 0.5 --json out.json
#
# Improvements you might add:
# - Add UDP scanning (requires different approach and more caution).
# - Implement SYN (half-open) scans using raw sockets or scapy (needs root/admin).
# - Add adaptive retries and exponential backoff for flaky networks.
# - Create a small CLI progress indicator or GUI.
# - Integrate a small port->service name mapping for nicer output.
#
# Legal/ethical reminder:
# Only run scans against systems you own or have authorization to test. Unauthorised scanning may be illegal and/or trigger security responses.

if __name__ == "__main__":
    main()
