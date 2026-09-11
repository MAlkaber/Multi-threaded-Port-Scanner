#!/usr/bin/env python3
"""
Multi-threaded Port Scanner
=============================
Scans one or more hosts across one or more ports concurrently, using
concurrent.futures.ThreadPoolExecutor. Builds directly on the ideas from
Project 01 (TCP connect scanning) and Project 02 (host expansion) - this
repo is self-contained (each project repo stands alone), so both are
reimplemented here rather than imported across repos.

Project 03 of a pentest/red-team learning portfolio.
Read README.md first for the concept walkthrough.

Usage:
    python3 threaded_scanner.py <targets> <ports> [--threads N] [--timeout SECONDS]

Examples:
    python3 threaded_scanner.py scanme.nmap.org 1-1024
    python3 threaded_scanner.py 192.168.1.0/24 22,80,443 --threads 200
"""

import argparse
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def expand_targets(target_spec: str) -> list[str]:
    """
    Expand a target spec into a list of host strings.
    Accepts a CIDR block, an IP range ("start-end"), a single IP, or a
    plain hostname (returned as-is - hostnames get resolved later by
    the socket layer, not here).
    """
    if "/" in target_spec:
        network = ipaddress.ip_network(target_spec, strict=False)
        return [str(ip) for ip in network.hosts()]

    if "-" in target_spec and _looks_like_ip(target_spec.split("-")[0]):
        start_str, end_str = target_spec.split("-", 1)
        start = ipaddress.ip_address(start_str.strip())
        end = ipaddress.ip_address(end_str.strip())
        if int(start) > int(end):
            start, end = end, start
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]

    return [target_spec]


def parse_ports(port_spec: str) -> list[int]:
    """Same port-spec parser as Project 01: '80', '22,80,443', '20-25', or a mix."""
    ports: set[int] = set()
    for chunk in port_spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    for p in ports:
        if not (0 < p <= 65535):
            raise ValueError(f"Port {p} is out of range (1-65535)")
    return sorted(ports)


def check_port(host: str, port: int, timeout: float) -> tuple[str, int, bool]:
    """
    One connect() attempt - identical logic to Project 01's check_port(),
    just returning (host, port) alongside the result. That's necessary
    here because results will arrive back from the thread pool in
    whatever order finishes first, not the order jobs were submitted -
    without echoing the host/port back, we couldn't tell which job a
    given result belongs to.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result_code = sock.connect_ex((host, port))
        is_open = result_code == 0
    except socket.gaierror:
        is_open = False
    finally:
        sock.close()
    return host, port, is_open


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan multiple hosts/ports concurrently with a thread pool."
    )
    parser.add_argument("targets", help="CIDR block, IP range, single IP, or hostname")
    parser.add_argument("ports", help="Port, comma list, and/or range, e.g. '1-1024'")
    parser.add_argument(
        "--threads", type=int, default=100, help="Worker threads (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-connection timeout in seconds (default: 1.0)",
    )
    args = parser.parse_args()

    try:
        hosts = expand_targets(args.targets)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    jobs = [(h, p) for h in hosts for p in ports]
    print(
        f"Scanning {len(hosts)} host(s) x {len(ports)} port(s) = "
        f"{len(jobs)} checks, {args.threads} threads\n"
    )

    start_time = time.perf_counter()
    open_results = []

    # ThreadPoolExecutor keeps a fixed pool of worker threads and hands
    # each submitted job to whichever worker is free. Because these jobs
    # spend nearly all their time *waiting* on the network (I/O-bound),
    # Python's GIL is not a bottleneck here - while one thread is blocked
    # inside connect_ex() waiting for a reply, the GIL is released and
    # another thread runs. This is why threading works well for network
    # scanning even though it wouldn't speed up CPU-bound work (like
    # hashing) - that's what multiprocessing is for instead.
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(check_port, h, p, args.timeout) for h, p in jobs]
        # as_completed() yields each future as soon as IT finishes, not
        # in submission order - that's what makes this fast: we print
        # open ports the moment they're found instead of waiting for
        # every single job to finish first.
        for future in as_completed(futures):
            host, port, is_open = future.result()
            if is_open:
                open_results.append((host, port))
                print(f"[+] {host:<15} {port:>5}/tcp OPEN")

    elapsed = time.perf_counter() - start_time
    open_results.sort()
    print(f"\n[+] {len(open_results)} open port(s) found across {len(jobs)} checks in {elapsed:.2f}s")


if __name__ == "__main__":
    main()
