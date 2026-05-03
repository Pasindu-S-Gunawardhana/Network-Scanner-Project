#!/usr/bin/env python3
"""
scanner.py
Multi-threaded TCP port scanner for CIDR subnets.
Features:
- CIDR parsing via ipaddress
- TCP connect scans using socket with configurable timeout
- High-performance scanning using ThreadPoolExecutor
- CLI via argparse (targets, ports, threads, timeout, output)
- Graceful error handling and keyboard interrupt support
- Optional CSV output
"""

import argparse
import ipaddress
import socket
import sys
import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Tuple, Iterable

DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 200
DEFAULT_PORTS = "1-1024"


def parse_ports(ports_str: str) -> List[int]:
    """Parse port range string like '22,80,443,8000-8100' into a sorted list of ports."""
    ports = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            start = int(start)
            end = int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def generate_targets(target: str) -> Iterable[str]:
    """Yield IP addresses from a target which may be a single IP or CIDR block."""
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            for ip in net.hosts():
                yield str(ip)
        else:
            # single IP or hostname
            # try to resolve hostname to IP
            try:
                resolved = socket.gethostbyname(target)
                yield resolved
            except socket.gaierror:
                # if it's already an IP-like string, yield it
                yield target
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid target '{target}': {e}")


def scan_port(ip: str, port: int, timeout: float) -> Tuple[str, int, bool, str]:
    """
    Attempt a TCP connect to (ip, port).
    Returns tuple: (ip, port, is_open, banner_or_error)
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                # Optionally attempt a small banner grab
                banner = ""
                try:
                    s.settimeout(0.5)
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                return (ip, port, True, banner)
            else:
                return (ip, port, False, "")
    except Exception as e:
        return (ip, port, False, f"error:{e}")


def worker_tasks(targets: Iterable[str], ports: List[int], timeout: float, threads: int, progress: bool = True):
    """
    Submit scanning tasks to ThreadPoolExecutor and yield results as they complete.
    """
    total_tasks = 0
    for _ in targets:
        # We can't rewind the generator; caller should pass a list if needed.
        total_tasks = None
        break

    # If targets is not a list, convert to list to allow multiple passes
    if not isinstance(targets, list):
        targets = list(targets)

    total_tasks = len(targets) * len(ports)
    submitted = 0
    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_task = {}
        for ip in targets:
            for port in ports:
                future = executor.submit(scan_port, ip, port, timeout)
                future_to_task[future] = (ip, port)
                submitted += 1

        completed = 0
        for future in as_completed(future_to_task):
            completed += 1
            try:
                res = future.result()
            except Exception as e:
                ip, port = future_to_task[future]
                res = (ip, port, False, f"exception:{e}")
            if progress:
                elapsed = (datetime.now() - start_time).total_seconds()
                print(f"[{completed}/{total_tasks}] {res[0]}:{res[1]} -> {'OPEN' if res[2] else 'closed'}", end="\r", flush=True)
            yield res

    if progress:
        print()  # newline after progress


def save_csv(results: List[Tuple[str, int, bool, str]], filename: str):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "port", "open", "banner"])
        for ip, port, is_open, banner in results:
            writer.writerow([ip, port, "yes" if is_open else "no", banner])


def save_json(results: List[Tuple[str, int, bool, str]], filename: str):
    out = []
    for ip, port, is_open, banner in results:
        out.append({"ip": ip, "port": port, "open": is_open, "banner": banner})
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Multi-threaded TCP port scanner for CIDR subnets and single hosts."
    )
    parser.add_argument("target", help="Target IP or CIDR block (e.g., 192.168.1.0/24 or 10.0.0.5)")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS,
                        help="Ports to scan. Examples: 22,80,443 or 1-1024 or combination 22,80,8000-8100")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of worker threads (default {DEFAULT_THREADS})")
    parser.add_argument("-T", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Socket timeout in seconds (default {DEFAULT_TIMEOUT})")
    parser.add_argument("-o", "--output", help="Save results to CSV or JSON. Use .csv or .json extension.")
    parser.add_argument("--no-progress", action="store_true", help="Disable progress printing")
    parser.add_argument("--version", action="version", version="Network Scanner 1.0")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        ports = parse_ports(args.ports)
    except Exception as e:
        print(f"Invalid ports specification: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        targets = list(generate_targets(args.target))
    except argparse.ArgumentTypeError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

    if not targets:
        print("No targets resolved. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {len(targets)} target(s) with {len(ports)} port(s) using {args.threads} threads and timeout {args.timeout}s")
    results = []
    try:
        for ip, port, is_open, banner in worker_tasks(targets, ports, args.timeout, args.threads, progress=not args.no_progress):
            if is_open:
                print(f"[OPEN] {ip}:{port} {('- ' + banner) if banner else ''}")
            results.append((ip, port, is_open, banner))
    except KeyboardInterrupt:
        print("\nScan interrupted by user. Saving partial results if requested...")

    if args.output:
        if args.output.lower().endswith(".csv"):
            save_csv(results, args.output)
            print(f"Results saved to {args.output}")
        elif args.output.lower().endswith(".json"):
            save_json(results, args.output)
            print(f"Results saved to {args.output}")
        else:
            print("Unsupported output format. Use .csv or .json", file=sys.stderr)

    # Print summary
    open_count = sum(1 for r in results if r[2])
    total = len(results)
    print(f"Scan complete. {open_count} open ports found out of {total} scanned.")

if __name__ == "__main__":
    main()
