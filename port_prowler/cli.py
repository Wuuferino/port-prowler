from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import Iterable, List
from .port_utils import parse_ports
from .scanner import PortScanner, PortStatus, ScanReport, ScanResult, ScanType

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='port_prowler.py', usage='port_prowler.py <ip> [options]', description='Port Prowler - versatile port scanning utility.')
    parser.add_argument('target', help='Target IP address or hostname.')
    parser.add_argument('-p', '--ports', default='1-1024', help='Ports to scan (single, comma-separated, or range). Default: 1-1024.')
    parser.add_argument('-tcp', '--tcp', action='store_true', help='Perform a TCP connect scan.')
    parser.add_argument('-udp', '--udp', action='store_true', help='Perform a UDP scan.')
    parser.add_argument('-s', '--stealth', action='store_true', help='Perform a stealth SYN scan.')
    parser.add_argument('-f', '--file', metavar='FILENAME', help='Save the scan output to the specified file.')
    parser.add_argument('--timeout', type=float, default=2.0, help='Socket timeout (seconds). Default: 2.0s.')
    parser.add_argument('--workers', type=int, default=100, help='Maximum number of concurrent workers. Default: 100.')
    parser.add_argument('--no-service', action='store_true', help='Disable service/banner detection on open ports.')
    parser.add_argument('--no-os', action='store_true', help='Skip OS fingerprinting via ICMP echo.')
    parser.add_argument('--banner-timeout', type=float, default=1.5, help='Timeout for banner grabbing attempts (seconds).')
    return parser

def parse_scan_types(args: argparse.Namespace) -> List[ScanType]:
    scan_types: List[ScanType] = []
    if args.tcp:
        scan_types.append(ScanType.TCP)
    if args.udp:
        scan_types.append(ScanType.UDP)
    if args.stealth:
        scan_types.append(ScanType.STEALTH)
    if not scan_types:
        scan_types.append(ScanType.TCP)
    return scan_types

def format_report(report: ScanReport) -> str:
    lines: List[str] = []
    scan_modes = ', '.join((scan_type.label() for scan_type in report.scan_types))
    lines.append(f'Scanning {report.target} ({scan_modes})...')
    if report.os_fingerprint:
        ttl_info = f', TTL={report.os_fingerprint.ttl}' if report.os_fingerprint.ttl is not None else ''
        lines.append(f'OS Guess: {report.os_fingerprint.guess}{ttl_info}')
    if report.errors:
        lines.extend((f'Warning: {err}' for err in report.errors))
    grouped = _group_results(report.results)
    for scan_type, results in grouped.items():
        lines.append(f'\n[{scan_type}]')
        for result in sorted(results, key=lambda r: r.port):
            line = _format_result_line(result)
            lines.append(line)
    lines.append(f'\nCompleted in {report.duration:.2f}s')
    return '\n'.join(lines)

def _group_results(results: Iterable[ScanResult]) -> dict:
    grouped: dict[str, List[ScanResult]] = {}
    for result in results:
        grouped.setdefault(result.scan_type.label(), []).append(result)
    return grouped

def _format_result_line(result: ScanResult) -> str:
    status = result.status.value
    detail_parts: List[str] = []
    if result.service:
        detail_parts.append(result.service)
    if result.banner:
        detail_parts.append(result.banner[:80])
    details = f" ({'; '.join(detail_parts)})" if detail_parts else ''
    return f'Port {result.port}/{result.protocol}: {status}{details}'

def write_output(output: str, filename: str) -> str:
    """
    Write output to a file, automatically versioning if the file exists.
    Returns the actual filename used (may be versioned).
    """
    path = Path(filename).expanduser()
    
    # If file exists, create versioned filename
    if path.exists():
        base = path.stem
        ext = path.suffix
        counter = 1
        while True:
            new_path = path.parent / f"{base}{counter}{ext}"
            if not new_path.exists():
                path = new_path
                break
            counter += 1
    
    path.write_text(output, encoding='utf-8')
    return str(path)

def main(argv: List[str] | None=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))
    scan_types = parse_scan_types(args)
    scanner = PortScanner(target=args.target, ports=ports, timeout=args.timeout, workers=args.workers, service_detection=not args.no_service, banner_timeout=args.banner_timeout, os_detection=not args.no_os)
    try:
        report = scanner.scan(scan_types)
    except KeyboardInterrupt:
        print('\nScan interrupted by user.', file=sys.stderr)
        return 130
    output = format_report(report)
    print(output)
    if args.file:
        actual_filename = write_output(output, args.file)
        print(f'Result written to file: {actual_filename}')
    return 0
if __name__ == '__main__':
    sys.exit(main())
