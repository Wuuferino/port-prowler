# Port Prowler

Port Prowler is a Python-powered network reconnaissance utility inspired by tools like Nmap. It focuses on fast, multi-threaded port discovery with optional TCP, UDP, and stealth SYN scanning modes, basic service detection, and light-weight OS fingerprinting heuristics.

> Warning: Only scan networks and hosts you own or have explicit permission to assess. Unauthorized port scanning may be illegal in many jurisdictions.

## Features
- TCP connect, UDP, and stealth (SYN) scanning modes
- Flexible port targeting: single values, comma-separated lists, and ranges
- Multi-threaded scanning for high throughput
- Automatic service lookups and best-effort banner grabbing on open ports
- Basic OS fingerprinting via ICMP TTL analysis
- Optional result export to disk
- Useful defaults with extensible CLI flags

## Requirements
- Python 3.9 or newer
- `scapy` (required for stealth scanning)
- Optional development tooling: `pytest`

Install runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

For local testing:

```bash
python -m pip install -r dev-requirements.txt
```

## Usage

```text
python port_prowler.py <ip> [options]

Options:
  -p / --ports           Port targets (single, comma-separated, or range). Default: 1-1024
  -tcp / --tcp           Enable TCP connect scan
  -udp / --udp           Enable UDP scan
  -s / --stealth         Enable stealth SYN scan (requires scapy + elevated privileges)
  -f / --file FILE       Write results to FILE
  --timeout SEC          Socket timeout (default 2.0)
  --workers N            Thread pool size (default 100)
  --no-service           Disable service/banner detection
  --no-os                Skip OS fingerprinting
  --banner-timeout SEC   Banner grab timeout (default 1.5)
```

### Examples

```bash
# Default scan (TCP on ports 1-1024 when no scan type specified)
python port_prowler.py 192.168.1.1

# Basic TCP scan against specific ports
python port_prowler.py 192.168.1.1 -p 22,80,443 -tcp

# UDP range scan with default ports
python port_prowler.py 10.0.0.1 -p 53-60 -udp

# Mixed TCP + stealth scan and write results to disk (stealth requires elevated privileges)
# On Windows: Run PowerShell/CMD as Administrator
# On Linux/macOS: Use sudo
python port_prowler.py 172.16.0.10 -p 20-25 -tcp -s -f scan.txt
```

### Output

```
Scanning 192.168.1.1 (tcp, stealth)...
OS Guess: Likely Windows (TTL<=128), TTL=128

[tcp]
Port 80/tcp: Open (http; Apache httpd)
Port 443/tcp: Closed

[stealth]
Port 80/tcp: Open (http; Apache httpd)
Port 443/tcp: Closed

Completed in 3.42s
```

## Stealth Scanning Notes
- The stealth (`-s`) mode performs a SYN scan using `scapy` and raw sockets.
- Administrator/root privileges are typically required to craft raw packets.
- If scapy is missing or raw sockets are unavailable, the tool will report a warning and continue with other modes.

## OS Fingerprinting
Port Prowler runs a single ICMP echo probe and interprets the TTL value to approximate the operating system family. This is a heuristic only - it can be affected by intermediate hops, firewall policies, or custom OS configurations.

## Service Detection
- Known ports are resolved to common services via `socket.getservbyport`.
- When TCP ports are reported open, Port Prowler attempts a quick banner grab to enrich the output.
- Banner detection uses short timeouts to avoid blocking the scan; not all services will emit data.

## Testing
Run the automated tests with `pytest`:

```bash
pytest
```

## Metasploitable Demo
When demonstrating against Metasploitable 2 (or similar vulnerable VMs), ensure the VM network is reachable from your host. Example workflow:

```bash
# Discover the VM's IP (adjust interface as needed)
python port_prowler.py 192.168.56.101 -p 1-1024 -tcp -udp -s -f metasploitable_scan.txt
```

Inspect the saved report and highlight interesting open ports and service banners during your presentation.

## Troubleshooting
- **Filtered results on all ports:** The target or intermediate firewall might be dropping probes. Increase `--timeout`, try stealth mode, or verify connectivity with `ping`/`traceroute`.
- **Stealth scan fails:** Confirm that `scapy` is installed and run the tool with administrative privileges.
- **OS fingerprint shows unknown:** Some hosts suppress ICMP replies; rerun without `--no-os` or try from a different network segment.

## License
This project is provided for educational purposes. Use responsibly and obey all applicable laws and policies.
