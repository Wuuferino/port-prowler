# Testing & Explanation Guide

This checklist aligns the Port Prowler implementation with the reviewer's evaluation flow. It documents how to demonstrate each behaviour and provides ready-to-use explanations for the required theory questions.

## Environment & Preparation
- **Metasploitable 2 VM**: Keep the VM unmodified. Do not change firewall rules, services, or network settings unless the reviewer explicitly requests it.
- **Tool configuration**: Use Port Prowler as delivered. Only adjust runtime flags during demonstrations.

## Concept Explanations
- **Ports in networking**: A port is a logical endpoint that allows an operating system to multiplex multiple networked services on a single IP address. Clients connect to an IP+port pair to reach the specific service listening there.
- **Importance of topology & open ports**: Knowing the network layout and which ports are exposed helps defenders reduce attack surface and monitor for unexpected services. It also helps attackers plan intrusions, so security teams must maintain visibility.
- **Purpose of port scanners (e.g., Nmap)**: Port scanners rapidly test ranges of ports to identify which services are reachable, how they respond, and sometimes what software or OS is behind them. The data informs security assessments and incident response.
- **TCP protocol in port scanning**: TCP is connection-oriented. A TCP connect scan completes (or attempts) the three-way handshake (SYN -> SYN/ACK -> ACK). A completed handshake indicates an open port; RST or timeout indicates closed or filtered. Port Prowler's `-tcp` mode uses `socket.connect_ex`, which performs this handshake.
- **UDP protocol in port scanning**: UDP is connectionless. Sending a datagram to a port yields no handshake. If an ICMP Port Unreachable arrives, the port is closed; if a response or no response is seen, it is considered open or filtered. Port Prowler's `-udp` mode sends an empty datagram and waits for a reply or timeout.
- **Stealth scan technique**: Port Prowler's stealth mode is a SYN scan using Scapy. It sends a SYN packet and inspects the reply. SYN/ACK implies open (followed by an RST we send to avoid completing the handshake). RST/ACK implies closed. No response implies filtered. This minimizes logging compared to full TCP connects.
- **Differences between TCP, UDP, and stealth scans**: TCP connect performs full handshakes, so it is reliable but noisier. UDP relies on lack of replies or ICMP errors and is slower to confirm state changes. Stealth (SYN) scans collect the same open or closed data as TCP connects but without finishing the handshake, reducing detection likelihood.

## CLI Behaviour Checks
1. **Help text**  
   - Command: `python port_prowler.py --help`  
   - Expected: Displays all flags (`-p`, `-tcp`, `-udp`, `-s`, `-f`, `--timeout`, `--workers`, `--no-service`, `--no-os`, `--banner-timeout`).

2. **Port parsing**  
   - Single port: `python port_prowler.py <ip> -p 80 -tcp`  
   - Multiple ports: `python port_prowler.py <ip> -p 80,443 -tcp`  
   - Range: `python port_prowler.py <ip> -p 1-1000 -tcp`  
   - Validation covered by `parse_ports`; tests in `tests/test_port_utils.py`.

3. **Invalid arguments**  
   - Example: `python port_prowler.py <ip> -p`  
   - Argparse raises an error and prints usage automatically.

4. **Default behaviour**  
   - Command: `python port_prowler.py <ip>`  
   - Result: Defaults to TCP scan on ports 1-1024. Output shown in terminal.

5. **Missing `-p` value**  
   - Command: `python port_prowler.py <ip> -p`  
   - Argparse error: "argument -p/--ports: expected one argument", usage shown.

6. **Protocol defaults**  
   - `python port_prowler.py <ip> -p 80` (no protocol flags) runs a TCP connect scan by design.

7. **Multiple protocols simultaneously**  
   - `python port_prowler.py <ip> -p 80 -tcp -udp` runs both scans. Output grouped by protocol.

8. **TCP scan**  
   - `python port_prowler.py <ip> -p 80,443,8080 -tcp`  
   - Collect the report and compare to `nmap -p 80,443,8080 -v <ip>`.

9. **UDP scan**  
   - `python port_prowler.py <ip> -p 80,443,8080 -udp`  
   - Compare to `nmap -p 80,443,8080 -v -sU <ip>`.

10. **Stealth scan**  
    - Required: Scapy installed and elevated privileges.  
    - Command: `python port_prowler.py <ip> -p 80,443,8080 -s`  
    - Compare to `nmap -p 80,443,8080 -v -sS <ip>`.

11. **Firewall (UFW) scenarios**  
    - Enable UFW on Metasploitable (`sudo ufw enable`).  
    - Repeat TCP scan and stealth scan comparisons with Nmap as above.  
    - Document any variances (timeouts vs. filtered).

12. **Output format**  
    - Terminal displays grouped sections `[tcp]`, `[udp]`, `[stealth]`.  
    - Matches example structure in README.

13. **Saving results**  
    - `python port_prowler.py <ip> -p 80 -tcp -f scan_results.txt`  
    - Rerun to confirm versioning: creates `scan_results1.txt`, then `scan_results2.txt`, etc.

14. **Missing filename with `-f`**  
    - `python port_prowler.py <ip> -p 80 -tcp -f`  
    - Argparse error: "argument -f/--file: expected one argument".

15. **Service detection**  
    - Open ports show `service` field via `socket.getservbyport` or banner heuristics.  
    - Example: SSH banner containing `OpenSSH` yields an `ssh` service label.

16. **OS detection**  
    - Default behaviour runs a single ping and reports TTL-based guess.  
    - Works best when ICMP replies are allowed; otherwise states "Unknown".

17. **Multithreading**  
    - TCP and UDP jobs execute via `ThreadPoolExecutor` with configurable worker count.  
    - Handles closed or filtered ports gracefully; each result includes status and reason.

18. **Extra features implemented**  
    - Service detection with banner grabbing.  
    - OS fingerprinting via TTL heuristics.  
    - Stealth SYN scan support.  
    - Threaded scanning for performance.

## Demonstration Script (Metasploitable 2)
1. Verify tool help.  
2. Run baseline TCP, UDP, and stealth scans (with root when needed) on a few ports.  
3. Compare each scan mode with matching Nmap commands, noting parity or explaining differences.  
4. Enable UFW, repeat TCP and stealth comparisons, discuss filtered results.  
5. Showcase saving output to a file and default behaviour.  
6. Answer theory questions using the explanations above.  
7. Highlight service and OS detection in the output.  
8. Note multithreading benefits when scanning wider ranges (rapid completion).

This document, alongside the README, should equip the student to satisfy the review checks and verbal questions.
