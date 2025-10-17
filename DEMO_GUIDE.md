# Port Prowler Demo Guide

Use this walkthrough when you need to show Port Prowler in action. Tweak the commands to match your environment and target host.

## Before You Start
- Activate your virtual environment if you use one.
- Install dependencies with `pip install -r requirements.txt` when needed.
- Identify the host you plan to scan. Replace `<TARGET_IP>` in the examples with that address (for Metasploitable 2 it is usually a local IP such as `192.168.x.x`).

Run the commands from the project root so they can locate `port_prowler.py`. Swap in `python3` if that is how Python is invoked on your system.

## Core Demo Commands

1. **Show Help**
   ```powershell
   python port_prowler.py --help
   ```

2. **Default TCP Scan (ports 1-1024)**
   ```powershell
   python port_prowler.py <TARGET_IP>
   ```

3. **Quick Scan of Common Services**
   ```powershell
   python port_prowler.py <TARGET_IP> -p 21,22,80,443 -tcp
   ```

4. **Scan a Port Range**
   ```powershell
   python port_prowler.py <TARGET_IP> -p 20-25 -tcp
   ```

5. **UDP Scan**
   ```powershell
   python port_prowler.py <TARGET_IP> -p 53,67,68 -udp
   ```

6. **Save Results to a File**
   ```powershell
   python port_prowler.py <TARGET_IP> -p 1-100 -tcp -f scan_results.txt
   ```

7. **Show File Versioning**
   ```powershell
   # Run this command a few times to demonstrate automatic file versioning
   python port_prowler.py <TARGET_IP> -p 80 -tcp -f demo.txt
   ```

8. **Scan Multiple Protocols in One Run**
   ```powershell
   python port_prowler.py <TARGET_IP> -p 80,443 -tcp -udp
   ```

9. **Full Demo Scan**
   ```powershell
   python port_prowler.py <TARGET_IP> -p 1-1024 -tcp -f full_scan.txt
   ```

10. **SYN Stealth Scan (Requires Elevated Privileges)**
    ```powershell
    # Start your terminal or PowerShell session with administrator/root rights first
    python port_prowler.py <TARGET_IP> -p 80,443,8080 -s
    ```

## Quick Test Suite

Run unit tests whenever you want to highlight code quality or confirm a clean setup:
```powershell
python -m pytest tests -v
```

## Expected Services on a Metasploitable 2 Target

If you are working against Metasploitable 2, point out these common services:
- Port 21 (FTP)
- Port 22 (SSH)
- Port 23 (Telnet)
- Port 25 (SMTP)
- Port 53 (DNS)
- Port 80 (HTTP)
- Ports 139/445 (NetBIOS/SMB)
- Port 3306 (MySQL)
- Port 5432 (PostgreSQL)
- Port 8180 (Tomcat)

Use the scan results to show banner grabbing and protocol details.

## Optional Comparison with Nmap

If you have Nmap handy, a quick comparison helps underline accuracy:
```powershell
nmap -p 21,22,80,443 <TARGET_IP>
python port_prowler.py <TARGET_IP> -p 21,22,80,443 -tcp
```
Talk through timing, service detection, and any differences you spot.

## Talking Points While Presenting
- Service detection: shows friendly names and captures banners when available.
- OS hints: uses ICMP responses and TTL values to guess the platform.
- Concurrency: multi-threaded scanning keeps runtime short on small ranges.
- File handling: automatic file versioning preserves previous outputs.
- Scan flexibility: TCP, UDP, and SYN stealth modes are all under one interface.

Wrap up by reminding reviewers to swap in their own Python executable or paths if their setup differs.
