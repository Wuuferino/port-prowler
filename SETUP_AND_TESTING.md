# Port Prowler Setup & Testing Guide

This guide walks through preparing your environment, validating the install, and exercising the main Port Prowler features. Use it as a checklist and adapt the commands to your operating system and Python setup.

## 1. Prepare Your Environment
- Confirm you have Python 3.10 or newer.
- (Optional but recommended) create a virtual environment:
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1  # PowerShell
  # OR
  source .venv/bin/activate     # Bash
  ```
- Install dependencies:
  ```powershell
  pip install -r requirements.txt
  ```
- If you plan to run SYN stealth scans, make sure you can start your terminal session with administrator/root privileges.

## 2. Find Your Target Host
Replace `<TARGET_IP>` in later examples with the host you plan to scan.

**Metasploitable 2 VM**
- Log into the VM console (`msfadmin/msfadmin` by default).
- Run `ifconfig` or `ip addr show` and note the IP under `inet`.

**From the host machine**
- Run `arp -a` (Windows) or `arp -n` (Linux/macOS) to view recently seen devices.
- If needed, sweep your local subnet with an external tool such as `nmap -sn 192.168.1.0/24` or use Port Prowler to scan in ranges until you locate the VM.

## 3. Quick Health Checks
Run these from the project root. Swap in `python3` if that is how Python is invoked on your system.

```powershell
python -m pytest tests -v
python port_prowler.py --help
```

You should see the test suite pass and the CLI help text render without errors.

## 4. Baseline Network Checks

```powershell
ping <TARGET_IP>
```
Use this to confirm the host responds before you run scans. Timeouts can indicate the VM is powered off or on a different network segment.

## 5. Scan Scenarios

Showcase whichever examples demonstrate the feature set you care about.

```powershell
# Default TCP scan (ports 1-1024)
python port_prowler.py <TARGET_IP>

# Specific ports over TCP
python port_prowler.py <TARGET_IP> -p 21,22,80,443 -tcp

# Port range
python port_prowler.py <TARGET_IP> -p 20-30 -tcp

# UDP scan
python port_prowler.py <TARGET_IP> -p 53,67,123 -udp

# Save results to a file
python port_prowler.py <TARGET_IP> -p 1-100 -tcp -f scan_results.txt

# Demonstrate file versioning (run multiple times)
python port_prowler.py <TARGET_IP> -p 80 -tcp -f demo.txt

# Combined TCP and UDP in one run
python port_prowler.py <TARGET_IP> -p 80,443 -tcp -udp
```

### Stealth (SYN) Scan
Requires elevated privileges because it uses raw sockets.

```powershell
# Start your terminal as Administrator (Windows) or with sudo (Linux/macOS) first
python port_prowler.py <TARGET_IP> -p 80,443,8080 -s
```

## 6. Optional Comparisons and Deep Dives

**Compare with Nmap**
```powershell
nmap -p 21,22,80,443 <TARGET_IP>
python port_prowler.py <TARGET_IP> -p 21,22,80,443 -tcp
```

Discuss similarities in detected services, timing, and banner information.

**Firewall Experiments (Metasploitable 2)**
```powershell
ssh msfadmin@<TARGET_IP>   # password: msfadmin
sudo ufw enable
sudo ufw status
```
Re-run scans and observe how filtered ports appear. Disable the firewall afterwards:
```bash
sudo ufw disable
```

## 7. Troubleshooting Reference

- **Cannot find the VM IP**  
  Check the VM console (`ifconfig` or `ip addr show`) and verify virtual network settings (NAT vs bridged).

- **Scans time out**  
  Ensure the VM is running and reachable (`ping <TARGET_IP>`). Firewalls on the host or VM may need adjustments.

- **Stealth scan fails immediately**  
  Confirm you launched the terminal with elevated privileges and that Scapy is installed (`python -c "import scapy; print(scapy.__version__)"`).

- **Missing dependencies**  
  Re-run `pip install -r requirements.txt`. For manual installs, `pip install scapy` is required for SYN scans.

- **No banner information**  
  Some services close connections quickly. Increase the banner timeout, for example:  
  `python port_prowler.py <TARGET_IP> -p 80 -tcp --banner-timeout 3.0`

## 8. Demo Checklist

- Help text displays correctly.
- Default TCP scan completes and lists open ports.
- Targeted TCP scan highlights services of interest (FTP/SSH/HTTP, etc.).
- UDP scan runs and explains how to interpret “open|filtered”.
- File output demonstrates versioning.
- Stealth scan succeeds from an elevated session (if applicable).
- Optional: show a comparison with Nmap and talk through differences.

You now have everything you need to validate the setup and walk reviewers through a clean, human-readable test flow. Customize the examples to match your own environment and tools.
