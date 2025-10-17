from __future__ import annotations
import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterable, List, Optional
from .os_detection import OSFingerprint, probe_ttl

class ScanType(Enum):
    TCP = auto()
    UDP = auto()
    STEALTH = auto()

    def label(self) -> str:
        return {ScanType.TCP: 'tcp', ScanType.UDP: 'udp', ScanType.STEALTH: 'stealth'}[self]

class PortStatus(Enum):
    OPEN = 'Open'
    CLOSED = 'Closed'
    FILTERED = 'Filtered'
    UNKNOWN = 'Unknown'
    ERROR = 'Error'

@dataclass
class ScanResult:
    port: int
    protocol: str
    scan_type: ScanType
    status: PortStatus
    latency: Optional[float] = None
    service: Optional[str] = None
    banner: Optional[str] = None
    reason: Optional[str] = None
    error: Optional[str] = None

    def display_name(self) -> str:
        return f'{self.port}/{self.protocol}'

@dataclass
class ScanReport:
    target: str
    ports: List[int]
    scan_types: List[ScanType]
    duration: float
    results: List[ScanResult]
    os_fingerprint: Optional[OSFingerprint] = None
    errors: List[str] = field(default_factory=list)

class PortScanner:

    def __init__(self, target: str, ports: List[int], timeout: float=2.0, workers: int=100, service_detection: bool=True, banner_timeout: float=1.5, os_detection: bool=True) -> None:
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.workers = max(1, workers)
        self.service_detection = service_detection
        self.banner_timeout = banner_timeout
        self.os_detection = os_detection

    def scan(self, scan_types: Iterable[ScanType]) -> ScanReport:
        scan_types = list(scan_types)
        results: List[ScanResult] = []
        errors: List[str] = []
        os_fp: Optional[OSFingerprint] = None
        start_time = time.perf_counter()
        if self.os_detection:
            os_fp = probe_ttl(self.target)
        for scan_type in scan_types:
            if scan_type == ScanType.STEALTH:
                try:
                    results.extend(self._run_stealth_scan())
                except RuntimeError as exc:
                    errors.append(str(exc))
            else:
                results.extend(self._run_concurrent_scan(scan_type))
        duration = time.perf_counter() - start_time
        return ScanReport(target=self.target, ports=self.ports, scan_types=scan_types, duration=duration, results=results, os_fingerprint=os_fp, errors=errors)

    def _run_concurrent_scan(self, scan_type: ScanType) -> List[ScanResult]:
        worker = {ScanType.TCP: self._scan_tcp, ScanType.UDP: self._scan_udp}[scan_type]
        results: List[ScanResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_map = {executor.submit(worker, port): port for port in self.ports}
            for future in as_completed(future_map):
                port = future_map[future]
                try:
                    result = future.result()
                    self._annotate_service_if_needed(result)
                    results.append(result)
                except Exception as exc:
                    results.append(ScanResult(port=port, protocol='tcp' if scan_type == ScanType.TCP else 'udp', scan_type=scan_type, status=PortStatus.ERROR, reason='Unhandled exception during scan', error=str(exc)))
        return results

    def _run_stealth_scan(self) -> List[ScanResult]:
        results: List[ScanResult] = []
        for port in self.ports:
            result = self._scan_stealth(port)
            if result.status == PortStatus.OPEN:
                self._annotate_service_if_needed(result)
            results.append(result)
        return results

    def _scan_tcp(self, port: int) -> ScanResult:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        status = PortStatus.UNKNOWN
        reason = None
        try:
            result = sock.connect_ex((self.target, port))
            latency = time.perf_counter() - start
            if result == 0:
                status = PortStatus.OPEN
                banner = self._try_recv_banner(sock)
                return ScanResult(port=port, protocol='tcp', scan_type=ScanType.TCP, status=status, latency=latency, banner=banner, reason='TCP connect succeeded')
            if result in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, getattr(errno, 'WSAECONNREFUSED', 10061), getattr(errno, 'WSAEHOSTUNREACH', 10065)}:
                status = PortStatus.CLOSED
                reason = f'connect_ex returned error {result}'
            else:
                status = PortStatus.FILTERED
                reason = f'connect_ex returned error {result}'
            return ScanResult(port=port, protocol='tcp', scan_type=ScanType.TCP, status=status, latency=latency, reason=reason)
        except socket.timeout:
            latency = time.perf_counter() - start
            return ScanResult(port=port, protocol='tcp', scan_type=ScanType.TCP, status=PortStatus.FILTERED, latency=latency, reason='Connection attempt timed out')
        except OSError as exc:
            latency = time.perf_counter() - start
            return ScanResult(port=port, protocol='tcp', scan_type=ScanType.TCP, status=PortStatus.ERROR, latency=latency, reason='OS error during TCP connect', error=str(exc))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _scan_udp(self, port: int) -> ScanResult:
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(b'', (self.target, port))
            try:
                data, _ = sock.recvfrom(1024)
                latency = time.perf_counter() - start
                banner = data.decode(errors='ignore').strip() or None
                return ScanResult(port=port, protocol='udp', scan_type=ScanType.UDP, status=PortStatus.OPEN, latency=latency, banner=banner, reason='Received UDP response')
            except socket.timeout:
                latency = time.perf_counter() - start
                return ScanResult(port=port, protocol='udp', scan_type=ScanType.UDP, status=PortStatus.FILTERED, latency=latency, reason='No UDP response (open|filtered)')
        except ConnectionRefusedError:
            latency = time.perf_counter() - start
            return ScanResult(port=port, protocol='udp', scan_type=ScanType.UDP, status=PortStatus.CLOSED, latency=latency, reason='ICMP port unreachable (closed)')
        except OSError as exc:
            latency = time.perf_counter() - start
            if getattr(exc, 'winerror', None) == 10054:
                return ScanResult(port=port, protocol='udp', scan_type=ScanType.UDP, status=PortStatus.CLOSED, latency=latency, reason='Port unreachable (WinError 10054)')
            return ScanResult(port=port, protocol='udp', scan_type=ScanType.UDP, status=PortStatus.ERROR, latency=latency, reason='OS error during UDP probe', error=str(exc))
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _scan_stealth(self, port: int) -> ScanResult:
        start = time.perf_counter()
        try:
            from scapy.all import IP, TCP, conf, send, sr1
        except ImportError as exc:
            raise RuntimeError('Stealth scan requires scapy. Install scapy and run with elevated privileges.') from exc
        except OSError as exc:
            raise RuntimeError(f'Stealth scan unavailable: {exc}') from exc
        conf.verb = 0
        packet = IP(dst=self.target) / TCP(dport=port, flags='S')
        try:
            response = sr1(packet, timeout=self.timeout)
        except PermissionError as exc:
            raise RuntimeError('Stealth scan requires administrative privileges to send raw packets.') from exc
        latency = time.perf_counter() - start
        if response is None:
            return ScanResult(port=port, protocol='tcp', scan_type=ScanType.STEALTH, status=PortStatus.FILTERED, latency=latency, reason='No response to SYN (filtered or open)')
        if response.haslayer(TCP):
            flags = response[TCP].flags
            if flags & 18:
                send(IP(dst=self.target) / TCP(dport=port, flags='R'), verbose=0)
                return ScanResult(port=port, protocol='tcp', scan_type=ScanType.STEALTH, status=PortStatus.OPEN, latency=latency, reason='Received SYN-ACK')
            if flags & 20:
                return ScanResult(port=port, protocol='tcp', scan_type=ScanType.STEALTH, status=PortStatus.CLOSED, latency=latency, reason='Received RST-ACK')
        return ScanResult(port=port, protocol='tcp', scan_type=ScanType.STEALTH, status=PortStatus.UNKNOWN, latency=latency, reason='Unexpected response during stealth scan')

    def _annotate_service_if_needed(self, result: ScanResult) -> None:
        if not self.service_detection:
            return
        if result.status != PortStatus.OPEN:
            return
        protocol = 'tcp' if result.protocol == 'tcp' else 'udp'
        try:
            service = socket.getservbyport(result.port, protocol)
        except OSError:
            service = None
        banner = result.banner
        if service:
            result.service = service
        if protocol == 'tcp' and (not banner):
            banner = self._grab_banner(result.port)
        if banner:
            result.banner = banner
        if not result.service:
            result.service = self._guess_service_from_banner(banner)

    def _try_recv_banner(self, sock: socket.socket) -> Optional[str]:
        try:
            sock.settimeout(0.5)
            data = sock.recv(1024)
            if not data:
                return None
            return data.decode(errors='ignore').strip() or None
        except (socket.timeout, OSError):
            return None

    def _grab_banner(self, port: int) -> Optional[str]:
        try:
            with socket.create_connection((self.target, port), timeout=self.banner_timeout) as sock:
                sock.settimeout(self.banner_timeout)
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    return None
                if not data:
                    return None
                return data.decode(errors='ignore').strip() or None
        except (socket.timeout, OSError):
            return None

    def _guess_service_from_banner(self, banner: Optional[str]) -> Optional[str]:
        if not banner:
            return None
        lowered = banner.lower()
        known_signatures = {'ssh': 'ssh', 'http': 'http', 'https': 'https', 'smtp': 'smtp', 'ftp': 'ftp', 'imap': 'imap', 'pop3': 'pop3', 'telnet': 'telnet', 'mysql': 'mysql', 'redis': 'redis', 'postgres': 'postgresql'}
        for keyword, service in known_signatures.items():
            if keyword in lowered:
                return service
        return None
