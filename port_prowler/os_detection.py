from __future__ import annotations
import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Optional
TTL_REGEX = re.compile('[Tt][Tt][Ll][=:\\s](\\d+)')

@dataclass
class OSFingerprint:
    target: str
    ttl: Optional[int]
    guess: str
    raw_output: str

def probe_ttl(target: str, timeout: int=3) -> OSFingerprint:
    system = platform.system().lower()
    count_flag = '-n' if system == 'windows' else '-c'
    timeout_flag = '-w' if system == 'windows' else '-W'
    command = ['ping', count_flag, '1', timeout_flag, str(timeout), target]
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True)
    except OSError as exc:
        return OSFingerprint(target=target, ttl=None, guess=f'Ping not available ({exc})', raw_output='')
    raw_output = proc.stdout + proc.stderr
    match = TTL_REGEX.search(raw_output)
    ttl = int(match.group(1)) if match else None
    guess = _interpret_ttl(ttl)
    return OSFingerprint(target=target, ttl=ttl, guess=guess, raw_output=raw_output.strip())

def _interpret_ttl(ttl: Optional[int]) -> str:
    if ttl is None:
        return 'Unknown (TTL not detected)'
    if ttl <= 64:
        return 'Likely Linux/Unix or networking device (TTL<=64)'
    if ttl <= 128:
        return 'Likely Windows (TTL<=128)'
    if ttl <= 255:
        return 'Likely network appliance or Solaris (TTL<=255)'
    return 'Unknown (TTL value outside expected range)'
