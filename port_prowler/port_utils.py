from __future__ import annotations
from typing import Iterable, List, Sequence, Set

def parse_ports(spec: str) -> List[int]:
    if not spec:
        raise ValueError('Port specification cannot be empty.')
    ports: Set[int] = set()
    for token in spec.split(','):
        token = token.strip()
        if not token:
            continue
        if '-' in token:
            start_str, end_str = token.split('-', maxsplit=1)
            start = _parse_port_value(start_str)
            end = _parse_port_value(end_str)
            if end < start:
                raise ValueError(f"Invalid port range: '{token}' (end before start)")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port_value(token))
    if not ports:
        raise ValueError('No valid ports found in specification.')
    return sorted(ports)

def _parse_port_value(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"Invalid port value '{value}'") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f'Port number out of range: {port} (valid range 1-65535)')
    return port

def deduplicate_preserve_order(values: Sequence[int]) -> List[int]:
    seen: Set[int] = set()
    result: List[int] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
