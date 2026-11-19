"""Strict allow/deny scope matching for host, URL, domain and IP targets."""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit


def _host(value: str) -> str:
    raw = str(value or '').strip()
    if not raw:
        return ''
    parsed = urlsplit(raw if '://' in raw else '//' + raw)
    return (parsed.hostname or '').rstrip('.').lower()


@dataclass
class ScopePolicy:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value=None):
        value = value or {}
        return cls(list(value.get('in_scope') or []), list(value.get('out_of_scope') or []))

    @staticmethod
    def _matches(pattern: str, target: str) -> bool:
        host = _host(target)
        rule = str(pattern or '').strip().lower()
        if not host or not rule:
            return False
        candidate = _host(rule) if '://' in rule else rule
        try:
            network = ipaddress.ip_network(candidate, strict=False)
            return ipaddress.ip_address(host) in network
        except ValueError:
            pass
        if '*' in candidate or '?' in candidate:
            return fnmatch.fnmatchcase(host, candidate)
        return host == candidate or host.endswith('.' + candidate)

    def decision(self, target: str) -> tuple[bool, str]:
        denied = next((rule for rule in self.out_of_scope if self._matches(rule, target)), None)
        if denied:
            return False, f'alvo explicitamente excluído por {denied}'
        if self.in_scope and not any(self._matches(rule, target) for rule in self.in_scope):
            return False, 'alvo não corresponde a nenhuma regra in_scope'
        return True, 'alvo permitido pela política de escopo'

    def require(self, target: str) -> str:
        allowed, reason = self.decision(target)
        if not allowed:
            raise ValueError(f'Alvo fora do escopo: {target} ({reason})')
        return target


def is_in_scope(target: str, in_scope=None, out_of_scope=None) -> bool:
    return ScopePolicy(list(in_scope or []), list(out_of_scope or [])).decision(target)[0]

