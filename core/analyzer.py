"""Offline OWASP WSTG-oriented triage and attack-surface prioritization."""
from __future__ import annotations

import re
from urllib.parse import urlsplit, parse_qsl

RULES = (
    ('WSTG-ATHN', re.compile(r'login|signin|auth|token|oauth|session|password|sso', re.I), 5),
    ('WSTG-ATHZ', re.compile(r'(?:\bid\b|uuid|tenant|account|user_id|order_id|customer)', re.I), 5),
    ('WSTG-INPV', re.compile(r'\?|search|query|filter|sort|redirect|url|input|comment|message', re.I), 4),
    ('WSTG-APIT', re.compile(r'graphql|/api(?:/|$)|/v\d+/|\.json(?:$|\?)', re.I), 4),
    ('WSTG-BUSL', re.compile(r'checkout|payment|billing|invoice|cart|transfer|purchase|subscription', re.I), 5),
)

def classify_endpoint(endpoint):
    url = str(endpoint.get('url') or endpoint.get('value') or '')
    parsed = urlsplit(url if '://' in url else 'https://placeholder/' + url.lstrip('/'))
    params = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    text = ' '.join((url, str(endpoint.get('kind', '')), ' '.join(params)))
    tags = [tag for tag, pattern, _ in RULES if pattern.search(text)]
    score = sum(weight for tag, _, weight in RULES if tag in tags)
    score += min(len(params), 4)
    if endpoint.get('method', 'GET').upper() not in ('GET', 'HEAD', 'OPTIONS'):
        score += 2
    if endpoint.get('in_scope') is False:
        score = 0
    return {**endpoint, 'wstg_tags': tags, 'priority_score': score,
            'priority': 'high' if score >= 8 else 'medium' if score >= 4 else 'low'}

def analyze(scan_data, assets=None):
    assets = assets or []
    adaptive = scan_data.get('adaptive_report') or {}
    reverse = adaptive.get('reverse_engineering') or {}
    candidates = []
    candidates.extend(reverse.get('endpoints', []))
    candidates.extend(adaptive.get('tasks', []))
    for asset in assets:
        if asset.get('atype') in ('url', 'endpoint', 'path') or asset.get('kind') in ('url', 'endpoint', 'path'):
            candidates.append({'url': asset.get('value'), 'kind': asset.get('atype') or asset.get('kind')})
    unique = {}
    for endpoint in candidates:
        item = classify_endpoint(endpoint)
        key = (item.get('method', 'GET'), item.get('url', item.get('value', '')))
        if key[1]:
            previous = unique.get(key)
            if not previous or item['priority_score'] > previous['priority_score']:
                unique[key] = item
    return sorted(unique.values(), key=lambda item: (-item['priority_score'], item.get('url', '')))

