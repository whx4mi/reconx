"""Generate a human analysis guide from offline scan artifacts."""
from __future__ import annotations

from collections import defaultdict
from .analyzer import analyze

def build_analysis_guide(scan_data, assets=None):
    assets = assets or []
    endpoints = analyze(scan_data, assets)
    adaptive = scan_data.get('adaptive_report') or {}
    reverse = adaptive.get('reverse_engineering') or {}
    technologies = sorted(set(reverse.get('frameworks', []) + reverse.get('technologies', [])))
    grouped = defaultdict(list)
    for endpoint in endpoints:
        for tag in endpoint.get('wstg_tags', []) or ['Sem classificação WSTG']:
            grouped[tag].append(endpoint)
    lines = ['# Guia de análise manual — ReconX', '',
             f"- **Alvo:** `{scan_data.get('target', '?')}`",
             f"- **Scan:** `{scan_data.get('scan_id', '?')}`",
             f"- **Data:** {scan_data.get('timestamp', '?')}",
             f"- **Superfície priorizada:** {len(endpoints)} endpoint(s)", '',
             '## Escopo, superfície e stack', '',
             f"- URLs/rotas observadas: {len(endpoints)}",
             f"- Tecnologias observadas: {', '.join(map(str, technologies)) if technologies else 'não identificadas'}", '',
             '## Endpoints prioritários por OWASP WSTG', '']
    if not grouped:
        lines.append('Nenhum endpoint classificável foi encontrado nos artefatos disponíveis.')
    for tag in sorted(grouped):
        lines += [f'### {tag}', '']
        for item in grouped[tag]:
            lines += [f"#### Prioridade {item['priority'].upper()} (score {item['priority_score']})",
                      f"- Método: `{item.get('method', 'GET')}`",
                      f"- Endpoint: `{item.get('url', item.get('value', '?'))}`",
                      f"- Parâmetros: `{', '.join(item.get('parameters', [])) or 'não identificados'}`", '',
                      '**Hipótese manual**',
                      '- Objetivo e pré-condições:',
                      '- Source → Sanitizer → Sink:',
                      '- First Principles: qual premissa de negócio pode ser quebrada?',
                      '- Admin: resultado observado / evidência:',
                      '- Usuário autenticado: resultado observado / evidência:',
                      '- Não autenticado: resultado observado / evidência:',
                      '- Resultado: pendente / confirmado / não reproduzido / inconclusivo', '']
    lines += ['## Limitações', '',
              'Classificações e scores são heurísticas para revisão humana, não findings nem prova de vulnerabilidade.',
              'A análise usa somente dados persistidos; endpoints não observados permanecem fora desta priorização.', '']
    return '\n'.join(lines)

