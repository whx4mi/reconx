"""Small fail-closed Gemini generateContent JSON client shared by ReconX AI features."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def generate_json(system_prompt, user_data, schema, proxy=None, environ=None):
    """Return one parsed JSON object; never expose the API key in argv or logs."""
    settings = os.environ if environ is None else environ
    key = settings.get('GEMINI_API_KEY')
    model = settings.get('GEMINI_MODEL', 'gemini-3.8-flash')
    if not isinstance(key, str) or not key or any(ord(c) < 32 or ord(c) == 127 for c in key):
        raise ValueError('Configure GEMINI_API_KEY no servidor')
    if not isinstance(model, str) or not re.fullmatch(r'gemini-[A-Za-z0-9._-]{1,100}', model):
        raise ValueError('GEMINI_MODEL inválido')
    if proxy and proxy.get('profile', 'none') != 'none' and not (proxy.get('http') or proxy.get('socks')):
        raise ValueError('Proxy selecionado sem endereço; IA bloqueada')
    endpoint = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent'
    payload = {
        'systemInstruction': {'parts': [{'text': system_prompt}]},
        'contents': [{'role': 'user', 'parts': [{'text': json.dumps(user_data, ensure_ascii=False)}]}],
        'generationConfig': {'responseFormat': {'text': {'mimeType': 'application/json', 'schema': schema}}},
    }
    try:
        with tempfile.TemporaryDirectory(prefix='reconx-gemini-') as work:
            work = Path(work)
            headers, body, response = work / 'headers', work / 'body.json', work / 'response.json'
            headers.write_text(f'Content-Type: application/json\nx-goog-api-key: {key}\n', encoding='utf-8')
            body.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
            headers.chmod(0o600)
            body.chmod(0o600)
            env = {k: v for k, v in os.environ.items() if k.lower() not in
                   ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
            address = (proxy.get('http') or proxy.get('socks')) if proxy else None
            command = ['curl', '-q', '--silent', '--show-error', '--proto', '=https',
                       '--max-time', '45', '--max-filesize', '65536',
                       '--header', '@' + str(headers), '--data-binary', '@' + str(body),
                       '--output', str(response), '--write-out', '%{http_code}',
                       '--proxy', address or '', '--noproxy', '', endpoint]
            transport = subprocess.run(command, capture_output=True, text=True, timeout=50, env=env)
            if transport.returncode or transport.stdout.strip() != '200':
                raise ValueError('Gemini não retornou HTTP 200; verifique chave, modelo, cota e conectividade')
            raw = response.read_bytes()
        if len(raw) > 65536:
            raise ValueError('Resposta do Gemini excedeu o limite')
        result = json.loads(raw)
        candidates = result.get('candidates')
        if not isinstance(candidates, list) or len(candidates) != 1:
            raise ValueError('Gemini não retornou uma resposta utilizável')
        candidate = candidates[0]
        if candidate.get('finishReason') != 'STOP':
            raise ValueError('Gemini interrompeu ou bloqueou a resposta')
        parts = candidate['content']['parts']
        if len(parts) != 1 or not isinstance(parts[0].get('text'), str):
            raise ValueError('Formato de resposta do Gemini inesperado')
        return json.loads(parts[0]['text'])
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Falha de conexão com o Gemini') from None
    except (KeyError, IndexError, TypeError, json.JSONDecodeError):
        raise ValueError('Resposta JSON inválida do Gemini') from None
