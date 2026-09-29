# Adaptive Web

Nos pipelines **Web App Pentest**, **Full Pentest**, **CTF / HTB Box**,
**Bug Bounty** e **API Pentest**, o perfil `full` inclui uma etapa adaptativa
antes dos testes gerais. Também é possível selecionar a ferramenta
`Adaptive Web` em um pipeline customizado. Quick/stealth não a ativam automaticamente.

A etapa busca HTML a partir do alvo original e das URLs já descobertas,
segue links da mesma origem (esquema, host e porta) e identifica formulários,
campos de texto, textarea, select, campos ocultos, tokens e parâmetros na URL.
Ela preserva os caminhos, query strings e campos duplicados.

URLs parametrizadas recebem testes SQLMap/Dalfox. Formulários GET/POST
recebem testes com os nomes e valores dos campos, botão de envio e cookies
da descoberta. Antes de cada teste o formulário é lido novamente; SQLMap
recebe instruções de renovação de CSRF quando há token conhecido. Login
recebe teste de injection, mas sua detecção não confirma bypass de autenticação.

Limites atuais: 12 páginas, profundidade 2, corpo de até 512 KiB por página
e 12 tarefas de teste. Cada scanner também tem o timeout definido no catálogo.
Esses limites contam páginas/tarefas, não todas as requisições feitas pelos scanners.
Login e POST têm prioridade quando o limite de tarefas é pequeno. Os limites
podem ser configurados por `RECONX_ADAPTIVE_PAGES` (até 200),
`RECONX_ADAPTIVE_DEPTH` (até 5) e `RECONX_ADAPTIVE_JOBS` (até 100).

O arquivo `results/<domínio>/<scan_id>/adaptive_report.json` registra páginas,
campos (sem seus valores), decisões, tarefas e pendências. O relatório também
integra o JSON final do scan. Estados:

- `completed`: ferramenta terminou com código zero; não significa alvo seguro.
- `failed`: erro de execução ou timeout.
- `skipped`: teste não executado, com motivo.
- `cancelled`: cancelado antes da execução.

Pendências explícitas incluem uploads, formulários com potencial de exclusão,
actions fora da origem inicial e XSS com token dinâmico. A camada interpreta
HTML estático; não automatiza fluxos de navegador/SPA, MFA, CAPTCHA,
bypass lógico, brute force ou sessões autenticadas fornecidas pelo usuário.
BF precisa de conta/lista de teste, limites e critério verificável de sucesso.

Ainda não utiliza API de IA. Uma integração futura deve propor decisões
estruturadas dentro de um catálogo de ações; conteúdo das páginas não deve
ganhar autoridade para escolher comandos, remover limites ou mudar o escopo.

Validação local: `python3 -m unittest discover -s tests -v`.
Validação real: selecionar Web App Pentest/full e fornecer a URL do MeOwna
acessível pelo Kali, incluindo caminho e porta. Confirmar no relatório os
formulários do lab e as execuções dos scanners instalados.
