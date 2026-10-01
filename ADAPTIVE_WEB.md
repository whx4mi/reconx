# Adaptive Web

Nos pipelines **Web App Pentest**, **Full Pentest**, **CTF / HTB Box**,
**Bug Bounty** e **API Pentest**, o perfil `full` inclui uma etapa adaptativa
antes dos testes gerais. Também é possível selecionar a ferramenta
`Adaptive Web` em um pipeline customizado. Quick/stealth não a ativam automaticamente.

A etapa busca HTML a partir do alvo original e das URLs já descobertas,
segue links da mesma origem (esquema, host e porta) e identifica formulários,
campos de texto, textarea, select, campos ocultos, tokens e parâmetros na URL.
Também reconhece requisições `fetch()` literais construídas com
`URLSearchParams` em scripts inline, sem executar o JavaScript. Ela preserva
os caminhos, query strings e campos duplicados.

## Engenharia reversa estática

A mesma etapa coleta, com limites, os `<script src>` da origem autorizada e
analisa scripts inline, bundles JavaScript e source maps sem executar código.
Quando `jsluice` está instalado, o mesmo conteúdo já baixado pelo ReconX também
passa por análise AST complementar. O código é entregue ao processo por `stdin`:
o analisador não refaz a requisição e não pode ampliar a origem autorizada.
O bloco `reverse_engineering` do `adaptive_report.json` correlaciona:

- scripts analisados, tamanho e SHA-256;
- frameworks/bundlers observados;
- métodos e endpoints REST/XHR, rotas de frontend, GraphQL, WebSocket e SSE;
- sinais de autenticação, papéis/permissões, tenancy, identificadores e ações
  de negócio;
- relações `artefato → operação → endpoint`;
- analisadores efetivamente disponíveis e nomes de parâmetros GET/POST extraídos;
- árvore de fontes revelada por source maps, sem copiar `sourcesContent`.

Scripts e endpoints externos são inventariados, mas nunca buscados ou tratados
como autorização. Endpoints mapeados não são invocados automaticamente: eles
são sinais arquiteturais para formular hipóteses e testes posteriores. Os
limites padrão são 24 scripts e 8 source maps, configuráveis por
`RECONX_REVERSE_SCRIPTS` (até 100) e `RECONX_REVERSE_SOURCE_MAPS` (até 30).
Bundles e mapas aceitam até 4 MiB por artefato por padrão; ajuste com
`RECONX_REVERSE_MAX_BYTES` até 16 MiB. Páginas HTML continuam limitadas a
512 KiB.

Perfis temporários de navegadores e scanners são criados em `.tmp` dentro do
diretório de resultados, evitando depender de uma partição `/tmp` pequena.
`RECONX_TMPDIR` permite selecionar outro diretório gravável quando necessário.

URLs parametrizadas recebem testes SQLMap/Dalfox. Formulários GET/POST
recebem testes com os nomes e valores dos campos, botão de envio e cookies
da descoberta. Antes de cada teste o formulário é lido novamente; SQLMap
recebe instruções de renovação de CSRF quando há token conhecido. Login
recebe teste de injection, mas sua detecção não confirma bypass de autenticação.
Requisições POST simples descobertas em scripts inline recebem SQLMap e Commix
com o corpo e os nomes de parâmetros observados.

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
actions fora da origem inicial e XSS com token dinâmico. A camada não executa
JavaScript arbitrário, módulos carregados em runtime, service workers ou estado
de SPA; valores calculados e fluxos autenticados podem permanecer ocultos.
Também não automatiza MFA, CAPTCHA ou bypass lógico.

## Wordlists e testes de login

Abra **Testes de login / wordlists** na barra lateral, marque **Testar logins
descobertos** e selecione um dos modos:

- **Wordlists personalizadas**: dois caminhos na VM do ReconX, um para usuários
  e outro para senhas. UTF-8, um candidato por linha, até 4 MiB por arquivo.
  Duplicatas e linhas vazias são removidas; espaços nas senhas são preservados.
  Até 5.000 candidatos únicos por arquivo são carregados.
- **Gerar wordlists por IA**: uma chamada por scan usa texto público visível e
  nomes dos campos das páginas descobertas. Cookies, valores de inputs,
  scripts e listas personalizadas não são enviados. O operador escolhe de 1 a
  100 candidatos por lista; eles ficam em `generated_users.txt` e
  `generated_passwords.txt` no diretório do scan.

Informe o caminho de sucesso (ex.: `/dashboard.php`) e/ou um texto literal
exclusivo da área autenticada. Quando ambos são informados, ambos devem
corresponder. HTTP 200 sozinho não confirma login. Dois controles com
credenciais aleatórias inválidas devem rejeitar esse critério antes dos
candidatos. Se um controle também corresponder, o módulo para e pede ajuste.

O módulo testa somente formulários POST urlencoded com um campo de senha.
Não testa cadastro, alteração/reset de senha, upload ou actions externas.
Nomes dos campos podem ser informados ou detectados. Cada tentativa começa
com sessão nova e leitura do formulário para renovar tokens. Redirecionamentos
só são seguidos dentro da origem inicial, até três passos.

O padrão é 20 submissões de login no total (incluindo os controles), intervalo
de 1 segundo. O operador pode configurar até 1.000 submissões e intervalo de
1–30 segundos. Leituras GET para tokens/redirecionamentos são adicionais ao
contador de submissões. O módulo para no primeiro match, cancelamento,
CAPTCHA, HTTP 403/429 ou indício textual de bloqueio. Um match é registrado
como `likely`, não confirmação automática de bypass ou acesso completo.

Credenciais correspondentes ficam somente em `login_credentials.json`, criado
com permissão `0600` no Linux; senhas não aparecem no terminal ou relatório
geral. Não exponha o diretório de resultados via servidor web. Os testes
seguintes da mesma etapa podem aproveitar os cookies; não há recrawl
autenticado automático nem transferência de sessão para outras etapas.

### Configurar a IA

Para triagem contínua em um pipeline separado, veja [AI_PIPELINE.md](AI_PIPELINE.md).
Esse fluxo tem BlackBox/WhiteBox e autorização por ação; não é a geração de wordlists abaixo.

Configure no ambiente do processo ReconX:

```bash
export GEMINI_MODEL="gemini-3.8-flash"
read -rsp 'Chave Gemini: ' GEMINI_API_KEY; echo
export GEMINI_API_KEY
sudo --preserve-env=GEMINI_API_KEY,GEMINI_MODEL reconx
```

O cliente usa o endpoint HTTPS `generateContent` do Gemini e saída JSON
estruturada. `GEMINI_MODEL` é opcional; o padrão é `gemini-3.8-flash`. O modelo
precisa estar disponível para a sua chave. Veja a
[documentação oficial](https://ai.google.dev/api/generate-content).
Respostas recusadas, incompletas ou fora do esquema interrompem a geração;
não há fallback silencioso para uma lista diferente. Conteúdo das páginas é
tratado como dados, sem poder escolher comandos, escopo ou limites.

A geração utiliza o proxy selecionado, inclusive SOCKS via curl, e não segue
redirecionamentos do provedor. Sem chave configurada, esse modo informa
o motivo e os outros testes seguem. A consulta pode gerar cobrança no provedor.

Validação local: `python3 -m unittest discover -s tests -v`.
Validação real: selecionar Web App Pentest/full e fornecer a URL do MeOwna
acessível pelo Kali, incluindo caminho e porta. Confirmar no relatório os
formulários do lab e as execuções dos scanners instalados.
