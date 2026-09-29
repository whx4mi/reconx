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
bypass lógico ou sessões autenticadas fornecidas pelo usuário.

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
export RECONX_AI_MODEL="gpt-4o-mini"
read -rsp 'Chave da API: ' RECONX_AI_KEY; echo
export RECONX_AI_KEY
sudo --preserve-env=RECONX_AI_KEY,RECONX_AI_MODEL reconx
```

`OPENAI_API_KEY` também é aceito como alternativa à chave. O endpoint padrão
é `https://api.openai.com/v1/chat/completions`; `RECONX_AI_URL` permite indicar
outro endpoint compatível, usando HTTPS (HTTP somente para localhost).
O modelo precisa aceitar `response_format: json_schema`. Essa integração segue
a [documentação oficial de Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).
Respostas recusadas, incompletas ou fora do esquema interrompem a geração;
não há fallback silencioso para uma lista diferente. Conteúdo das páginas é
tratado como dados, sem poder escolher comandos, escopo ou limites.

A geração utiliza o proxy selecionado, inclusive SOCKS via curl, e não segue
redirecionamentos do provedor. Sem chave/modelo configurados, esse modo informa
o motivo e os outros testes seguem. A consulta pode gerar cobrança no provedor.

Validação local: `python3 -m unittest discover -s tests -v`.
Validação real: selecionar Web App Pentest/full e fornecer a URL do MeOwna
acessível pelo Kali, incluindo caminho e porta. Confirmar no relatório os
formulários do lab e as execuções dos scanners instalados.
