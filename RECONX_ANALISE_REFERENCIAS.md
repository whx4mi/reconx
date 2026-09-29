# ReconX — Análise de Referências, Ferramentas e Melhorias

> Documento gerado com base em pesquisa ativa (junho 2026).  
> Objetivo: mapear o ecossistema de ferramentas similares, extrair pontos fortes e propor melhorias concretas por contexto de uso.

---

## 1. Contexto do ReconX v5

O ReconX é um **orquestrador de pentest/recon com UI web** (Flask + SocketIO) que executa ferramentas sequencialmente em pipelines configuráveis, com suporte a proxy (Burp/ZAP/Tor), deduplicação de findings via SQLite e exportação de relatório em Markdown.

**Pipelines atuais:** CTF/HTB Box · Web App Pentest · Subdomain Recon · Bug Bounty

**Ferramentas cobertas:** subfinder, assetfinder, dnsx, dnsrecon, whois, nmap, naabu, httpx, whatweb, wafw00f, curl, gowitness, ffuf, gobuster, arjun, waybackurls, gau, katana, theHarvester, nikto, nuclei (4 modos), sqlmap, commix, dalfox, wpscan, feroxbuster, testssl

---

## 2. Ferramentas Similares — Análise Comparativa

### 2.1 ReconFTW (`six2dez/reconftw`)

**Proposta:** Script Bash de automação de recon completo, orientado a linha de comando. Referência principal da comunidade.

**Pontos fortes que o ReconX deve incorporar:**

| Feature | Como implementar no ReconX |
|---|---|
| **Perfis de intensidade** (Quick / Full / Stealth) | Adicionar campo `intensity` nos pipelines — Quick usa só ferramentas passivas/rápidas, Full ativa tudo, Stealth desabilita ferramentas ativas |
| **Cloud bucket discovery** (`cloud_enum`, `S3Scanner`) | Nova categoria `cloud` com tools para detectar buckets S3/GCS/Azure misconfigured |
| **TLS cert harvesting** (`tlsx`) | Nova tool `tlsx` que extrai SANs/CNs de certificados TLS — gera subdomínios que nenhuma API entrega |
| **API Keys configuráveis** (Shodan, GitHub, WHOISXML) | Aba de configuração de API keys na UI para ferramentas que as usam (subfinder, amass, uncover) |
| **Notificações** (Slack/Telegram) | Webhook configurável disparado no `pipeline_complete` |
| **Scanning distribuído** (AX Framework) | Roadmap futuro — agentes em múltiplas VMs coordinados pelo ReconX |
| **Recursive subdomain** (`dsieve`) | Filtragem e recursão inteligente de subdomínios descobertos |

---

### 2.2 Reconmap (`reconmap/reconmap`)

**Proposta:** Plataforma de colaboração para equipes de pentest — gestão de projetos, clientes e relatórios profissionais. Atualmente o player mais maduro em UI web para este contexto.

**Pontos fortes que o ReconX deve incorporar:**

| Feature | Como implementar no ReconX |
|---|---|
| **AI-assisted summaries** | Após `pipeline_complete`, chamar Claude/OpenAI API para resumir findings por severidade e sugerir vetor de ataque prioritário |
| **Templates de relatório múltiplos** | Além do Markdown atual, gerar PDF e DOCX via export |
| **Agendamento de scans** | Cron job configurável pela UI para recon contínuo (monitorar novos subdomínios/mudanças) |
| **Histórico de engagement** | Na UI, comparar duas runs do mesmo alvo e mostrar **delta** (findings novos vs. resolvidos) |
| **Gestão de escopo** | Definir escopos permitidos (CIDRs, domínios) e bloquear automaticamente alvos fora de escopo antes de executar cada tool |

---

### 2.3 XPFarm (`canuk40/xpfarm`)

**Proposta:** Framework web UI similar ao ReconX — wraps das mesmas ferramentas ProjectDiscovery + CVEMap integrado.

**Ponto forte principal:**

| Feature | Como implementar no ReconX |
|---|---|
| **CVEMap pós-fingerprint** | Após `whatweb`/`httpx` detectar tecnologia+versão, executar `cvemap` automaticamente para listar CVEs conhecidos daquele produto — cria findings de severidade automaticamente |

---

### 2.4 Pentest Swarm AI (`Armur-Ai/Pentest-Swarm-AI`)

**Proposta:** Orquestrador autônomo orientado a AI swarm — agentes com raciocínio ReAct coordenados por um blackboard compartilhado de findings.

**Pontos fortes que o ReconX deve incorporar:**

| Feature | Como implementar no ReconX |
|---|---|
| **AI Reasoning sobre findings** | Após cada stage, passar findings para LLM e receber sugestão de qual tool/ataque faz mais sentido no próximo stage (enriquece os `manual_followup`) |
| **Correlação entre findings** | Cruzar automaticamente portas abertas + tecnologias + CVEs detectados e sugerir exploits específicos |
| **Modo autônomo** | Opção para o pipeline aprovar automaticamente checkpoints sem intervenção humana (com limite de escopo) |

---

## 3. Ferramentas para Adicionar ao ReconX

### 3.1 Por Categoria

#### RECON — Subdomínios / TLS

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **tlsx** | `tlsx` | Extrai SANs/CNs de certificados TLS — descobre subdomínios que DNS/APIs não entregam. Input: host/CIDR. | 🔴 Alta |
| **amass** | `amass` | OSINT passivo mais profundo (fontes: CertDB, PassiveTotal, SecurityTrails). Complementa subfinder. | 🟡 Média |
| **findomain** | `findomain` | Subdomain finder rápido com APIs Cert.sh, AnubisDB, Threatminer. | 🟡 Média |
| **dsieve** | `dsieve` | Filtra e nível-normaliza listas de subdomínios para recursão inteligente. | 🟢 Baixa |

**Exemplo de entrada no `TOOLS` para `tlsx`:**
```python
"tlsx": {
    "label": "TLSx (cert harvest)", "phase": "recon", "category": "subdomains",
    "desc": "Extrai subdomínios de certificados TLS via SAN/CN",
    "cmd": ["tlsx", "-host", "{domain}", "-san", "-cn", "-silent", "-json"],
    "input": "domain", "output": "subdomains",
    "json": True, "binary": "tlsx", "tags": ["passive","tls","fast"],
    "proxy_support": False,
    "manual_followup": ["Subdomínios de cert são frequentemente internos ou legados — priorize-os"],
}
```

---

#### RECON — Asset Discovery / Cloud / Shodan

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **uncover** | `uncover` | Agrega Shodan, Censys, Fofa, Hunter.io — descobre IPs/hosts expostos com contexto. | 🔴 Alta |
| **cloud_enum** | `cloud_enum` | Enumera buckets S3, GCS (Google Cloud), Azure Blob misconfigured. Input: keyword/company. | 🔴 Alta |
| **S3Scanner** | `s3scanner` | Descobre e testa permissões de buckets S3 (leitura pública, listagem, escrita). | 🟡 Média |
| **shosubgo** | `shosubgo` | Subdomínios via Shodan API. Requer API key. | 🟢 Baixa |

---

#### RECON — OSINT / Secrets

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **trufflehog** | `trufflehog` | Busca secrets/credenciais em páginas HTML, JS e repositórios. Detecta tokens AWS, GitHub, GCP etc. | 🔴 Alta |
| **github-subdomains** | `github-subdomains` | Descobre subdomínios mencionados no código público do GitHub. Requer token. | 🟡 Média |
| **gitdorker** / **gitrob** | — | Busca por informações sensíveis em GitHub via dorks. | 🟢 Baixa |

---

#### RECON — Port Scanning

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **masscan** | `masscan` | Port scanner extremamente rápido (pacotes raw). Ideal para varrer ranges /24 ou maiores antes do nmap. | 🟡 Média |
| **rustscan** | `rustscan` | Port scanner em Rust — mais rápido que nmap na descoberta de portas, passa resultado para nmap. | 🟡 Média |

---

#### TEST — OOB / Blind Vulnerabilities

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **interactsh-client** | `interactsh-client` | **Crítico para blind SSRF, blind XSS, blind SQLi, XXE OOB, RCE OOB.** Gera URL única; qualquer callback é detectado. Integra com nuclei. | 🔴 Alta |

**Como integrar:**  
No início do pipeline, iniciar `interactsh-client` em background e capturar o URL OOB gerado. Passar esse URL como payload para as tools de injection (dalfox, sqlmap, commix, nuclei_dast). Ao final, verificar callbacks recebidos.

---

#### TEST — CVE / Vulnerability Intelligence

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **cvemap** / **vulnx** | `cvemap` | Busca CVEs por produto/versão com PoC disponível e template nuclei associado. Usar após whatweb/httpx detectar tecnologia. | 🔴 Alta |
| **nuclei** (PDCP cloud) | `nuclei` | Modo AI: `nuclei -ai` para gerar templates customizados baseados em findings. | 🟡 Média |

---

#### TEST — Web / Auth / 403 Bypass

| Tool | Binário | Propósito | Prioridade |
|---|---|---|---|
| **nomore403** | `nomore403` | Testa 20+ técnicas de bypass em endpoints que retornam 403 (path normalization, headers, verbos HTTP). | 🔴 Alta |
| **byp4xx** | `byp4xx` | Similar ao nomore403 — bypass de 401/403/404. | 🟡 Média |
| **jwt-tool** | `jwt_tool` | Testa vulnerabilidades em JWTs (alg=none, weak secret, kid injection). | 🟡 Média |
| **CORScanner** | `python3 cors_scan.py` | Testa CORS misconfiguration em múltiplos endpoints. | 🟡 Média |
| **corsy** | `corsy` | Alternativa leve ao CORScanner. | 🟢 Baixa |

---

### 3.2 Melhorias por Ferramenta Já Existente

| Tool Atual | Melhoria |
|---|---|
| **ffuf_dirs** | Adicionar `-recursion` e `-recursion-depth 2` — cobertura recursiva automática sem precisar do feroxbuster |
| **naabu** | Adicionar `-cdn` flag para ignorar IPs de CDN (Cloudflare, Akamai) e focar em infra real |
| **gobuster_vhost** | Adicionar `-r` para follow redirects e `-k` para ignorar erros TLS |
| **nuclei_cves** | Adicionar `-severity critical,high,medium` para pegar mais findings relevantes |
| **katana** | Adicionar `-jc` (JS crawling) e `-hl` (headless) para SPA coverage mais profundo |
| **sqlmap** | Adicionar `--technique=BEUSTQ --dbs` quando `--level=2` — mais cobertura de técnicas |
| **gowitness** | Usar output `--write-db` (SQLite nativo do gowitness) para indexar screenshots e consultar depois |
| **httpx** | Adicionar `-follow-host-redirects -pipeline -ports 80,443,8080,8443,8888` — detecta apps em portas não-padrão |

---

## 4. Melhorias Estruturais no ReconX

### 4.1 Integração com AI (Alto Impacto)

Após `pipeline_complete`, chamar LLM com o contexto de findings e gerar:

1. **Resumo executivo** — 3-5 linhas descrevendo superfície de ataque do alvo
2. **Top 3 vetores de ataque** recomendados com base nos findings
3. **Análise de severidade contextualizada** — cruza tecnologia + CVEs + configuração

Implementação simples via `requests.post` para API do Claude/OpenAI dentro do `_finish()`:

```python
def ai_summary(scan_id, findings, summary):
    import requests
    prompt = f"Analise os seguintes findings de pentest...\n{json.dumps(findings[:50])}"
    # POST para API
    return ai_text
```

---

### 4.2 Perfis de Intensidade (Quick / Full / Stealth)

Adicionar campo `intensity` nos pipelines e filtrar tools por tag:

- `quick` → apenas tools com tag `fast` + `passive`
- `full` → todas as tools (comportamento atual)
- `stealth` → apenas tools `passive`, sem bruteforce, delay maior entre requests

---

### 4.3 Monitoramento Contínuo (Recon Persistente)

Recon contínuo é um diferencial enorme para bug bounty e red team:

- **Scan agendado** (cron) para rodar subdomain recon semanalmente
- **Delta alert** — compara findings novos vs. run anterior e notifica por webhook (Slack/Telegram)
- **Superfície de ataque tracking** — dashboard mostrando evolução de ativos ao longo do tempo

---

### 4.4 Relatório Enriquecido

Além do Markdown atual, adicionar:

- **Export PDF** com evidências de screenshot embutidas (gowitness screenshots)
- **Export DOCX** via python-docx (estilo relatório profissional)
- **JSON normalizado** com schema fixo para importação em outras plataformas (Reconmap, Faraday, Dradis)

---

### 4.5 Fingerprint → CVE Automático

Quando `whatweb` ou `httpx` detectar tecnologia + versão:

1. Extrair do JSON: `{"tech": ["WordPress 6.4.2", "PHP 8.1"]}`
2. Para cada tecnologia: `cvemap -product wordpress -version 6.4.2 -severity critical,high -json`
3. Injetar findings no DB com severidade mapeada do CVSS

Este fluxo replica o que o XPFarm faz e entrega **CVEs específicos do alvo** sem depender de templates nuclei genéricos.

---

### 4.6 OOB Session com interactsh

Fluxo proposto:

```
pipeline_start
  └─ inicia interactsh-client em background
       └─ captura OOB_URL (ex: abc123.oast.site)
           └─ injeta OOB_URL nos payloads de:
               - dalfox (--blind OOB_URL)
               - nuclei_dast (-iserver OOB_URL)
               - commix (--oob OOB_URL)
           └─ ao final, consulta callbacks recebidos
               └─ gera findings "Blind [SSRF|XSS|RCE] confirmado"
```

---

## 5. Pipelines Novos Sugeridos

### 5.1 Cloud Attack Surface
```
Stage 1: subfinder + tlsx + amass (passive)
Stage 2: httpx + uncover (Shodan)
Stage 3: cloud_enum + S3Scanner
Stage 4: nuclei_misconfig + nuclei_takeover
```

### 5.2 API Pentest
```
Stage 1: httpx + katana (JS crawling) + arjun
Stage 2: gau + waybackurls (filtrar endpoints de API)
Stage 3: nuclei_dast + dalfox_url + commix
Stage 4: sqlmap_url (parâmetros descobertos pelo arjun)
```

### 5.3 Stealth Recon (mínimo ruído)
```
Stage 1: subfinder + assetfinder + tlsx (apenas passivos)
Stage 2: waybackurls + gau + theHarvester
Stage 3: httpx (só probe, sem fuzzing)
Stage 4: nuclei (apenas templates passive/safe)
```

---

## 6. Checklist Manual — Categorias Novas

### Cloud & Infrastructure
- [ ] S3 bucket com mesmo nome do domínio existe e é público?
- [ ] Google Cloud Storage: `storage.googleapis.com/{empresa}`
- [ ] Azure Blob: `{empresa}.blob.core.windows.net`
- [ ] Metadata server acessível via SSRF? `http://169.254.169.254/latest/meta-data/`
- [ ] Secrets em arquivos `.env`, `.git/config`, `docker-compose.yml` expostos?
- [ ] Kubernetes API exposto? `/api/v1/pods`, `/metrics`

### JWT / OAuth
- [ ] JWT com `alg: none` aceito?
- [ ] Secret JWT fraco (bruteforçável)?  
- [ ] `kid` header faz path traversal ou SQL injection?
- [ ] OAuth: `redirect_uri` aceita domínios arbitrários?
- [ ] OAuth: token vazado em `Referer` header?

### API Security
- [ ] API versão v1 sem autenticação quando v2 exige?
- [ ] GraphQL introspection habilitada em produção?
- [ ] GraphQL: batching de queries permite brute force?
- [ ] Rate limiting ausente em endpoints de autenticação?
- [ ] Mass assignment em PUT/PATCH (campos extras aceitos)?

---

## 7. Resumo de Prioridades de Implementação

| Prioridade | Item |
|---|---|
| 🔴 1 | **interactsh** — blind vuln detection (SSRF/XXE/RCE OOB) |
| 🔴 2 | **tlsx** — cert-based subdomain discovery |
| 🔴 3 | **cvemap** — fingerprint → CVE automático pós-whatweb |
| 🔴 4 | **nomore403** — bypass de 403 nos diretórios encontrados |
| 🔴 5 | **cloud_enum + uncover** — superfície de ataque em cloud/Shodan |
| 🔴 6 | **trufflehog** — secrets/tokens em JS e HTML |
| 🟡 7 | **Perfis de intensidade** (Quick/Full/Stealth) na UI |
| 🟡 8 | **AI summary** pós-scan via LLM |
| 🟡 9 | **Export PDF/DOCX** com screenshots |
| 🟡 10 | **Webhook de notificação** (Slack/Telegram) ao completar |
| 🟡 11 | **amass** + **masscan** como alternativas mais potentes |
| 🟢 12 | **Pipeline Cloud Attack Surface** |
| 🟢 13 | **Pipeline API Pentest** |
| 🟢 14 | **Monitoramento contínuo / recon delta** |

---

## Referências

- [ReconFTW — six2dez/reconftw](https://github.com/six2dez/reconftw)
- [Reconmap — plataforma de colaboração](https://github.com/reconmap/reconmap)
- [XPFarm — web UI wrapper](https://github.com/canuk40/xpfarm)
- [Pentest Swarm AI — Armur-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI)
- [ProjectDiscovery Tools](https://github.com/projectdiscovery)
- [cvemap — CVE navigation CLI](https://docs.projectdiscovery.io/tools/cvemap/usage)
- [interactsh — OOB interaction server](https://github.com/projectdiscovery/interactsh)
- [2025 Bug Bounty Methodology](https://ravi73079.medium.com/2025-bug-bounty-methodology-toolsets-and-persistent-recon-d991e39e52ce)
- [AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026)
