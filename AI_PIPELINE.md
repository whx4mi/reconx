# Pipeline de triagem orientada por IA

Selecione **Triagem orientada por IA** na lista de pipelines. Abra a seção
**Pipeline orientado por IA** da barra lateral, escolha o modo e confirme o
envio de contexto/outputs ao provedor. Os pipelines anteriores não mudam.

- **BlackBox:** recebe domínio, IPv4 ou URL HTTP(S); começa sem dicas internas.
- **WhiteBox / contexto adicional:** aceita endpoints (um por linha), parâmetros
  na URL e descrição de tecnologias/comportamento. Apenas referências na mesma
  origem inicial são aceitas: protocolo, host e porta. Não lê diretórios locais,
  nem envia arquivos, código ou credenciais automaticamente.

Um domínio/IP sem protocolo é interpretado como HTTP na porta 80. Para HTTPS,
ou o lab em outra porta, informe a URL completa. IPv6 ainda não é suportado.
O campo genérico de escopo não amplia o escopo deste pipeline; subdomínios,
outras portas e redirects para outra origem não são seguidos.

## Decisões e autorização

A cada ciclo, a IA recebe as observações recentes e seleciona um par
ferramenta/ID de alvo do catálogo do servidor, ou encerra. Não pode criar
comandos, argumentos, payloads ou alvos arbitrários. Depois de cada execução,
o output sanitizado entra na próxima análise. No limite de ações, uma última
análise só pode resumir e encerrar, sem executar nada.

| Ação | Autorização |
| --- | --- |
| HTTP HEAD, sem redirects | Operador, por ação |
| HTTP GET de uma página (até 256 KiB), sem redirects | Operador, por ação |
| TCP connect nas 100 portas mais comuns do host inicial, sem NSE | Operador, por ação |
| Protocolos e configuração TLS do alvo HTTPS inicial | Operador, por ação |
| Fingerprint de tecnologia web com WhatWeb | Operador, por ação |
| Verificação manual orientada pela triagem | Operador registra observações para o próximo ciclo |

Todas as ações exigem autorização. GET também exige cuidado porque até uma leitura pode disparar uma ação no
servidor. A tela mostra ferramenta, alvo, impacto, motivo e evidência. Aprovar
libera somente o par proposto, não as próximas ações. Rejeição e expiração
não executam a ferramenta; o par não é proposto novamente. O modelo pode
escolher outra ação permitida ou encerrar. Aprovações são vinculadas ao socket
que iniciou o scan, têm ID imprevisível, são consumidas uma única vez e expiram
em cinco minutos (30 minutos para etapa manual). Recarregar/desconectar a interface não transfere a aprovação:
sem resposta válida, ela expira. Cancelar impede novas execuções. Uma etapa
manual é executada fora do ReconX pelo operador: a IA propõe uma verificação
de alto nível, e o operador informa suas observações. Essas observações entram
na análise seguinte, sem execução de comandos livres pela IA.

O catálogo inicial **não contém exploração, bypass, força bruta, envio de
formulários, SQLmap, Commix nem o módulo Adaptive Web**. Configurações de login
não são encadeadas neste pipeline. A IA fornece triagem, não confirmação de
vulnerabilidade. Os parsers existentes continuam responsáveis pelos findings.
O fluxo pode acompanhar um pentest completo por meio de verificações manuais
registradas, mas não executa automaticamente todos os tipos de teste.

Limites: 8 ações por padrão (configurável de 1 a 20), até 40 URLs conhecidas,
sem repetir pares de testes automatizados; etapas manuais podem ocorrer mais
de uma vez para verificações distintas. Falha de API, recusa, resposta inválida ou
ação fora do catálogo encerra o fluxo sem fallback automático. Proxy inválido
ou ferramenta incompatível continua bloqueando a execução. Nmap não roda com
proxy selecionado; não há fallback para conexão direta.

## Gemini API e privacidade

O pipeline e a geração de wordlists usam **Gemini**. Crie a chave no
[Google AI Studio](https://aistudio.google.com/app/apikey) e configure-a na
VM onde roda o ReconX (nunca na interface web nem no repositório):

```bash
export GEMINI_MODEL="gemini-3.8-flash"
read -rsp 'Chave Gemini: ' GEMINI_API_KEY; echo
export GEMINI_API_KEY
sudo --preserve-env=GEMINI_API_KEY,GEMINI_MODEL reconx
```

`GEMINI_MODEL` é opcional; o padrão atual é `gemini-3.8-flash`. Escolha um modelo
disponível para sua conta que aceite output JSON estruturado. O servidor usa o
endpoint HTTPS `generateContent` e mantém a chave apenas na VM, em arquivo de
header temporário durante cada chamada; não a envia no argumento de processo.
Veja a [referência oficial do Gemini](https://ai.google.dev/api/generate-content).

Cada análise é uma chamada ao Gemini sujeita aos limites/cobrança da sua conta
(até limite + 1 por scan).
O output enviado é limitado a 12 mil caracteres por observação, com no máximo
oito observações recentes. Headers de cookies/autorização e padrões comuns de
segredos são mascarados; valores de query são omitidos. Para páginas HTML,
são enviados texto visível e nomes dos campos, não valores dos inputs.
Observações manuais inseridas pelo operador também são enviadas após a mesma
sanitização heurística.
**A sanitização é heurística e não garante remoção de todos os dados sensíveis.**
Não informe segredos no contexto. O consentimento de envio é obrigatório.
Conteúdo de ferramentas/sites é tratado como dado não confiável; mesmo se uma
instrução maliciosa influenciar a IA, o executor limita catálogo, alvos e gates.

As decisões, autorizações, resultados e motivos ficam em `ai_report.json`
no diretório do scan, também incluídos no JSON final. Outputs brutos permanecem
nos arquivos locais normais do ReconX e podem conter dados sensíveis.

## Validação

```bash
python -B -m unittest discover -s tests -v
```

Os testes usam API e ferramentas simuladas: não chamam a API paga nem atacam
um alvo. Validação real no Kali/MeOwna continua necessária, incluindo os
binários curl, nmap, whatweb e testssl.sh e o modelo Gemini configurado.
