# ReconX Next — fluxo operacional orientado por cobertura

## Objetivo

O operador escolhe um tipo de avaliação e acompanha cinco fases estáveis, em vez
de montar mentalmente uma sequência de ferramentas. Ferramentas continuam sendo
adapters internos; a unidade visível de trabalho é uma hipótese de cobertura.

## Garantia possível

O ReconX não pode garantir que toda vulnerabilidade existente será encontrada.
Ele deve garantir **completude contábil da operação**:

- todo teste planejado termina como `completed`, `failed`, `blocked`, `skipped`
  ou `cancelled`, sempre com motivo e evidência de execução;
- toda descoberta termina como `consumed`, `retained`, `out_of_scope`,
  `not_applicable` ou `discarded`, sempre com justificativa;
- todo candidato termina como `confirmed`, `likely`, `possible`,
  `not_reproduced`, `false_positive` ou `inconclusive`;
- uma fase somente fica verde quando seus critérios de saída estão satisfeitos;
- lacunas por ferramenta ausente, timeout, autenticação, limite ou falta de
  parâmetro permanecem visíveis e nunca viram “não vulnerável”.

## Fases

### 1. Reconhecimento

Entrada: alvo e regras de engajamento.

Saída: origem normalizada, fingerprint, DNS/certificados e serviços iniciais.

Gate: o alvo foi alcançado ou a impossibilidade foi registrada; escopo e impacto
das próximas fases foram revisados.

### 2. Descoberta e enumeração

Entrada: ativos confirmados pelo reconhecimento.

Saída: hosts, portas, aplicações, rotas, parâmetros, formulários, APIs,
tecnologias e relações de proveniência.

Gate: cada descoberta acionável foi encaminhada para uma hipótese posterior ou
recebeu uma disposição explícita.

### 3. Varredura orientada

Entrada: superfície tipada. Ferramentas web recebem URLs completas; ferramentas
de rede recebem hosts; scanners de parâmetros recebem requests compatíveis.

Saída: candidatos com evidência bruta, cobertura negativa e lacunas.

Gate: todos os testes autorizados e aplicáveis chegaram a um estado terminal.

### 4. Validação e PoC

Entrada: candidatos deduplicados por causa-raiz, endpoint, parâmetro e
comportamento.

Saída: candidato confirmado, descartado, não reproduzido ou inconclusivo, com
procedimento e evidência. Ações mutáveis ou agressivas exigem aprovação.

Gate: nenhum candidato permanece sem responsável, próximo teste ou motivo de
encerramento.

### 5. Relatório e reteste

Entrada: cobertura, lacunas e candidatos triados.

Saída: achados formais, limitações, recomendações e plano de reteste.

Gate: o relatório reconcilia objetivos, ativos, testes planejados e resultados.

## Modelo de rastreabilidade

```text
objetivo
  └─ hipótese de cobertura
       ├─ execução de ferramenta ──> artefato bruto
       ├─ descoberta ──────────────> nova hipótese
       └─ candidato ───────────────> validação/PoC ──> achado
```

Cada aresta preserva `scan_id`, fase de origem, alvo, ferramenta, horário e
motivo. Evidência mais forte atualiza o mesmo candidato em vez de criar uma
contagem paralela.

## Entregas incrementais

1. **Navegação por fases:** agrupar os pipelines existentes nas cinco fases e
   explicar o objetivo de cada uma. Implementado como primeira fatia.
2. **Ledger persistente:** tabelas de `stage_runs`, `tool_runs`,
   `discovery_items` e `coverage_items`, com estados terminais e razões.
   Implementado; disponível na aba **Cobertura** e em
   `GET /api/scan/<scan_id>/ledger`.
3. **Gates:** critérios de saída calculados e bloqueio explícito antes de fases
   mais agressivas.
4. **Roteador de descobertas:** cada ativo/rota/parâmetro gera trabalho
   aplicável ou uma disposição auditável.
5. **Fila de validação:** candidatos priorizados, PoCs seguros e aprovações para
   impacto alto.
6. **Relatório de cobertura:** mostrar testado, não aplicável, bloqueado, falhou
   e não testado separadamente.

## Relação com o Pinorch

O ReconX permanece o motor e produto principal. Do Pinorch devem migrar o
planejador de atividades autorizadas, o preview de política, o reteste
controlado e a linguagem guiada. Não se deve manter uma segunda implementação
de executor; o Pinorch fica como referência de UX e pode, futuramente, virar um
cliente do ReconX ou ser arquivado após paridade funcional.
