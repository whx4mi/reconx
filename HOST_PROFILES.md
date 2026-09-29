# Perfis por host — primeira etapa

O ReconX agora mantém um perfil para cada hostname ou IP em `results/reconx.db`. A aba **Hosts** lista os alvos escaneados; clicar em um host abre uma página própria em outra aba com histórico, outputs, achados atribuídos, serviços, recomendações e checklist persistente. URLs com portas ou caminhos diferentes do mesmo hostname compartilham o perfil; hostnames e IPs diferentes não são fundidos automaticamente.

## Fluxo

1. Informe o alvo e inicie uma scan. O perfil é criado automaticamente e aparece na aba **Hosts**. Perfis cadastrados sem nenhuma scan não aparecem nessa lista.
2. Execute **Recon inicial por host**. Uma porta/serviço HTTP observado libera a sugestão **Recon web segmentado**. Uma rota de API observada libera **Recon API segmentado** depois de recon bem-sucedido.
3. Clique no host para abrir sua página própria. Revise os resultados e as recomendações, depois use **Preparar no ReconX** se quiser seguir um pipeline. Isso abre o formulário com alvo e pipeline preenchidos; o operador ainda precisa revisar escopo e iniciar a execução. O servidor também verifica os pré-requisitos dos dois pipelines segmentados.
4. Atualize cada item do checklist com estado, nota e referência de evidência. **Testado** exige evidência. Execução de ferramenta, inclusive exit code 0, nunca marca um item como testado automaticamente.

Os pipelines antigos seguem disponíveis durante a transição. A triagem Gemini permanece separada e suas ações continuam sujeitas às aprovações já implementadas. Esta etapa ainda não implementa um motor de exploração/pós-exploração, inventário cloud estruturado, importação de código WhiteBox nem uma matriz completa de cobertura por endpoint/parâmetro. “Liberado” indica somente dados suficientes para sugerir recon adicional; não é autorização para explorar.

Os dados novos são adicionados ao SQLite existente sem apagar scans ou findings. O instalador copia `host_profiles.py`; depois de atualizar o repositório no Kali, execute o fluxo normal de atualização/instalação. Não cole credenciais ou tokens no checklist: notas e referências de evidência são guardadas em texto no SQLite local.
