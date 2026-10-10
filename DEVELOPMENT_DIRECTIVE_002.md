# OBERHAU — DIRETIVA DE DESENVOLVIMENTO 002
## Advanced Vulnerability Research & Autonomous Investigation

**Repositório:** `If-Kaliel/Oberhau`  
**Base conhecida:** Oberhau 0.4.0  
**Ambiente:** Windows 11  
**IA local:** Ollama + `qwen3.5:4b`  
**Orçamento operacional:** R$ 0  
**Objetivo:** Evoluir o Oberhau de uma plataforma de análise estática e correlação de alertas para um ambiente sofisticado de investigação automatizada de vulnerabilidades.

---

# 1. MISSÃO

Você atuará como arquiteto principal, engenheiro de segurança, desenvolvedor Python e responsável técnico pela evolução do Oberhau.

O projeto já possui uma base funcional. Sua responsabilidade não é reconstruí-la, mas expandir suas capacidades.

A prioridade desta diretiva é melhorar a qualidade e a profundidade das descobertas.

O Oberhau deve ser capaz de identificar, investigar e correlacionar condições potencialmente vulneráveis que ferramentas estáticas convencionais frequentemente não conseguem interpretar adequadamente.

Queremos evoluir de:

**Scanner → Alerta → Relatório**

Para:

**Análise → Hipótese → Investigação contextual → Validação → Evidências → Revisão humana → Relatório**

A máquina deve executar automaticamente o máximo possível das operações repetitivas, mantendo aprovação humana para testes ativos externos, validação final e submissões.

Não apresente suspeitas como vulnerabilidades comprovadas.

# 2. INSPEÇÃO OBRIGATÓRIA DO REPOSITÓRIO

Antes de implementar qualquer alteração:

1. Examine o estado atual do repositório.
2. Identifique a branch de trabalho.
3. Verifique alterações locais não commitadas.
4. Leia `README.md`, `ARCHITECTURE.md`, `ROADMAP.md`, `WORKLOG.md`, `SECURITY_MODEL.md` e `TESTING.md`.
5. Inspecione os módulos existentes de análise, orquestração, correlação, investigação, relatórios e integração com Ollama.
6. Execute a suíte de testes existente.
7. Identifique funcionalidades existentes que podem ser reutilizadas.

A versão examinada anteriormente possuía scanners integrados, histórico, snapshots Git, correlação conservadora, relatórios Qwen e um laboratório SQL.

Confirme o estado atual antes de assumir que essas informações continuam válidas.

Não reimplemente funcionalidades existentes sem necessidade.

Não introduza regressões para acomodar uma nova arquitetura.

Preserve a separação entre motor de pesquisa, persistência, interface gráfica e ferramentas externas.

Trabalhe preferencialmente na branch `testes`, preservando `main` como versão estável.

Não realize merge para `main` sem testes aprovados e instrução explícita do usuário.

# 3. RESTRIÇÃO ABSOLUTA: GRATUIDADE

Todas as novas funcionalidades devem operar gratuitamente.

Não introduza dependências obrigatórias de:

- APIs pagas de IA.
- Serviços comerciais de análise.
- Bancos de vulnerabilidades premium.
- Computação em nuvem.
- Assinaturas de segurança.
- Planos pagos do GitHub.
- Ferramentas proprietárias com licenças comerciais obrigatórias.

Utilize bibliotecas e ferramentas gratuitas compatíveis com suas respectivas licenças.

A aplicação deve continuar executável localmente no Windows 11.

O Qwen já instalado pelo usuário deve ser aproveitado.

Não exija novos modelos grandes nem aquisição de hardware.

# 4. PRIORIDADE MÁXIMA: CONTEXTUAL SECURITY ANALYSIS

Desenvolva um novo subsistema de análise contextual de segurança.

Este subsistema deve investigar relações entre diferentes componentes do código, em vez de depender exclusivamente de correspondências de padrões.

Nome sugerido:

`Contextual Investigation Engine`

Ele deve ser capaz de construir representações estruturadas de partes relevantes de um projeto.

Investigue bibliotecas gratuitas para parsing, AST, análise de fluxo de dados e grafos de chamadas.

Use parsers específicos por linguagem quando necessário.

Não implemente um parser complexo do zero se houver uma alternativa madura e gratuita.

## Capacidades desejadas

- Identificar pontos de entrada de dados.
- Localizar operações sensíveis.
- Rastrear transformações de valores.
- Identificar funções intermediárias.
- Inspecionar verificações de autenticação.
- Inspecionar verificações de autorização.
- Reconhecer validações e sanitizações.
- Comparar fluxos de código equivalentes.
- Identificar verificações inconsistentes.
- Correlacionar dependências entre módulos.
- Investigar possíveis fluxos inseguros.
- Construir caminhos de investigação com evidências verificáveis.

## Fontes e operações sensíveis

Reconheça, conforme a linguagem e o framework:

- Parâmetros HTTP.
- Corpos JSON.
- Headers.
- Cookies.
- IDs de usuário e recursos.
- Dados de sessão.
- Entradas de formulários.
- Arquivos enviados.
- Variáveis de ambiente.
- Consultas a bancos de dados.
- Operações de arquivos.
- Requisições HTTP de saída.
- Comandos do sistema.
- Renderização HTML.
- Operações administrativas.
- Alterações de permissões.

Não considere automaticamente que uma entrada é controlada por um atacante.

Não considere que a ausência de um controle em uma função significa ausência do controle em todo o fluxo.

Analise chamadas intermediárias e proteções externas quando houver informações suficientes.

Quando o contexto não permitir uma conclusão, registre explicitamente a incerteza.

# 5. FRAMEWORK SECURITY INTELLIGENCE

Crie perfis especializados inicialmente para três ecossistemas.

## 5.1 Next.js / Node.js / TypeScript

Investigar:

- Route Handlers.
- Server Actions.
- Middleware.
- Autenticação.
- Controle de acesso.
- Uso de cookies e sessões.
- Fluxos envolvendo identificadores de recursos.
- Validação de entradas.
- Operações de banco de dados.
- Exposição de dados sensíveis.
- Separação entre cliente e servidor.
- Uso inseguro de funções privilegiadas.

Priorize especialmente falhas de autorização e inconsistências entre diferentes endpoints.

## 5.2 Java / Spring Boot

Investigar:

- Controllers REST.
- Service Layer.
- Repositories.
- Spring Security.
- Filtros e interceptadores.
- Anotações de autorização.
- Verificações em nível de objeto.
- Manipulação de dados de usuários.
- Operações administrativas.
- Validação de entrada e acesso a dados.

## 5.3 C# / ASP.NET Core

Investigar:

- Controllers.
- Minimal APIs.
- Middleware.
- Authentication Schemes.
- Authorization Policies.
- Claims.
- Entity Framework.
- Operações sensíveis.
- Verificações de propriedade dos recursos.
- Inconsistências na aplicação das políticas.

Esses perfis devem compartilhar um modelo de evidências, mas suas análises devem respeitar as particularidades de cada framework.

Evite utilizar as mesmas heurísticas genéricas para todos os ecossistemas.

# 6. INVESTIGAÇÃO DE AUTENTICAÇÃO E AUTORIZAÇÃO

Este módulo merece prioridade especial.

Implemente análise capaz de comparar caminhos de acesso a operações sensíveis.

Exemplos de hipóteses que o sistema deve conseguir levantar:

- Uma rota acessa um recurso sem uma verificação de propriedade visível.
- Um endpoint exige determinada permissão, mas outro endpoint equivalente parece não exigir.
- Uma operação administrativa depende apenas de uma verificação insuficiente.
- Uma verificação de identidade está presente, mas a autorização sobre o recurso não está demonstrada.
- Uma proteção existe no frontend, mas não há evidência suficiente de proteção no backend.

Esses exemplos são hipóteses de pesquisa, não conclusões automáticas.

O sistema deve buscar evidências contrárias à hipótese antes de promovê-la.

Crie um mecanismo de comparação entre rotas ou operações funcionalmente relacionadas.

Priorize investigação de diferenças inesperadas nas políticas de acesso.

Toda suspeita deve incluir:

- Operação analisada.
- Entradas relevantes.
- Caminho de execução conhecido.
- Verificações identificadas.
- Verificações não encontradas.
- Limitações da análise.
- Arquivos e linhas envolvidos.
- Evidências necessárias para confirmação.

# 7. ANÁLISE DE FLUXO DE DADOS

Amplie as capacidades atuais de investigação Python e implemente infraestrutura para análises estruturais adicionais.

Priorize:

- Rastreamento intraprocedural confiável.
- Grafo de chamadas limitado.
- Propagação de valores entre funções suportadas.
- Reconhecimento de sanitizadores.
- Reconhecimento de verificações condicionais.
- Análise conservadora de caminhos.
- Identificação de operações sensíveis.
- Explicação dos caminhos encontrados.

Não afirme suporte completo a análise interprocedural se apenas subconjuntos estiverem implementados.

Não confunda correspondência sintática com prova de alcançabilidade.

Permita que cada descoberta mostre visualmente ou textualmente seu caminho de evidências.

Por exemplo:

Entrada identificada → Transformação conhecida → Função intermediária → Operação sensível.

Quando algum trecho não puder ser resolvido, apresente uma interrupção explícita no caminho de análise.

# 8. INVESTIGADOR LOCAL ASSISTIDO POR QWEN

O Qwen atualmente é utilizado principalmente para elaboração de relatórios.

Amplie sua participação para investigação assistida, mantendo o motor determinístico como fonte de evidências.

Crie o módulo:

`AI Research Assistant`

Responsabilidades:

- Interpretar achados normalizados.
- Examinar trechos de código relevantes.
- Comparar caminhos potencialmente equivalentes.
- Identificar perguntas que precisam ser respondidas.
- Sugerir verificações locais.
- Sintetizar evidências.
- Apontar possíveis falsos positivos.
- Propor hipóteses adicionais.
- Explicar por que determinada suspeita merece investigação.

## Arquitetura

Não envie repositórios inteiros ao Qwen.

Implemente ferramentas internas de consulta ao índice do projeto.

O modelo poderá solicitar dados por meio de interfaces estruturadas e limitadas, como:

- Localizar função.
- Consultar símbolos.
- Ler trecho de arquivo.
- Consultar referências.
- Inspecionar chamadas conhecidas.
- Consultar achados anteriores.
- Obter resultados de scanners.
- Consultar alterações Git.

Cada solicitação deverá passar por validação determinística.

Não permita execução arbitrária de comandos gerados pelo modelo.

Utilize iterações limitadas, cancelamento, orçamento de contexto e controle de recursos.

As respostas deverão empregar esquemas estruturados.

Exija que as conclusões relevantes referenciem evidências do repositório ou resultados registrados.

## Limitações

O modelo `qwen3.5:4b` é relativamente pequeno.

Não assuma capacidade confiável de raciocínio profundo em projetos extensos.

Prefira decompor tarefas, reduzir contexto, fornecer dados estruturados e verificar suas conclusões.

Mantenha o sistema funcional quando o Ollama estiver desligado.

# 9. INTELLIGENT TRIAGE ENGINE

Desenvolva uma triagem que reduza o trabalho manual do operador.

O objetivo não é simplesmente atribuir pontuações altas a determinadas palavras ou CWEs.

Considere separadamente:

- Severidade estimada.
- Confiança da detecção.
- Qualidade das evidências.
- Existência de testes reproduzíveis.
- Possível impacto.
- Cobertura dos controles de segurança.
- Existência de proteções compensatórias.
- Correspondência com advisories conhecidos.
- Histórico de achados similares.
- Possibilidade de duplicidade.
- Elegibilidade conhecida do programa.

Crie uma fila priorizada de investigação.

Exija justificativas para cada classificação.

Permita ao usuário corrigir resultados, marcar falsos positivos e registrar decisões.

Use esse histórico para melhorar heurísticas locais de priorização, sem treinar modelos automaticamente sobre dados sensíveis.

Não remova achados de baixa prioridade silenciosamente.

# 10. GIT CHANGE INTELLIGENCE

A infraestrutura de snapshots Git já existe.

Expanda-a para pesquisas orientadas a alterações.

Implemente:

- Monitoramento opcional de atualizações em repositórios autorizados.
- Comparação entre commits.
- Identificação de mudanças em componentes sensíveis.
- Análise de controles de segurança adicionados ou removidos.
- Reavaliação de achados afetados.
- Rastreamento de alterações em dependências.
- Agrupamento de mudanças relacionadas.
- Histórico de investigações associado a commits.
- Priorização de código alterado recentemente.

O sistema deve conseguir distinguir:

- Problema já observado.
- Novo alerta em arquivo alterado.
- Alerta removido após correção.
- Possível regressão.
- Mudança que exige revisão de segurança.

Não interprete toda correção como evidência de vulnerabilidade explorável.

Não marque descobertas como inéditas apenas porque são novas no banco local.

# 11. AUTOMATED RESEARCH WORKFLOW

Crie um fluxo automatizado completo de pesquisa offline.

Exemplo de funcionamento:

1. O usuário registra um repositório autorizado.
2. Configura um perfil de investigação.
3. O Oberhau importa ou atualiza o snapshot.
4. Executa os scanners disponíveis.
5. Normaliza e correlaciona achados.
6. Identifica alterações relevantes.
7. Executa análises contextuais suportadas.
8. Abre hipóteses estruturadas.
9. Busca evidências adicionais no código.
10. Prioriza as hipóteses.
11. Executa verificações determinísticas locais permitidas.
12. Utiliza Qwen para resumir os achados, quando habilitado.
13. Armazena resultados e histórico.
14. Notifica o operador sobre descobertas que merecem revisão.

Todo esse fluxo deve poder operar sem intervenção constante quando limitado a ações offline previamente autorizadas.

Suporte:

- Execução manual.
- Execução agendada.
- Reanálise incremental.
- Limites de tempo.
- Limites de memória.
- Limites de concorrência.
- Cancelamento.
- Recuperação após falhas.
- Prevenção de trabalhos repetidos.
- Histórico completo de execução.

Não execute automaticamente testes ativos em sistemas externos.

Não instale serviços persistentes no Windows sem consentimento explícito.

# 12. LOCAL VALIDATION FRAMEWORK

O laboratório existente é limitado.

Desenvolva uma infraestrutura extensível para validações locais controladas.

Suporte:

- Aplicações HTTP locais.
- APIs simuladas.
- Fixtures vulneráveis.
- Fixtures corrigidas.
- Dados sintéticos.
- Bancos temporários.
- Resultados esperados.
- Resultados observados.
- Testes de regressão.
- Evidências estruturadas.
- Limpeza automática de ambientes temporários.

Adicione receitas de teste seguras para várias classes de falha.

Priorize inicialmente:

- Injeção em código de laboratório.
- Falhas de autorização em APIs locais.
- Validação inadequada de entrada.
- Exposição indevida de informações sintéticas.
- Configurações inseguras.
- Problemas conhecidos em dependências.

Não execute automaticamente código importado de terceiros apenas porque ele faz parte de um projeto analisado.

Mantenha uma distinção estrita entre fixtures confiáveis e repositórios não confiáveis.

Se for utilizar Docker, trate-o como dependência opcional.

# 13. BENCHMARKS REAIS DE DETECÇÃO

Esta etapa é obrigatória.

O Oberhau precisa provar que suas novas funcionalidades identificam problemas reais em condições controladas.

Crie uma suíte de avaliação independente dos testes unitários.

Utilize:

- Fixtures vulneráveis próprias.
- Controles corrigidos.
- Projetos educacionais intencionalmente vulneráveis.
- Casos de segurança publicados com licença compatível.
- Exemplos de código com proteções válidas para testar falsos positivos.

Sempre que possível, utilize casos que não tenham servido para desenvolver as heurísticas.

Não altere o benchmark para fazer uma implementação deficiente parecer correta.

Registre:

- Vulnerabilidades esperadas.
- Vulnerabilidades detectadas.
- Vulnerabilidades não detectadas.
- Falsos positivos.
- Precisão.
- Recall, quando mensurável.
- Tempo de análise.
- Memória utilizada.
- Categorias efetivamente cobertas.

Relate claramente conjuntos pequenos ou não representativos.

Nenhum resultado deve ser apresentado como capacidade comprovada de encontrar zero-days sem evidência apropriada.

# 14. RESEARCH EVIDENCE GRAPH

Implemente uma estrutura que represente as relações entre evidências.

Entidades possíveis:

- Projeto.
- Commit.
- Arquivo.
- Função.
- Endpoint.
- Fonte de dados.
- Operação sensível.
- Controle de segurança.
- Alerta do scanner.
- Hipótese.
- Teste local.
- Resultado de validação.
- Revisão humana.
- Relatório.

Permita visualizar a origem de cada conclusão.

Evite depender exclusivamente de longos textos gerados por IA.

O sistema deve permitir responder:

"Por que o Oberhau considera esse código suspeito?"

E apresentar evidências concretas.

Se não houver evidências suficientes, o sistema deve dizer isso explicitamente.

# 15. DESKTOP INTERFACE EXPANSION

Preserve a identidade visual existente do Oberhau:

- Preto.
- Grafite.
- Cinza.
- Branco.
- Espada partindo uma caveira.
- Interface sóbria e profissional.

Não redesenhe a aplicação desnecessariamente.

Amplie a interface para incorporar:

**Investigation Workspace**

Painel dedicado a hipóteses, arquivos relevantes, caminhos de análise e evidências.

**Code Flow Viewer**

Representação de fluxos conhecidos entre fontes de dados, verificações e operações sensíveis.

**AI Investigator**

Interface de investigação com Qwen, incluindo perguntas, evidências consultadas e limitações.

**Research Queue**

Fila organizada de descobertas que merecem análise humana.

**Git Intelligence**

Histórico de alterações, possíveis regressões e novas suspeitas.

**Benchmark Dashboard**

Métricas reais de precisão, recall e desempenho.

**Automation Control**

Gerenciamento de pesquisas programadas e recursos utilizados.

## Refatoração da interface

O arquivo `src/oberhau/desktop/app.py` estava relativamente grande na versão examinada.

Avalie separar páginas e componentes da interface sem alterar desnecessariamente seu funcionamento.

Não faça uma grande refatoração apenas por preferência estética.

Priorize mudanças incrementais com testes de regressão.

# 16. RESOURCE MANAGEMENT

A aplicação precisa continuar confortável no computador do operador.

Hardware conhecido:

- Windows 11.
- NVIDIA RTX 4060, 8 GB de VRAM.
- 32 GB de RAM.
- Ollama local.

Implemente gerenciamento prudente de recursos.

Requisitos:

- Fila única ou configurável de inferências.
- Controle de concorrência.
- Liberação do Qwen após operações concluídas.
- Execução sem IA quando apropriado.
- Indexação incremental.
- Reutilização de resultados.
- Limites de memória.
- Pausa manual.
- Interrupção limpa.
- Monitoramento de tarefas.
- Prevenção de processamento desnecessário.

Se possível, adicione pausa automática quando o computador estiver executando aplicações que utilizem intensamente a GPU, mas mantenha essa funcionalidade opcional.

# 17. SECURITY AND AUTHORIZATION

Preserve e fortaleça o modelo de segurança existente.

O Oberhau deve continuar limitado a:

- Análise offline de código legitimamente acessível.
- Projetos autorizados.
- Ambientes locais de laboratório.
- Testes externos somente quando expressamente permitidos, com revisão humana e controles específicos.

Não implemente:

- Varredura indiscriminada de hosts.
- Exploração automática de sistemas públicos.
- Ataques de força bruta.
- Exfiltração de dados.
- Destruição ou modificação não autorizada de informações.
- Execução irrestrita de comandos produzidos por IA.
- Submissão automática de relatórios de bug bounty.

O código importado deve continuar sendo tratado como não confiável.

Fortaleça, quando relevante:

- Tratamento de caminhos.
- Isolamento de processos.
- Controle de rede.
- Execução de scanners.
- Validação de entradas.
- Proteção contra prompt injection.
- Redação de credenciais.
- Integridade dos snapshots.
- Segurança dos backups.
- Controle de recursos.

Se uma integração exigir uma mudança arriscada no modelo de segurança, documente-a e prefira uma alternativa segura.

# 18. PERFORMANCE AND QUALITY

Priorize qualidade de descoberta sobre volume de alertas.

Não considere um resultado melhor simplesmente porque um novo scanner produz mais avisos.

Métricas relevantes:

- Novas hipóteses com evidências.
- Problemas reproduzidos em laboratório.
- Falsos positivos eliminados.
- Tempo economizado na investigação.
- Profundidade da análise.
- Cobertura de frameworks.
- Regressões identificadas.
- Qualidade dos relatórios.
- Capacidade de reproduzir resultados.

Crie testes com exemplos vulneráveis e não vulneráveis.

Um detector que marca todos os endpoints como inseguros deve ser considerado deficiente, mesmo que encontre casos realmente vulneráveis.

# 19. IMPLEMENTATION ORDER

Execute o desenvolvimento em etapas verificáveis.

## Etapa A — Foundation and Investigation Graph

- Revisão da arquitetura.
- Modelos de evidências.
- Representação estruturada dos caminhos.
- Persistência.
- Testes.

## Etapa B — Framework-Aware Analysis

- Next.js / TypeScript.
- Spring Boot / Java.
- ASP.NET Core / C#.
- Regras contextuais.
- Casos positivos e negativos.

## Etapa C — Automated Investigation

- Investigação contextual.
- Correlação de caminhos.
- Análise de autorização.
- Classificação de hipóteses.
- Explicações baseadas em evidências.

## Etapa D — Qwen Research Assistant

- Ferramentas estruturadas.
- Consulta limitada ao código.
- Iterações controladas.
- Justificativas verificáveis.
- Integração com o relatório existente.

## Etapa E — Git Intelligence

- Monitoramento opcional.
- Comparação de versões.
- Investigações incrementais.
- Histórico de regressões.

## Etapa F — Local Validation

- Novos laboratórios.
- Testes HTTP locais.
- Evidências reproduzíveis.
- Regressões de segurança.

## Etapa G — GUI and Automation

- Novos painéis.
- Fluxo completo de investigação.
- Agendamentos.
- Notificações.
- Gerenciamento de recursos.

## Etapa H — Benchmark and Hardening

- Benchmark independente.
- Avaliação de falsos positivos.
- Testes de segurança.
- Correções de desempenho.
- Revisão da documentação.
- Validação do aplicativo Windows.

Não avance adicionando funcionalidades superficiais quando uma etapa fundamental estiver quebrada.

# 20. DEVELOPMENT DISCIPLINE

Mantenha a base do projeto estável.

Regras:

1. Não descarte código funcional.
2. Não substitua análises determinísticas por opiniões de IA.
3. Não crie interfaces desconectadas do backend.
4. Não gere falsos resultados para preencher dashboards.
5. Não apresente heurísticas como provas de exploração.
6. Não ignore testes falhando.
7. Não introduza serviços pagos.
8. Não modifique `main` automaticamente.
9. Não execute testes em alvos externos sem autorização.
10. Não produza apenas scaffolding e declare o trabalho concluído.

Faça commits verificáveis e bem delimitados.

Atualize `WORKLOG.md`, `ROADMAP.md`, `ARCHITECTURE.md`, `TESTING.md` e demais documentos relevantes conforme as implementações.

Preserve evidências do que foi realmente testado.

Não infle contagens de testes ou métricas de cobertura.

Se uma funcionalidade não puder ser concluída, registre precisamente o estado alcançado.

# 21. ACCEPTANCE CRITERIA

A evolução será considerada bem-sucedida quando o Oberhau conseguir demonstrar, em testes controlados:

1. Importação de um projeto real.
2. Identificação de seus principais componentes de segurança.
3. Mapeamento de operações sensíveis em frameworks suportados.
4. Identificação de hipóteses contextuais fundamentadas.
5. Recuperação das evidências de código utilizadas.
6. Reconhecimento de pelo menos alguns controles que invalidam suspeitas.
7. Correlacionamento com resultados dos scanners existentes.
8. Geração de uma fila priorizada de investigação.
9. Consulta ao Qwen para explicações baseadas em evidências.
10. Execução de testes locais suportados.
11. Registro de resultados reproduzíveis.
12. Comparação com versões corrigidas.
13. Atualização incremental das investigações.
14. Exportação de relatórios para revisão humana.
15. Apresentação de métricas mensuráveis de desempenho e falsos positivos.

A suíte de avaliação deve incluir casos não utilizados durante o desenvolvimento.

Documente quais critérios foram demonstrados e quais continuam parciais ou não implementados.

# 22. FINAL DIRECTIVE

Oberhau não deve ser apenas uma interface para executar Semgrep, Trivy e outros scanners.

Seu diferencial deve ser a capacidade de investigar o relacionamento entre diferentes partes de um sistema, reconhecer suspeitas relevantes, reunir evidências e reduzir a carga de investigação manual.

Não busque inteligência aparente por meio de textos convincentes gerados por IA.

Busque inteligência operacional demonstrada por resultados reproduzíveis.

Priorize mecanismos que aumentem a probabilidade de identificar problemas reais que análises superficiais deixariam passar.

A meta de longo prazo é apoiar pesquisas legítimas em programas de bug bounty, respeitando integralmente seus escopos e restrições.

Nenhum ganho financeiro é garantido, e detecção não equivale a elegibilidade.

**Comece inspecionando o estado atual do repositório e executando os testes. Em seguida, implemente os novos subsistemas em etapas funcionais. Continue desenvolvendo enquanto houver trabalho viável nesta sessão, preservando a integridade do código, dos dados e da branch estável.**