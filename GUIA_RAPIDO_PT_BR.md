# Começar a usar o Oberhau

A versão 1.0 é uma ferramenta local de investigação assistida: os alertas e hipóteses exigem
revisão humana. O escopo e a validação estão em [RELEASE_1_0.md](RELEASE_1_0.md).

Baixe o ZIP Windows x64 em [Releases](https://github.com/If-Kaliel/Oberhau/releases), extraia a
pasta inteira e abra **Oberhau.exe**. O Python vem incluído. Os dados ficam em
`%LOCALAPPDATA%\Oberhau`; copiar a pasta do aplicativo não copia a sua pesquisa.

1. No primeiro uso, ajuste a concorrência e importe a demonstração se quiser conhecer o fluxo.
2. Em **Projetos**, importe uma pasta, arquivo, ZIP ou repositório público que você tem autorização
   para analisar. A importação Git aceita URLs HTTPS do GitHub, GitLab e Codeberg e uma branch/tag.
3. Em **Scanner**, escolha o projeto e o perfil **quick** para começar sem instalar ferramentas.
   O perfil **standard** acrescenta Semgrep. Ferramentas ausentes aparecem como falta de cobertura.
4. Em **Investigações**, abra um alerta. Confira o código, o hash e as observações de cada scanner.
   A análise Python mostra atribuições e referências a chamadas, com limitações explícitas.
5. Registre sua conclusão e justificativa. O alerta estático exige revisão; ele não comprova impacto.
6. Em **Relatórios**, gere um rascunho, revise o texto e exporte Markdown, HTML, JSON ou SARIF.
   O Qwen é opcional: abra o Ollama com `qwen3.5:4b` instalado para gerar um rascunho local.
7. Em **Configurações**, use **Backup da pesquisa** para guardar banco e todas as cópias de código.
   O backup contém código original e possíveis segredos: proteja esse arquivo.

**Laboratório** reproduz somente o exemplo SQL fornecido, em um banco descartável, e compara a
consulta corrigida. O código importado não é executado automaticamente. Esta versão faz pesquisa
offline e não realiza testes ativos em sites, exploração nem envio automático de relatórios.

Para investigar frameworks, escolha o projeto no **Scanner** e abra **Pesquisa contextual**.
Execute a pesquisa, filtre as hipóteses e expanda uma linha para ver as evidências. **Ver código da
evidência** abre um trecho do snapshot após conferir seu hash. **Fluxos de código** lista as relações
observadas; elas não comprovam execução. A apresentação usa tabelas e detalhes; **JSON técnico** é
opcional. A navegação por páginas mantém a interface limitada a 200 resultados por vez.

As validações locais de autorização e entradas, na pesquisa, usam exemplos HTTP sintéticos em
loopback. Elas não executam o projeto importado nem confirmam seus alertas.

Em **Controle de automação**, configure limites de armazenamento ou preveja a limpeza do cache.
A limpeza remove apenas índices sem referência em pesquisas históricas concluídas. Ela preserva
código, hipóteses, decisões humanas e relatórios. Ao atingir um limite, faça um backup completo e
use um novo diretório de dados, ou ajuste o limite conscientemente; o histórico não é apagado.

**Atualizar cópia** mantém o snapshot anterior. **Detalhes do projeto** exibe commit e alterações;
**Comparar arquivo** mostra a diferença com segredos reconhecidos ocultados. Após uma recuperação,
vincule novamente a origem local ou a URL Git antes de atualizar.

Em **Visão geral**, **Detalhes dos scanners** mostra o estado, duração, quantidade de alertas,
erros e procedência de cada execução, inclusive quando não há alertas. Diagnósticos exibem RAM,
GPU NVIDIA quando disponível, ferramentas e modelos reais.

O pacote não inclui scanners opcionais, suas bases de vulnerabilidades ou pesos do Qwen. As
instalações e atualizações são ações explícitas; não existe API paga obrigatória. Consulte
[SCANNERS.md](SCANNERS.md), [BACKUP.md](BACKUP.md) e [WINDOWS_BUILD.md](WINDOWS_BUILD.md).
