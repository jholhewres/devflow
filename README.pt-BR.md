# devflow

Um fluxo de engenharia para agentes de código, com gates de evidência,
entregue como **servidor MCP e plugin**. O trabalho passa por **briefing →
contexto → plano → execução → review → conclusão** e só está pronto quando a
evidência diz: os checks rodaram depois da última mudança e passaram, cada
critério de aceite tem um teste ou uma prova, e revisores independentes, nos
seus próprios CLIs de agente, não encontraram nada que bloqueie.

Funciona com Claude Code (como plugin), Codex, Gemini CLI (como extensão),
Cursor, OpenCode, VS Code e qualquer outro cliente MCP. A configuração e a
evidência ficam no seu repositório.

> **Estado: inicial.** O servidor MCP, o instalador e a release estão
> prontos; o motor está sendo portado do Devflow do
> [devpit](https://github.com/jholhewres/devpit), onde roda hoje. As fases
> estão em [docs/plan.md](docs/plan.md). [Read in English](README.md).

## Instalação

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
```

Baixa a release da sua máquina, confere com o `checksums.txt` da release,
coloca o `devflow` em `~/.local/bin` e registra em cada CLI de agente e IDE
que encontrar. Opções: `--tools=claude,codex`, `--dry-run`, `--uninstall`,
`--version=X.Y.Z`; veja [docs/integrations.md](docs/integrations.md).

Só no Claude Code:

```text
/plugin marketplace add jholhewres/devflow
/plugin install devflow@devflow
```

O plugin inicia `devflow mcp`, então o binário precisa estar no `PATH`.

## O que faz

- **Stages com gates.** Cada stage é uma skill que o agente segue; um stage
  seu pode ter como gate um comando que sai com 0 ou uma rubrica.
- **Checks como evidência.** Seus comandos de teste, lint e E2E, detectados
  no repositório, rodam com o contexto só em variáveis de ambiente. Os
  relatórios (JUnit, Vitest, Jest, cargo, Go) ficam guardados por execução.
- **Review de quem não escreveu o código.** Personas de spec, padrões e
  segurança revisam o diff em modo headless, cada uma no CLI que você
  escolher, no mesmo schema de findings; `block_on` decide o que para o
  trabalho.
- **Gate no fim do turno**, por hooks onde o CLI tem.
- **Camadas.** Seus padrões pessoais, os do time (fixados num commit que você
  aprovou, com campos que ele pode travar) e os do projeto.
- **Decisions (Jev)**, opcional: rubricas tipadas julgadas por um modelo via
  OpenRouter, em shadow ou enforce.
- **Review de pull request**, rascunhado e publicado só depois do seu sim.

## Hoje

```sh
devflow status               # qual configuração vale aqui
devflow register --dry-run   # o que o registro mudaria
devflow mcp                  # o servidor; os CLIs de agente iniciam
```

O servidor responde `status`. As outras tools chegam com o port.

## Desenvolvimento

```sh
make check            # rustfmt --check, clippy -D warnings, testes, versões
make sync-version     # depois de mudar o VERSION
```

Veja [CONTRIBUTING.md](CONTRIBUTING.md).

## Licença

[Apache-2.0](LICENSE). O [NOTICE](NOTICE) diz de onde vem o código.
