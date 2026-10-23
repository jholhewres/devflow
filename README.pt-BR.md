# stagegate

Um fluxo de engenharia para agentes de código, com gates de evidência. O
trabalho passa por **briefing → contexto → plano → execução → review →
conclusão** e só está pronto quando a evidência diz: os checks rodaram depois
da última mudança e passaram, cada critério de aceite tem um teste ou uma
prova, e revisores independentes, nos seus próprios CLIs de agente, não
encontraram nada que bloqueie.

Roda onde o agente roda: uma linha de comando `stagegate` e um servidor MCP
por stdio, para Claude Code, Codex, Gemini CLI, Cursor, OpenCode ou qualquer
IDE que fale MCP. A configuração e a evidência ficam no seu repositório.

> **Estado: inicial.** Isto é o scaffold. O motor está sendo extraído do
> Devflow do [devpit](https://github.com/jholhewres/devpit), onde roda hoje.
> As fases estão em [docs/plan.md](docs/plan.md) e o que muda de lugar em
> [docs/extraction-map.md](docs/extraction-map.md).
> [Read in English](README.md).

## O que faz

- **Stages com gates.** Cada stage é uma skill que o agente segue; um stage
  seu pode ter como gate um comando que sai com 0 ou uma rubrica.
- **Checks como evidência.** Seus comandos de teste, lint e E2E, detectados no
  repositório, rodam com o contexto só em variáveis de ambiente. Os relatórios
  (JUnit, Vitest, Jest, cargo, Go) ficam guardados por execução.
- **Review de quem não escreveu o código.** Personas de spec, padrões e
  segurança revisam o diff em modo headless, cada uma no CLI que você escolher,
  todas no mesmo schema de findings; `block_on` decide o que para o trabalho.
- **Gate no fim do turno.** Hooks seguram o turno do agente até o gate passar,
  onde o CLI tem hook de parada.
- **Camadas.** Seus padrões pessoais, os do time (fixados num commit que você
  aprovou, com campos que ele pode travar) e os do projeto.
- **Review de pull request.** De um PR, de um intervalo de commits ou de uma
  worktree, rascunhado e publicado só depois do seu sim.

## Instalação

Ainda não publicado. A partir do código:

```sh
cargo install --git https://github.com/jholhewres/stagegate stagegate
stagegate --help
```

## Uso hoje

```sh
stagegate status            # qual configuração vale aqui
```

Lê `stagegate.yaml`, `.stagegate/stagegate.yaml` ou o
`.devpit/devflow/devflow.yaml` do devpit, quando o projeto já tem um.

## Desenvolvimento

```sh
make check    # rustfmt --check, clippy -D warnings, testes
```

Veja [CONTRIBUTING.md](CONTRIBUTING.md).

## Licença

[Apache-2.0](LICENSE). O [NOTICE](NOTICE) diz de onde vem o código.
