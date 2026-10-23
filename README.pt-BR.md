<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/devflow-logo-dark.png">
    <img src="docs/assets/devflow-logo.png" alt="devflow, by devpit.app" width="420">
  </picture>
</p>

<p align="center">
  Um fluxo de engenharia guiado por evidência para agentes de código, como servidor MCP e plugin.
</p>

<p align="center">
  <a href="README.md">English</a> &middot; <b>Português</b>
</p>

<p align="center">
  <img src="docs/assets/devflow-flow.svg" alt="briefing, contexto, plano, execução, revisão, conclusão; pronto só quando as checagens passam depois da última mudança, todo critério de aceite está provado e a revisão não tem achados bloqueantes" width="100%">
</p>

O trabalho está pronto quando a evidência diz, não quando o agente diz:
checagens verdes depois da última mudança, cada critério de aceite provado
por um teste ou um arquivo de prova, uma revisão que não bloqueia nada.
Configuração, work items e execuções ficam no seu repositório.

## Instalação

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh -s -- --version=0.0.1-rc.2
devflow setup
```

O `install.sh` confere o checksum da release, coloca o `devflow` em
`~/.local/bin` e o registra nas CLIs de agente e IDEs que encontrar
(`--tools=`, `--dry-run`, `--uninstall`). Por enquanto só há pré-releases,
por isso o `--version`. O `devflow setup` escreve o `devflow.yaml` do projeto
e liga o devflow, perguntando antes.

## Uso

| Ferramenta | O que recebe |
|---|---|
| Claude Code | plugin: tools MCP, skills `/devflow:<etapa>`, `/devflow:status`, `/devflow:pr`, subagentes revisores, o Stop hook do gate |
| Codex | tools MCP (`codex mcp add devflow -- devflow mcp`) |
| Gemini CLI | extensão: tools MCP e `GEMINI.md` |
| Cursor, OpenCode, VS Code | tools MCP |

Depois, peça o trabalho ao seu agente. Ele faz o brief, planeja em work items
(`.devflow/work/`) depois do seu sim, constrói cada um com teste primeiro,
roda as checagens (`evidence`), manda revisar headless nas suas próprias CLIs
de revisão (`review`) e só pode dar como pronto quando o `gate` passa.

| Comando | Faz |
|---|---|
| `devflow setup` · `doctor` | configura esta máquina e o projeto · confere |
| `devflow config get` · `set <campo> <valor>` | lê ou muda o `devflow.yaml` |
| `devflow jev setup` · `test` | Decisions (Jev) via OpenRouter, opcional |

A chave do OpenRouter vem de `OPENROUTER_API_KEY` ou fica em
`~/.config/devflow/credentials` (modo 0600): nunca no repositório, nunca
impressa. Um projeto no Devflow do devpit funciona sem mudança: o
`.devpit/devflow/` é lido onde está.

Mais: [integrações](docs/integrations.md) · [plano](docs/plan.md) ·
[contribuir](CONTRIBUTING.md).

## Licença

[Apache-2.0](LICENSE). Veja o [NOTICE](NOTICE).
