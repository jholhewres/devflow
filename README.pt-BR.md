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
  <img src="docs/assets/devflow-flow-attack.svg" alt="briefing, contexto, plano, execução, revisão, ataque quando devido (testes de exploit num sandbox sem rede), conclusão; pronto só quando as checagens passam depois da última mudança, todo critério de aceite está provado, a revisão não tem achados bloqueantes e nenhum exploit confirmado está aberto" width="100%">
</p>

O trabalho está pronto quando a evidência diz, não quando o agente diz:
checagens verdes depois da última mudança, cada critério de aceite provado
por um teste ou um arquivo de prova, uma revisão que não bloqueia nada e
nenhum exploit confirmado em aberto. Configuração, work items e execuções
ficam no seu repositório.

## Instalação

```sh
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
devflow setup
```

O instalador confere o checksum da release e registra o devflow nas CLIs de
agente e IDEs que encontrar; depois o devflow se mantém atualizado sozinho.
Opções e atualização: [docs/install.md](docs/install.md) (em inglês).

## Uso

| Ferramenta | O que recebe |
|---|---|
| Claude Code | plugin: tools MCP, skills `/devflow:<etapa>`, `/devflow:status`, `/devflow:pr`, subagentes revisores, o Stop hook do gate; o servidor MCP também na config de usuário, para uma sessão que carrega outro plugin chamado devflow continuar com ele ([por quê](docs/integrations.md#claude-code-and-another-plugin-named-devflow)) |
| Codex | tools MCP, o Stop hook do gate (aprovado no `/hooks` do Codex), `AGENTS.md` no projeto ([como](docs/integrations.md#codex)) |
| Gemini CLI | extensão: tools MCP e `GEMINI.md` |
| Cursor | tools MCP, o stop hook do gate, a regra do projeto ([como](docs/integrations.md#cursor)) |
| OpenCode, VS Code, Antigravity, Windsurf (Devin Desktop) | tools MCP |

Depois, peça o trabalho ao seu agente. Ele faz o brief, planeja em work items
depois do seu sim, constrói cada um com teste primeiro, roda as checagens
como evidência, manda revisar headless nas suas próprias CLIs de revisão,
ataca quando é devido e só dá como pronto quando o gate passa.

**Segurança.** Um revisor de segurança lê toda mudança. A etapa de ataque
tenta explorá-la com testes que rodam num sandbox sem rede, e só um exploit
confirmado ali segura o trabalho. Ela só alcança o que você confirmou e não
publica nada. [Como funciona](docs/security.md) (em inglês).

## Documentação

A documentação detalhada está em inglês.

| | |
|---|---|
| [Configuração](docs/configuration.md) | comandos, `devflow.yaml`, critérios de aceite, modelos, chaves |
| [Segurança e ataque](docs/security.md) | o revisor de segurança, a etapa de ataque, o sandbox, orçamento, relatórios e CI |
| [Integrações](docs/integrations.md) | o que cada CLI de agente e IDE recebe, e como |
| [Instalação e atualização](docs/install.md) | as opções do instalador, a atualização automática |
| [Design e releases](docs/plan.md) | como o devflow é feito, e o que cada release mudou |
| [SECURITY.md](SECURITY.md) | o que o devflow toca, e o que o sandbox garante |
| [Contribuir](CONTRIBUTING.md) | como compilar, testar e enviar uma mudança |

## Licença

[Apache-2.0](LICENSE). Veja o [NOTICE](NOTICE).

---

<p align="center">O devflow é feito pelo <a href="https://devpit.app">devpit.app</a>.</p>
