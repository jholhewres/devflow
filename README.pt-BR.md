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
curl -fsSL https://raw.githubusercontent.com/jholhewres/devflow/main/install.sh | sh
devflow setup
```

O `install.sh` confere o checksum da release, coloca o `devflow` em
`~/.local/bin` e o registra nas CLIs de agente e IDEs que encontrar
(`--tools=`, `--dry-run`, `--uninstall`, `--version=`). O `devflow setup` escreve o `devflow.yaml` do projeto
e liga o devflow, perguntando antes.

O devflow se mantém atualizado: toda vez que uma CLI de agente inicia o
`devflow mcp`, uma thread em segundo plano pergunta ao GitHub qual é a
release mais recente e instala uma mais nova por cima do binário. O arquivo
tem que bater com o `checksums.txt` da release, e o binário novo tem que
rodar antes de substituir o antigo, que fica guardado como `devflow.prev`. O
plugin do Claude Code vai para a mesma versão. O servidor responde na hora;
offline, registra uma linha e segue; a próxima inicialização roda a versão
nova. `DEVFLOW_NO_UPDATE=1` desliga, e um build feito de um checkout nunca se
substitui. `devflow update` faz agora (`--check` só olha, `--json` responde
numa linha).

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
| `devflow update` · `version --json` | instala a release mais recente agora · esta versão e os protocolos de host |
| `devflow host` | uma chamada de um app host (devpit) via JSON-RPC no stdio |

Os critérios de aceite de um work item são os checkboxes sob
`## Acceptance criteria`. Um projeto que os escreve sob um título próprio o
nomeia, e os dois são lidos, na evidência e no gate:
`devflow config set criteria.headings '["Critérios de aceite"]'`.

A chave do OpenRouter vem de `OPENROUTER_API_KEY` ou fica em
`~/.config/devflow/credentials` (modo 0600): nunca no repositório, nunca
impressa. Um projeto no Devflow do devpit funciona sem mudança: o
`.devpit/devflow/` é lido onde está.

Modelos: `models: economy` roda o trabalho e os revisores num modelo
pequeno, e uma análise de diff grande ou sensível num modelo grande; sem
preset, só a sessão do trabalho abre no pequeno; `models: quality` roda tudo no grande. O `model` de uma etapa
(`small`, `default`, `large` ou o id de um modelo) e o de um revisor vencem o
preset. Um `devflow.yaml` sem preset revisa como antes; `models: economy` é
o que escrever ([medido](docs/measurements/2026-11-presets.md)). Um modelo é um tier,
exato, ou o id de um modelo; qualquer outra coisa é recusada, com o que
escrever no lugar. Para planejar e revisar num modelo grande e executar num
pequeno:

```sh
devflow config set stages.plan.model large
devflow config set stages.execution.model small
devflow config set stages.review.model large   # todo revisor que não diz modelo próprio
devflow config set review.reviewers.devflow-security.model claude-opus-5-5   # um revisor, pela persona
devflow status   # o modelo de cada etapa e revisor, e de onde veio
```

O `status` também diz o que o review mais recente gastou por etapa e modelo
(`spent`).

## Segurança e ataque

Duas coisas olham a segurança de uma mudança. O **revisor de segurança**
(`devflow-security`) a lê durante o review, como os revisores de spec e de
standards, e seus achados críticos e altos seguram o trabalho. O **ataque**
é uma etapa própria depois do review: tenta explorar a mudança e responde
com hipóteses, cada uma com um teste de exploração. O devflow roda cada
exploit num sandbox (bwrap, ou docker sem rede), numa worktree descartável,
e só um que falha ali, `confirmed`, segura o trabalho, até ser provado
vermelho na base e verde no HEAD.

```sh
devflow config set stages.attack.run per-item   # sensitive, per-item, release ou off
devflow config set stages.attack.test 'sh scripts/run-exploit.sh'   # roda um exploit, dado $DEVFLOW_EXPLOIT
devflow config set stages.attack.budget '{"run_usd":5,"month_usd":50}'
devflow config set security.targets '["http://localhost:8080"]'   # pede confirmação de cada alvo, no terminal
devflow status --attack   # quanto os ataques custaram e confirmaram, e o modo que sugerem
```

`review.attack` é o nome antigo da etapa e continua valendo. Um devflow.yaml
que não fala da etapa de ataque a tem desligada, como na 0.5.x; o `devflow
setup` escreve `sensitive` num projeto novo: além de um diff pequeno, ou num
caminho sensível, o gate espera por ela. Um ataque só alcança as
instâncias do próprio projeto que você confirmou (loopback, `localhost`,
`host.docker.internal`, nomes de serviço do docker) ou uma stack compose que
você confirmou, numa rede interna; nunca um terceiro nem os metadados da
nuvem, e nunca contorna a recusa de um modelo. Cada execução escreve seu
relatório em markdown, JSON e SARIF, com um rascunho de issue por falha
confirmada, e não publica nada disso. Um intervalo já em produção ganha um
retro só de segurança, cujos exploits ficam num cofre fora do repositório.
`devflow attack --range A..B` ataca um intervalo de release no CI, escreve
SARIF e JUnit e falha num exploit confirmado. Itens do plano que cruzam uma fronteira
de confiança dizem seus casos de abuso, cada um um critério provado por
teste.

O devflow não isola o shell do próprio agente. Como cada parte funciona,
quanto custa e como ler as hipóteses: [docs/security.md](docs/security.md)
(em inglês); o que o sandbox garante e o que não garante:
[SECURITY.md](SECURITY.md).

Mais: [integrações](docs/integrations.md) · [segurança](docs/security.md) · [plano](docs/plan.md) ·
[contribuir](CONTRIBUTING.md).

## Licença

[Apache-2.0](LICENSE). Veja o [NOTICE](NOTICE).

---

<p align="center">O devflow é feito pelo <a href="https://devpit.app">devpit.app</a>.</p>
