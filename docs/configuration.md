# Configuration

devflow reads `devflow.yaml` in `.devflow/` (or `.devpit/devflow/` in a
project on devpit's Devflow, read where it is). `devflow setup` writes it;
`devflow config` reads and changes it, field by field.

## Commands

| Command | Does |
|---|---|
| `devflow setup` · `doctor` | set up this machine and project · check them |
| `devflow config get` · `set <path> <value>` | read or change `devflow.yaml` |
| `devflow status` | each stage's and reviewer's model, where it came from, and what the newest review spent (`spent`) |
| `devflow status --attack` | what the attacks cost and confirmed, and the run mode they suggest |
| `devflow attack <item>` · `--range A..B` | attack a work item, or a release range in CI ([security](security.md)) |
| `devflow payloads list` · `table` · `add` | the attack's payload repertoire |
| `devflow jev setup` · `test` | Decisions (Jev) through OpenRouter, opt-in |
| `devflow update` · `version --json` | install the latest release now · this version and the host protocols |
| `devflow host` | one call from a host app (devpit) over stdio JSON-RPC |

## The flow

Ask your agent for the work. It briefs it, plans it into work items
(`.devflow/work/`) after your yes, builds each test-first, runs the checks
(`evidence`), has it reviewed headless on your own reviewer CLIs (`review`),
attacks it when due (`attack`), and may call it done only when `gate`
passes.

## Acceptance criteria

A work item's acceptance criteria are the checkboxes under
`## Acceptance criteria`. A project that writes them under a heading of its
own names it, and both are read, in the evidence and at the gate:

```sh
devflow config set criteria.headings '["Done when"]'
```

## Models

| Preset | Runs |
|---|---|
| `economy` | the work and the reviewers on a small model, and an analysis of a large or sensitive diff on a large one ([measured](measurements/2026-11-presets.md): the one to write) |
| `quality` | everything on a large model |
| none | only the work's session opens small; reviews run as they did |

A stage's own `model` (`small`, `default`, `large` or a model id) and a
reviewer's `model` win over the preset. A model is a tier, exactly, or a
model id; anything else is refused with what to write. To plan and review on
a large model and execute on a small one:

```sh
devflow config set stages.plan.model large
devflow config set stages.execution.model small
devflow config set stages.review.model large   # every reviewer that names no model of its own
devflow config set review.reviewers.devflow-security.model claude-opus-5-5   # one reviewer, by its persona
devflow status   # each stage's and reviewer's model, and where it came from
```

## Keys

The OpenRouter key Decisions uses is read from `OPENROUTER_API_KEY` or kept
in `~/.config/devflow/credentials` (mode 0600): never in the repository,
never printed.
