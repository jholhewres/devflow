# Context and tokens per card: baseline and cuts (November 2026)

Where a Devflow card's context and tokens go, measured on real sessions, and
which cuts pay for themselves. The scripts that produced every number here
read the agent's own transcripts and the runs Devflow keeps; nothing was
estimated where it could be counted.

## What was measured

- **11 main sessions, 16 cards**, all on Opus, on 2026-11-03 and 04, in three
  projects: A (a Go service, 600–800 tests, five sessions), B (a Go web app,
  three sessions) and C (a Go engine, one card).
- **106 headless reviewer sessions** of those projects.
- **60 review rounds and 66 evidence runs** of 27 cards, from the runs
  folder (`devflow/runs/<card>/<time>/`).

Per turn, a transcript gives the context read (input plus cache read plus
cache write) and the output. A turn is put in a stage by the tool it calls:
`orient` (context, board, card, skill, memory), `plan`, `execution` (until the
first review), `evidence`, `review`, `fix` (work after the first review),
`gate` and `close` (handoff, finish, comments). "Billed input" is the sum of
every turn's context: what the quota pays for, most of it as cache reads.

## Baseline

| | |
|---|---|
| Context before the first message | 56–65k tokens (system prompt, tool schemas, skill listing) |
| Context when the first card starts | 110–250k: the orientation adds 50–150k |
| Context a card adds | 137k on average (60k–240k) |
| Peak context | 232k–302k for a card alone; 888k on the 4th card of one session |
| Billed input per card | 1.8M–66M, median 15.8M; 374M for the 16 cards |
| Output per card | 23k–253k; 1.2M in all (0.3% of the billed input) |
| Billed input after the first review (fix, re-review, evidence, gate) | **70%** |
| Billed input above a 125k start, carried from earlier cards of the session | **47%** |
| Billed input after the first review that approved | **27%** |
| Reviewer sessions | 50–80k peak, 2–8 turns, 20–200 s, 0.25–0.9M billed each: 5–10% of a card |
| Review rounds per card | 2.2 (lower bound: runs older than the folder keeps are gone); 9 of 27 cards had 3 or more |
| Re-review rounds that followed an `approve` | **27 of 33** |
| Rounds with `request_changes` | 7 of 60 |
| Rounds whose high came back on the same file and axis | 3 of 60 (two cards of A had 4 rounds) |
| Evidence run | 1.8 s for 794 tests; 2k tokens of answer per call |

Every main session ran on Opus; there was no model per stage.

### Where the tool output goes

Tokens each tool's answer added to the context, and how often later turns read
it again (the share of the 194M re-read tokens that tool output costs):

| Tool | Calls | Tokens per call | Share added | Share re-read |
|---|---:|---:|---:|---:|
| Bash (tests, git, reads) | 857 | 1.0k | 45% | 49% |
| devpit_handoff | 18 | 10.6k | 10% | 6% |
| devpit_devflow_review | 96 | 1.7k | 9% | 7% |
| devpit_card | 30 | 5.2k | 8% | 10% |
| devpit_devflow_evidence | 57 | 2.1k | 6% | 6% |
| devpit_board | 9 | 10.0k | 5% | 7% |
| devpit_devflow_skill | 22 | 3.6k | 4% | 5% |
| devpit_comment (answers the whole card) | 10 | 7.5k | 4% | 1% |

Pretty-printed JSON is 13% of the devpit tools' answers (27% of evidence's,
33% of the board's): compact JSON says the same in fewer tokens.

## What drives the cost

1. **The session carries every card.** A card's turns each read the whole
   context again, so a 4th card that starts at 737k pays 66M for 82 turns,
   where a card alone pays 8–25M. 47% of all billed input is context carried
   from earlier cards.
2. **The review loop after an approval.** The agent fixes the medium and low
   findings of an approving review, HEAD moves, the gate wants a new review,
   and the new round finds new nits. 27 of 33 re-reviews came after an
   `approve`, and 27% of the billed input happened after the first approval.
3. **The orientation.** Board, card, handoffs, skill and memory put 50–150k in
   the context before any code is read, on top of the 60k the session starts
   with.
4. **A repeated blocking finding.** Rare (3 of 60 rounds) but costly: each
   extra round re-reads the whole context.

The reviewers themselves (5–10%) and the evidence runs (2 s, 2k tokens) are
not where the tokens go.

## The hypotheses, measured

| # | Cut | Estimated gain | Quality risk | Decision |
|---|---|---|---|---|
| 8 | One card per session; end with a handoff at a context threshold | up to 47% of billed input; card peak back to 230–300k | the next session re-orients (≈1M billed), less than the 11M per card carried | **card (devpit)** |
| new | An approval closes the review: findings below `block_on` go under `Left` | up to 27% of billed input; re-reviews after approve from 27 to ≈0 | medium findings ship unfixed, recorded in the handoff; a project that wants them fixed puts `medium` in `block_on` | **applied** (review skill); devpit's copy: card |
| 4 | A blocking finding that repeats asks for a design decision | 10–20M billed per occurrence (3 of 60 rounds) | none: the gate still blocks, the person decides | **applied** (review skill); engine detector: card |
| 1 | Lean answers: compact JSON; summary and path for evidence, review, card, board; comment and handoff answer an id | 13% of the devpit tools' answers from compact JSON alone; 25–35% of the orientation's tokens with summaries | the agent opens the file when it needs a detail | compact JSON **applied** in `devflow-mcp`; the rest: card (devpit) |
| 7 | Compact handoff, read alone by the next session | the handoff answers 10.6k per call; the orientation reads it 1–4 times | none if the handoff keeps state, commits, contract and what is left | part of the lean-answers card |
| 6 | Model per stage (card #3) | the main session is ≥90% of the tokens, so `execution` on the small tier is the lever; reviewers on `small` save 5–10% at most | a smaller model executing; the large-model analysis before the review covers it | card #3 |
| 3 | Re-review of the delta only, headless | already so: `previous` sends the delta, reviewers run headless | — | nothing to do |
| 2 | Review proportional to the diff | the rounds measured ran 2 reviewers; reviewers are 5–10% | — | low gain: not now |
| 5 | Incremental evidence | the suite runs in 2 s; the answer is 2k tokens | — | **not worth it**: keep the whole suite |

No cut removes the gate or a card's final evidence: the gate still reads the
newest evidence and review, and refuses code changed since the review.

## Targets

- A card's start context at most 130k, and its peak at most 30% of the window
  (300k of 1M).
- Billed input after the first approval at most 10% of a card's.
- Re-review rounds after an approval: at most 1 in 10 cards.

## How to measure again

The scripts are kept outside the repository, with the maintainer's session
scripts; they read Claude Code's JSONL transcripts and the runs folder:

- `measure.py <session.jsonl>... --reviewers <dir>...`: per card and stage.
- `tokens_by_tool.py <session.jsonl>...`: tool output in the context.
- `rounds.py <runs dir>... --since <date>`: rounds, severities, repeats.
- `after_approve.py <session.jsonl>...`: what a card spends after approval.
- `compact_gain.py <session.jsonl>...`: what compact JSON saves.
