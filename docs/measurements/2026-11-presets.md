# Economy and quality presets on one real change (November 2026)

The same change was reviewed and attacked once under each models preset, and
nothing else differed. The change was devflow's own: the scanner findings
the attack calls reachable or not (`31a50af..f991228`, 734 changed lines,
12 files). Each run used the branch's devflow in a throwaway clone, with one
headless `devflow-all` reviewer on Claude Code, the analysis reading, and an
attack on the range. The readers ran headless and read-only. Every number
below comes from the runs' own records (`review.json`, `attack.json`); none
is estimated.

## Per stage

| Stage | Preset | Model | Time | Cost | Input tokens | Output tokens | Findings |
|---|---|---|---|---|---|---|---|
| Review: reviewer | economy | sonnet | 31 s | US$ 0.16 | 65,529 | 3,597 | 3 |
| Review: analysis | economy | opus | 339 s | US$ 1.73 | 1,767,864 | 30,316 | 8 |
| **Review, both readers** | **economy** | | **339 s** | **US$ 1.89** | | | **2 medium, 9 low** |
| Review: reviewer | quality | opus | 336 s | US$ 1.44 | 1,507,622 | 31,592 | 10 |
| Review: analysis | quality | opus | 277 s | US$ 1.18 | 1,226,060 | 25,073 | 7 |
| **Review, both readers** | **quality** | | **337 s** | **US$ 2.62** | | | **3 medium, 12 low** |
| Attack | economy | opus (large) | 467 s | US$ 1.81 | 919,607 | 48,882 | 3 tried, 2 refuted, 0 confirmed |
| Attack | quality | opus (large) | 390 s | US$ 1.39 | 728,009 | 41,440 | 4 tried, 5 refuted, 0 confirmed |

The two readers of a review run side by side, so its time is the slower one.
Input tokens count cache reads and writes. The attack runs on the large tier
under both presets, so its rows differ only by the model's own variance.

| | economy | quality |
|---|---|---|
| Verdict | approve | approve |
| Re-reviews | 0: nothing blocked | 0: nothing blocked |
| Gate (`block_on: [critical, high]`) | passes on these findings | passes on these findings |
| Review and attack, in all | US$ 3.70 | US$ 4.01 |

## What each one found

Both found the same worst finding: the dependency readers drop findings past
their ceiling in report order, not by severity, and nothing counts them.
Economy also found that a govulncheck run that fails after its first message
counts as a passed check. Quality found two other mediums: scanner findings
the attacker never assessed are reported as "none reachable", and a
govulncheck finding is placed at the trace's entry point rather than where
the checkout calls in. Neither preset found anything at `block_on`, and
neither attack confirmed an exploit.

## Recommendation

**Economy stays the default.** On this change it gave the same verdict and
the same gate, found the change's worst problem, and its review cost 28%
less (US$ 1.89 against US$ 2.62) in the same time. The analysis reading runs
on the large model under both presets, and it finds most of what economy's
small reviewer leaves. Quality found one more medium and three more lows,
which is worth paying for on a sensitive change or before a release:
`models: quality` in devflow.yaml, or `review.reviewers.<persona>.model:
large` for one reviewer.

One change is one sample: a run of the same preset varies too (the attack
rows show how much). These numbers set the default; they do not rank the
presets once and for all.
