# Devflow review: retro, code already in production

Part of the `devflow-review` skill, with its `without-card` part.

A range already merged and deployed is reviewed with `mode: "retro"`:

```json
{ "base": "<the commit before it>", "head": "<the merged commit>", "mode": "retro" }
```

Nothing can hold it back, so the verdict is `follow_up`, never
`request_changes`, and there may be no criteria, brief or evidence to hold it
to: review it against the repo's rules and what it plainly meant to do. Every
medium or worse defect carries `impact`, the read-only query or log search
that shows what it touched in production since the deploy (how many records
it wrote wrong, how many requests took the broken path); devpit refuses an
answer whose defect has none.

Once the review is done, for each defect, ask the person before running its
`impact`, then run it **read-only**: a `SELECT`, a log search, a metrics
query, never a write, a migration or a script left on a server. Tell the
person what each showed. The draft from `devpit_devflow_publish` carries one
follow-up ticket per medium or worse finding, each defect with its `impact`,
for the person to file.

## Security only

`axes: ["security"]` holds a retro to the security axis: only
devflow-security reads it, and nothing waits on spec or standards. Its
answer names a `vault`, a folder of the run outside the repository. Write
each finding's exploit test there, one folder per finding, run it, and hand
back `verified` (`finding`, `result`, `evidence`, `test`: the exploit's
path). Never write an exploit into the checkout. The answer's `report`, and
`retro-report.md` beside findings.json, say each finding confirmed, not
confirmed or not run, with where its exploit is. An attack on the range
(`attack` with `base` and `head`, `"mode": "retro"` and no item) keeps its
run and exploits in the project's vault the same way: its answer's `next`
says so, never to copy one into the checkout. Its `verified` and `prove`
go with the same `base` and `head` and the attack's `run`; `devflow attack
<range> --promote <hypothesis> --run <run>` copies one into the repository
at its path once its fix lands.
