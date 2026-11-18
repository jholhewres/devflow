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
