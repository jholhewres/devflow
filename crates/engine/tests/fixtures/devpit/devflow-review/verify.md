# Devflow review: verify the criticals and highs

Part of the `devflow-review` skill, for a card whose `devflow.yaml` sets
`review.verify` to `advise` or `required`.

With `review.verify` at `advise` or `required` in `devflow.yaml`, the
answer's `next` names the standing criticals and highs by their place in
`findings.json` (from 0). Run each one's PoC where there is an environment to
run it in (a local build, a test database, a staging the card names) and
record what it showed:

```json
{ "card": "<card id>", "run": "<the run>", "verified": [{ "finding": 0, "result": "confirmed", "evidence": "<the environment, the command and what it answered>" }] }
```

- `confirmed`: the PoC did what the finding says. `evidence` names where.
- `refuted`: it did not; the finding then holds nothing under `required`.
- `not_run`: there was nowhere safe to run it; `evidence` says why.

Never create a file, script or folder on a server: run each step from here.
A PoC that writes to a database runs in a transaction rolled back at its end
when the database allows one, and a destructive PoC runs only on a disposable
copy, else it is `not_run`.

With `required`, a high nobody confirmed counts as `medium` in the verdict,
and the card's comment says why; a critical still blocks. Each critical and
high in the comment and in the answer's `findings` reads "confirmed in
<evidence>", "refuted in <evidence>" or "not verified": use those words when
drafting the review for a pull request. With `off`, the default, skip this
step.

Done when every standing critical and high has a `verified` result, or
`review.verify` is `off`.
