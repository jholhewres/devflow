# Devflow review: without a card

Part of the `devflow-review` skill: steps 2 to 4 and 6 of the skill apply.

A pull request, a range or a worktree is reviewed on demand wherever Devflow
is on in devpit's Settings,
with no devflow.yaml needed: pass what to review in place of the card.

```json
{ "pr": 1193, "criteria": ["<a line the change is held to>"] }
```

```json
{ "base": "<branch or commit>", "head": "<branch or commit>" }
```

or `{ "path": "<a worktree of the project>" }`, at its own HEAD against the
default branch (or `base`). For `pr` devpit asks `gh` for the pull request,
fetches its head when it is not here, and takes BASE as its merge-base with
the PR's base branch; its body's checkboxes, else its title and body, join
the `criteria`. A pull request or a range is read in a detached worktree in
devpit's home, removed
once the review is: never check one out yourself, in the project's root or
anywhere the person works. With no devflow.yaml the reviewers are the person's
own layer's, and every persona is otherwise `pending`. The run is kept under
the project's `reviews/` in devpit's home
and attached; no card is
commented. Steps 2 to 4 and 6 are the same, handing the
reports back with the same `pr`, `base` and `head`, or `path`, as the
answer's `next` says; the next stage is the person's to choose, as there is
no card to move on.
