# Devflow review: publish on the pull request

Part of the `devflow-review` skill, after a review without a card.

Once a review without a card is done, `devpit_devflow_publish` drafts it for
its pull request, never posting by itself:

```json
{ "review": "pr-1193/<the run>" }
```

The draft, `publish.json` beside `findings.json`, holds each critical, high
and medium on a line the diff shows as one short comment per line, whatever
its axes; and one general comment with the low and info as numbered nits,
what lies outside the diff (a critical or high there as a separate ticket),
the verification and what is good. Show the person every comment. Only after
their explicit yes, call again with `apply: true`: devpit posts that same
draft with `gh`, as one review that only comments, and the general comment.
A draft that changed since they saw it is not posted; it comes back to show.
Approving or requesting changes (`event`) is the person's to ask for, never
yours. Published again, the comments are edited, not posted twice. A
`destination` of `gitlab` or `bitbucket` is drafted to paste, and a layer's
`reviewers/publish/<destination>.md` replaces devpit's template.
