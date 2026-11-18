# Devflow review: by hand, without devpit's tool

Part of the `devflow-review` skill: its steps 2 to 6 apply.

When `devpit_devflow_review` is not listed, do its work yourself: pin BASE
(`git merge-base HEAD <base branch>`) and HEAD (`git rev-parse HEAD`), write
the packet with these headings, each filled or "none": BASE, HEAD, the
changed files, the card's criteria, the brief, the standards, the evidence
and the diff. Run all three personas as in step 2, and write
`findings.json` beside the packet as step 4 describes it.
