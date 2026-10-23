# devflow

This project may use devflow: an engineering flow of briefing, context, plan,
execution, review and completion, in which work is done only when its
evidence says so — its checks green after the last change, each acceptance
criterion proven by a test or a proof file, a review that blocks nothing.
Its tools come from the `devflow` MCP server.

- Call `status` first: the project's state and the step that comes next.
- Before each stage, call `skill` with `devflow-<stage>` (briefing, context,
  plan, execution, review, completion) and follow the skill it returns.
- Work items are Markdown files in the project's devflow folder: `items`
  lists them, `item` reads or makes one, `start` picks the one you work on.
- An item is done when `gate` passes: run its checks with `evidence`, review
  it with `review`, then `gate`, then `finish`.
- What only the person decides — switching devflow on, Decisions in enforce,
  a team layer's command — is a terminal command the tools name; a brief, a
  plan or a published review waits for their explicit yes in the conversation.
