---
name: attack
description: "Use when a work item in a project with devflow on has passed review and its attack is due (its diff is past small or touches a sensitive path, or `stages.attack.run` is per-item), when a release is to be attacked by name, or when someone asks to attack, exploit or pentest the change."
---

Call devflow's `skill` tool with `{ "name": "devflow-attack" }` and follow the skill it returns: it is this project's own when the project has one. When devflow's tools are not there, read the resource `skill://devflow/devflow-attack/SKILL.md` from the devflow server instead.
