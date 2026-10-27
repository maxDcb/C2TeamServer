# Client-owned Agent Skills

## Skill format and creation

The client uses one skill format: a directory under
`C2Client/C2Client/assistant_agent/skills/` containing `SKILL.md` and `skill.yaml`.
Skills are shipped with the client source. Restart the client after adding or editing one.
The `SKILL.md` frontmatter supplies a lowercase hyphenated `name` matching the directory
and a description. Its Markdown body instructs the LLM. `skill.yaml` selects the C2
capability bundles and sets the execution limits:

```yaml
tool_bundles: [recon.identity, recon.host]
objective: Identify the selected session's user and network context.
required_tools: [whoami, ipConfig]
completion_tools: [whoami, ipConfig]
max_tool_calls: 10
max_iterations: 16
```

A required tool must be available for the selected session before the run starts.
Completion tools determine whether the final report can be considered complete.
The effective tool list is the intersection of the declared bundles, registered
adapters, and platform-compatible commands. A new skill can combine existing
bundles without adding Python code. A new C2 operation still needs a typed adapter.

The Tasks panel shows the skill's description, bundles, and tools in its help popup.
The operator selects a live session and can enter **Additional task context** for
that run. The client snapshots this text, the skill instructions, TeamServer session
metadata, available tools, and command specifications. Session metadata and operator
context help guide the task; the report may cite only observed job or terminal
observation IDs as evidence. Changing a skill file does not change an existing run.

## Execution and recovery

Every skill uses agent-core's structured task executor. The LLM chooses tools within
the selected bundles. Beacon commands are bound to the selected session, validated,
and submitted as V2 jobs with stable IDs. If a module must be loaded first, its load
job is recorded separately; its output is not presented as the command result.
The client waits for each command and resumes from the stored event cursor after a
restart. An uncertain command is never resubmitted under a new ID. The operator may
mark **No result** to continue toward a partial report, or **Mark failed** to stop.
The client performs LLM work only while it is running; TeamServer may receive a
late beacon result while the client is closed.

Skills can use the typed TeamServer tools already available to the conversation:
`listC2Listeners`, `listC2Artifacts`, `hostArtifact`, and `socksControl`, when their
bundles select them. `hostArtifact` and `socksControl` change TeamServer state. The
client records intent before invoking them. If the client is interrupted or loses
the terminal response and cannot establish the action's outcome, it records
`outcome_unknown`, avoids
automatic replay, and makes the report partial. The operator must inspect TeamServer
state before deciding whether to run the action again. These terminal actions do not
have V2 job IDs. Other terminal operations need typed adapters before a skill can call
them; the skill never receives a free-form terminal command tool.

Reports contain a plain-English summary, findings cited by `source_id`, limitations,
and exact job output retained in the local run snapshot. Runs are stored under
`C2Client/C2Client/logs/assistant_sessions/skills/runs/`. Only the `agentic_skill`
run format is usable. Previous fixed-plan and identity-specific run files are not
listed or resumed.

## Local build and tests

From the C2TeamServer root, after CMake has generated the Python protocol bindings:

```bash
C2_PROTOCOL_PYTHON_ROOT="$PWD/build-codex-scratch/generated/python_protocol" \
  QT_QPA_PLATFORM=offscreen \
  C2Client/.venv/bin/python -m pytest C2Client/tests -q
ctest --test-dir build-codex-scratch -R '^(testsNetstat|testsHostContext|testsJobRuntimeE2E)$' \
  --output-on-failure --timeout 120
```

To run the GUI with the current local LLM settings:

```bash
export C2_PROTOCOL_PYTHON_ROOT="$PWD/build-codex-scratch/generated/python_protocol"
C2Client/.venv/bin/python -m C2Client.GUI
```
