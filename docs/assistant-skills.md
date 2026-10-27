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

`target: teamserver` defines a skill that runs with the **TeamServer · no beacon
session** target. It receives only registered TeamServer adapters and does not load
beacon command specifications. The `teamserver.inspect`, `teamserver.publish`, and
`teamserver.control` bundles group the typed inventory, publication, and control
operations. Focused bundles `teamserver.commands`, `teamserver.listeners`,
`teamserver.sessions`, `teamserver.artifacts`, `teamserver.credentials`, and
`teamserver.tools` grant the corresponding catalog, lifecycle, artifact, vault,
and tool installation actions. These adapters are also registered in the
conversation, while skills receive only the operations in their selected bundles.
The Conversation tab selects every declared bundle and also retains command tools
loaded dynamically from the TeamServer catalog. Enter `/bundles` in Conversation
to see which bundled tools the current client and TeamServer actually provide.
Listener and session lifecycle actions can be requested without selecting a beacon;
beacon commands still need a specific session.
`teamserver-inspect` checks local inventory in read-only mode.
`teamserver-publish-test` exercises only the publication action and destination
explicitly named in **Additional task context**, using existing artifact IDs.

`artifact-to-session` runs against one selected beacon session and combines the
`artifact.to_session` bundle. **Additional task context** is free text. For
example, `transfert /etc/hosts sur /tmp de la session` asks for `/tmp/hosts`;
`ok transfert /etc/hosts dans /tmp/toto et /tmp/hotsss` asks for two exact
destination files. The skill interprets the context and passes the source and
destination paths as tool arguments. If source or destination information is
missing, the run displays an error instead of a transfer report.

The skill calls `uploadC2Artifact` to store the local bytes in the same Artifacts
catalog used by the Artifacts tab, then calls the beacon `upload` command with
the verified artifact ID. In this command catalog, `upload` sends data to the
beacon; `download` retrieves data from it. The skill waits for the beacon job
result before reporting success. A lost Artifacts upload response has no durable
job receipt and is not automatically retried.

`recon-network` uses the narrow `recon.network` bundle: `ipConfig`,
`hostContext`, `netstat`, optional `ps`, and `listC2Listeners`. The model chooses
the command order from observed results. Its report compares beacon-host evidence
with TeamServer listener metadata and cites the IDs of both sources. `ps` is
reserved for a concrete socket ownership question.

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

Skills can use typed TeamServer operations selected by their bundles:
command catalog and help; listener inventory, creation and stop; live sessions,
history and stop; artifact inventory, upload, download, hosting and deletion;
credential vault listing, detail, creation, update and deletion; tool installation,
module reload and SOCKS control. The same `TeamServerOperations` layer serves the
corresponding UI panels and assistant adapters. Binary lookup returns a size and digest, not
the binary itself. File actions download an existing artifact by ID before sending
its bytes to the typed RPC; they accept an explicit safe destination filename.
`hostArtifact`, `socksControl`, and `reloadModules` have durable V2 job receipts.
The client saves the job ID before dispatch and can resolve an interrupted action
from that receipt. Other mutations return a direct acknowledgement and have no job
receipt. If interrupted, their outcome is marked unknown and they are not replayed
automatically. The operator should inspect TeamServer state before retrying. The
skill has no free-form TeamServer terminal command tool.

Reports contain a plain-English summary, findings cited by `source_id`, limitations,
and exact job output retained in the local run snapshot. Runs are stored under
`C2Client/C2Client/logs/assistant_sessions/skills/runs/`. Only the `agentic_skill`
run format is usable. Previous fixed-plan and identity-specific run files are not
listed or resumed.

Report citation or format mismatches are shown as warnings; they do not discard
the model's response or otherwise successful observations. The original response
is retained for review. Complete beacon output is passed to agent-core's artifact
system, which can page large results; each result states whether its stored bytes
cover the reported size. The Tasks panel shows a shorter output preview and labels
it when the preview is incomplete.

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
