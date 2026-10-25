# Client hooks

The Hooks tab lists Python files in `C2Client/C2Client/Scripts/` without importing
their modules. A new file starts disabled. Enabling its checkbox allows its
module to be imported in a worker on the next trigger. Activation is saved in
`~/.config/c2client/hook-state.json` (override with `C2_HOOK_STATE_PATH`).
Disable a hook to stop future invocations; a hook already running is not cancelled.

Hooks receive `(grpcClient, context)`. The client queues calls outside the Qt GUI
thread, with four concurrent workers and 64 waiting invocations. A call still
running after ten seconds is reported as `timeout_unknown`; Python code cannot
be forcibly stopped safely, so its remote action may finish later. The queue
rejects additional work when full. `SubmitJob` has a ten second RPC deadline.

`OnStart` runs on initial connection and after a new authentication generation.
`OnStop` is explicitly dispatched at window close; shutdown waits up to two
seconds in total. Listener and session hooks use completed snapshots. Manual
replay of an event targeting a session or listener requires that exact route or
listener to remain available.

`OnConsoleReceive` observes results of commands sent by this client while it
remains open, whether or not their console tab remains open. Historical results
from before this client run do not trigger the hook. The Hooks tab has no command
input; use its checkboxes and Run Hook button.

Hook invocation and gRPC action metadata are appended to
`~/.config/c2client/hook-audit.jsonl` (override with `C2_HOOK_AUDIT_PATH`). Request
bodies and response text are excluded. Session jobs started through the hook
client also carry a client-declared `origin` in TeamServer's durable job record,
alongside the username resolved from the authenticated token. `origin` is
attribution data, not an authorization decision. Direct listener RPCs are
covered by the client audit file; they do not create a job record.
