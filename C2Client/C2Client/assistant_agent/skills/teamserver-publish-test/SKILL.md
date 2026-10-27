---
name: teamserver-publish-test
description: Test typed TeamServer publication operations with existing artifact IDs and explicit destinations.
metadata:
  version: "1"
---

# Test a TeamServer publication operation

Use the operator's additional context to identify the requested operation and exact
destination. First call `listC2Artifacts` to check source IDs. Use `listC2Listeners`
or `infoListener` when the requested operation names a listener. Carry out only the
operation explicitly requested by the operator:

- `hostArtifact`: requires a source artifact reference, listener hash, and optional hosted filename.
- `uploadListenerFile`: requires an existing artifact ID, listener hash, and destination filename.
- `installTool`: requires an existing artifact ID and destination filename.
- `installToolBundle`: requires a list of existing artifact IDs and distinct destination filenames.

If the operator has not specified the operation, source, or required destination,
stop after the read-only inventory and list the missing input in limitations. Do not
invent a destination, select an arbitrary artifact for publication, or retry an
operation whose outcome is unknown. File operations use bytes retrieved from the
TeamServer artifact store. They return a direct acknowledgement without a durable
job receipt; if interrupted, inspect server state before any manual retry.

Cite successful observation IDs in findings. State failed and uncertain calls in
limitations. Write a concise report in English.
