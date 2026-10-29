# Shared TeamServer operations

`TeamServerOperations` in `C2Client/C2Client/operations.py` is the client interface
used by the terminal, Artifacts tab, and assistant tools. It accepts typed arguments
and calls domain-specific gRPC methods. The terminal only parses user input and
presents results.

`HostArtifact`, `ControlSocks`, and `ReloadModules` return durable
`JobExecutionRecord` receipts. The server records the job before execution;
`GetJobExecution` recovers a lost response. A repeated ID with the same input
returns the existing record, while conflicting input is rejected. Assistant skills
save these IDs before dispatch and use them when resuming a run.

The dropper and Batcave workflows use `GetListenerInfo`, `GetBeaconBinary`,
`UploadListenerFile`, `InstallTool`, and `InstallToolBundle`. These methods use
structured requests and responses, including binary fields and repeated tool
files. They return direct acknowledgements for writes; they do not yet have
durable job receipts. Artifact catalog, upload, download, and deletion use the
same client operation layer, so further actions can be shared with assistant tools
through separate capability grants.

The text `ExecuteTerminalCommand` RPC and its terminal request and response types
were removed. `TeamServerLocalOperationService` owns local file, tool, artifact
hosting, and module actions independently of the terminal UI.
