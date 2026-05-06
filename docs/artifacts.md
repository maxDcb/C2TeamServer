# Artifact Runtime

## Goal

Artifacts are files known by the TeamServer and exposed through one consistent
catalog. Modules, commands, tools, scripts, generated payloads, downloads,
uploads, hosted files, and operator-provided files should all use this model
instead of ad hoc paths.

The current implementation intentionally does not preserve compatibility with
older path conventions.

## Runtime Roots

```text
Release/
  CommandSpecs/
  LinuxBeacons/<arch>/
  LinuxModules/<arch>/
  TeamServer/
  TeamServerModules/
  WindowsBeacons/<arch>/
  WindowsModules/<arch>/

data/
  GeneratedArtifacts/
    hosted/
  Scripts/
    Any/
    Linux/
    Windows/
  Tools/
    Any/any/
    Linux/<arch>/
    Windows/<arch>/
  UploadedArtifacts/
    Any/any/
    Linux/<arch>/
    Windows/<arch>/
```

`www` is retired. Files served by HTTP/HTTPS listeners belong under
`data/GeneratedArtifacts/hosted`.

## Catalog Fields

Each artifact has stable metadata:

```text
artifact_id
name
display_name
category
scope
target
platform
arch
format
runtime
source
size
sha256
description
tags
```

Common category values:

```text
beacon
download
hosted
minidump
module
payload
screenshot
script
tool
upload
```

Common runtime values:

```text
archive
bof
dotnet
file
native
powershell
script
shellcode
text
```

## Generated Artifacts

Generated artifacts use a payload file plus a sidecar:

```text
<payload>
<payload>.artifact.json
```

The sidecar is the source of truth for generated metadata. Delete operations are
restricted to generated artifacts that have this sidecar.

Hosted files are different: they are raw files in
`GeneratedArtifacts/hosted`. They are indexed as:

```text
category: hosted
scope: generated
target: listener
platform: any
arch: any
runtime: file
source: operator
```

They are downloadable from the Artifacts UI, served by listeners, and deletable
from the Artifacts UI. Deletion is restricted to files that resolve under
`GeneratedArtifacts/hosted`.

## Command Specs

Command specs describe command arguments and completion sources. Artifact-backed
arguments should use `artifact_filter` or `artifact_filters` so the client can
query the TeamServer catalog instead of guessing from examples or local paths.

Use multiple filters when a command accepts several artifact families, for
example `psExec` accepting release tools and uploaded operator files.

## Client UI

The Artifacts tab is the operational view for the catalog:

- filters refresh immediately on selection
- upload stores files under `UploadedArtifacts`
- download writes the selected artifact to the client machine
- generated sidecar-backed artifacts can be deleted
- hosted files are visible through the `hosted` category and can be deleted

The Terminal `Host` command works from catalog artifacts, not local client
files:

```text
Host <artifact_id|artifact_name> <listener_hash> [hosted_filename]
```

The TeamServer resolves the artifact, copies its payload into the listener
hosted directory, and returns the download URL to the client.

The URL host is resolved in this order:

```text
DomainName
ExposedIp
IpInterface resolved address
listener bind address
127.0.0.1 for wildcard binds such as 0.0.0.0
```

## Stabilization Checklist

- Run real listener tests with hosted files under `GeneratedArtifacts/hosted`.
- Verify each migrated module with real artifacts and command autocomplete.
- Confirm upload/download behavior on Linux and Windows clients.
- Validate that generated sidecars are created, indexed, downloaded, and deleted.
- Check release staging rejects runtime/operator roots.
- Review command specs for argument descriptions, examples, and artifact filters.
- Keep new modules on the CommandSpec and ArtifactCatalog path.
