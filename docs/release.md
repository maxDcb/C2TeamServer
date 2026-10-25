# Release Packaging

## Stage TeamServer Release

```bash
cmake --build build \
  --target validate_release_bundle \
  --config Release
```

Output:

```text
build/release-staging/Release
```

Base layout:

```text
Release/
  TeamServer/
  TeamServerModules/
  Client/
  install/
    exploration.py
```

## Validate Base Staging

```bash
python packaging/validate_release.py \
  --release-root build/release-staging/Release
```

Validation checks:

- `TeamServer/TeamServer`
- TeamServer config and certificates
- `TeamServer/logs`
- full `TeamServerModules` list
- Python client launchers and generated protocol files
- client `uv.lock` and the Linux/WSL installer
- no `.gitignore`
- no `__pycache__`

## Add Implant Assets

See [Implant asset contract](implants.md).

```bash
python packaging/import_implant_releases.py \
  --stage-root build/release-staging/Release \
  --import-root build/release-imports

python packaging/validate_release.py \
  --release-root build/release-staging/Release \
  --require-implants
```

The importer accepts the known GitHub beacon artifacts in Windows implant
archives, and GitHub/SMB beacon artifacts in Linux implant archives, but does
not include them in the TeamServer bundle. These transports are excluded from
the current release contract. Unknown artifacts still fail import validation.

## Create Archive

Only archive validated staging, then publish its checksum and `install.sh`:

```bash
tar -C build/release-staging -czf Release.tar.gz Release
sha256sum Release.tar.gz > Release.tar.gz.sha256
```

## Rules

- Build and test before packaging.
- Package from staging only.
- Do not rename source directories.
- Do not delete source directories.
- Do not mutate source directories during CD.
- Publish the validated `Release.tar.gz`, its checksum and `install.sh`.
