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

## Create Archive

Only archive validated staging:

```bash
tar -C build/release-staging -czf Release.tar.gz Release
```

## Rules

- Build and test before packaging.
- Package from staging only.
- Do not rename source directories.
- Do not delete source directories.
- Do not mutate source directories during CD.
- Publish only the validated `Release.tar.gz`.
