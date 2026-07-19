# Release packaging

`1.0.0-rc.1` separates immutable release artifacts from mutable deployment state.
The archive must never contain a private key, credentials file, vault key,
bootstrap password, runtime logs, or source-control metadata.

## Build and validate

```bash
cmake --build build --target validate_release_bundle --config Release
python packaging/validate_release.py \
  --release-root build/release-staging/Release
```

The base bundle contains the TeamServer executable, a non-secret example config,
first-run documentation, modules, command specifications, and the Python client.

## Add immutable implant inputs

Release builds use explicit upstream tags; `latest` is not accepted by CI/CD:

```bash
python packaging/import_implant_releases.py \
  --stage-root build/release-staging/Release \
  --import-root build/release-imports \
  --windows-tag 0.15.0 \
  --linux-tag 0.14.0
python packaging/validate_release.py \
  --release-root build/release-staging/Release \
  --require-implants
```

## Archive and checksum

```bash
tar -C build/release-staging -czf Release.tar.gz Release
sha256sum Release.tar.gz > Release.tar.gz.sha256
```

Publish the archive and its checksum only after CTest, client pytest, packaging
pytest, runtime integration, and release validation pass.
