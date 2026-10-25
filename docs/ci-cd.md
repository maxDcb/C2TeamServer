# CI/CD Contract

## Workflows

```text
.github/workflows/Tests.yml    CI
.github/workflows/Release.yml  CD
```

## CI

Triggers:

```text
pull_request
push branches
workflow_dispatch
```

`Decide whether to build` runs first. It skips the expensive build when a push
to a non-default branch already has an open pull request (the `pull_request`
run owns validation), or
when a push/pull request changes only `docs/**` and/or `README.md`. Manual runs
always build. If the previous commit cannot be inspected, CI builds normally.
If the pull request lookup fails, the push run still builds unless it is a
documentation-only change. The build job remains present as a skipped
successful check when there is no build to run, so it can remain a required PR
check. New runs cancel older runs for the same event and branch/PR.

Permissions:

```yaml
permissions:
  contents: read
```

Gates:

```bash
cmake -S "$GITHUB_WORKSPACE" -B "$GITHUB_WORKSPACE/$BUILD_DIR" ...
cmake --build "$BUILD_DIR" --config "$BUILD_TYPE" --parallel "$(nproc)"
ctest --test-dir "$BUILD_DIR" --build-config "$BUILD_TYPE" --output-on-failure --timeout 120
timeout 180 python -m pytest "$GITHUB_WORKSPACE/C2Client/tests" -vv -s
cmake --build "$BUILD_DIR" --target validate_release_bundle --config "$BUILD_TYPE"
cmake --build "$BUILD_DIR" --target stage_integration_runtime --config "$BUILD_TYPE"
```

## CD

Triggers:

```text
push tags
workflow_dispatch
```

Build job permissions:

```yaml
permissions:
  contents: read
```

Publish job permissions:

```yaml
permissions:
  contents: write
```

Gates before publishing:

```bash
uv lock --check --project C2Client
ctest --test-dir "$BUILD_DIR" --build-config "$BUILD_TYPE" --output-on-failure --timeout 120
timeout 180 python -m pytest "$GITHUB_WORKSPACE/C2Client/tests" -vv -s
cmake --build "$BUILD_DIR" --target validate_release_bundle --config "$BUILD_TYPE"
python packaging/import_implant_releases.py ... --manifest packaging/release_inputs.json
python packaging/validate_release.py --release-root "$BUILD_DIR/release-staging/Release" --require-implants
tar -C "$BUILD_DIR/release-staging" -czf Release.tar.gz Release
sha256sum Release.tar.gz > Release.tar.gz.sha256
```

The release manifest pins implant tags, their Git commits, and asset SHA-256
digests. A tag push publishes only when the TeamServer tag matches this manifest
and the imported assets pass provenance and layout checks. Manual dispatch
builds and validates without publishing. The release publishes `Release.tar.gz`,
`Release.tar.gz.sha256` and `install.sh`.

## Cache

```text
pip cache from C2Client dependency files
Conan cache from conanfile.txt, conan.lock, conan/profiles/linux-gcc13
ccache (500 MB) for C/C++ compilation in CI and CD; keyed by Linux GCC profile and Conan lock
```

Both workflows pass `ccache` as the CMake C and C++ compiler launcher. The
ccache action reports hit statistics at the end of each build; compare those
statistics and build time across consecutive code-changing runs to measure the
benefit.

## Rules

- CI runs before release.
- CD publishes only after build and tests pass.
- Archive and checksum are created from validated staging.
- Default GitHub token permission is read-only.
- Only the publish job gets `contents: write`.
