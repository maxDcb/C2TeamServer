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
ctest --test-dir "$BUILD_DIR" --build-config "$BUILD_TYPE" --output-on-failure --timeout 120
timeout 180 python -m pytest "$GITHUB_WORKSPACE/C2Client/tests" -vv -s
cmake --build "$BUILD_DIR" --target validate_release_bundle --config "$BUILD_TYPE"
python packaging/import_implant_releases.py ...
python packaging/validate_release.py --release-root "$BUILD_DIR/release-staging/Release" --require-implants
tar -C "$BUILD_DIR/release-staging" -czf Release.tar.gz Release
```

## Cache

```text
pip cache from C2Client dependency files
Conan cache from conanfile.txt, conan.lock, conan/profiles/linux-gcc13
```

## Rules

- CI runs before release.
- CD publishes only after build and tests pass.
- Archive is created from validated staging.
- Default GitHub token permission is read-only.
- Only the publish job gets `contents: write`.
