# Build and tests

## Configure from scratch

```bash
git submodule update --init --recursive
python3 -m pip install "conan==2.24.0"
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DWITH_TESTS=ON \
  -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="$PWD/conan_provider.cmake" \
  -DCONAN_HOST_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_BUILD_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_LOCKFILE="$PWD/conan.lock"
cmake --build build --parallel "$(nproc)"
```

The supported CI image also installs the Qt runtime libraries and
`libsmbclient-dev` listed in `.github/workflows/Tests.yml`.

## Verification gates

```bash
ctest --test-dir build --output-on-failure --timeout 120

cd C2Client
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
C2_PROTOCOL_PYTHON_ROOT="$PWD/../build/generated/python_protocol" \
QT_QPA_PLATFORM=offscreen pytest tests

cd ..
python -m pytest packaging/tests
cmake --build build --target validate_release_bundle
```

The runtime integration test initializes a fresh instance, starts the staged
binary over TLS, authenticates with the generated bootstrap credential, and makes
an authorized RPC.
