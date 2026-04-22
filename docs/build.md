# Build And Tests

## Dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
  golang-cfssl \
  libegl1 \
  libgl1 \
  libsmbclient-dev \
  libxkbcommon-x11-0 \
  libxcb-cursor0 \
  libxcb-icccm4 \
  libxcb-image0 \
  libxcb-keysyms1 \
  libxcb-render-util0 \
  libxcb-xinerama0

python3 -m pip install --upgrade "conan==2.24.0"
```

## Configure And Build

```bash
git submodule update --init --recursive

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DWITH_TESTS=ON \
  -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES="$PWD/conan_provider.cmake" \
  -DCONAN_HOST_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_BUILD_PROFILE="$PWD/conan/profiles/linux-gcc13" \
  -DCONAN_LOCKFILE="$PWD/conan.lock"

cmake --build build --config Release --parallel "$(nproc)"
```

## CTest

```bash
ctest --test-dir build \
  --build-config Release \
  --output-on-failure \
  --timeout 120
```

Current validated root suite:

```text
63 CTest tests
```

`libs/libDns/tests/fonctionalTest` is built but not registered in CTest. It is a manual server/client harness.

## Client Pytest

The client tests need generated Python protocol bindings from the CMake build.

```bash
cd C2Client
python -m venv .venv
. .venv/bin/activate
pip install -e .[test]

C2_PROTOCOL_PYTHON_ROOT="$PWD/../build/generated/python_protocol" \
QT_QPA_PLATFORM=offscreen \
pytest tests -vv -s
```

Current validated client suite:

```text
5 pytest tests
```
