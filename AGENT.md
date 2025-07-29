# Build Instructions

## Dependencies
- GCC 11 (`gcc-11`, `g++-11`)
- Python `conan` package
- `golang-cfssl` for certificate generation

Install packages on Ubuntu:
```bash
sudo apt-get update
sudo apt-get install -y gcc-11 g++-11 golang-cfssl
pip install conan --break-system-packages
```

## Conan profile
Create a custom profile using GCC 11:
```bash
conan profile detect --force --name=gcc11
sed -i 's/compiler.version=.*/compiler.version=11/' ~/.conan2/profiles/gcc11
sed -i 's/compiler.cppstd=.*/compiler.cppstd=17/' ~/.conan2/profiles/gcc11
echo "build_type=Release" >> ~/.conan2/profiles/gcc11
```

## Configure and build
Set environment variables so CMake and Conan use GCC 11:
```bash
export CC=gcc-11
export CXX=g++-11
```
Configure with CMake and Conan:
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=${PWD}/conan_provider.cmake -DCONAN_PROFILE=gcc11
cmake --build build -j $(nproc)
```
Run tests:
```bash
ctest --test-dir build
```
