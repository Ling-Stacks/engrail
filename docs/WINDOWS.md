# Windows Build Guide

Engrail supports two Windows toolchains.

## MSYS2 / MinGW-w64 (recommended)

```bash
pacman -S mingw-w64-x86_64-gcc make python
./configure --cc=gcc --cxx=g++
make
make smoke
make check
```

All 10 test suites pass under MinGW. The vendor CLI, integrity tool,
and bench are fully functional.

## MSVC (Visual Studio 2022)

The C99 core + C++17 wrapper compile with MSVC 19.x via CMake:

```bat
configure --cc=cl --cxx=cl --disable-tools --disable-tests
cmake -B build -G "Visual Studio 17 2022" .
cmake --build build --config Release
```

`--disable-tools` is needed because MSVC lacks `unistd.h` (vendor CLI
uses POSIX file I/O internally). The core library itself has no
POSIX dependency — `random.c`, `fingerprint.c`, `harden.c` all carry
`_WIN32` branches.

## Preprocessor branches already handled

| File | Windows path |
| --- | --- |
| `random.c` | `ProcessPrng` / `BCryptGenRandom` |
| `fingerprint.c` | `COMPUTERNAME`, `PROCESSOR_*`, volume serial |
| `harden.c` | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `GetModuleFileNameA` |
| `state.c` | no umask, no chmod |

## Shared library for Python/Java bindings

```bash
./configure --cc=gcc --enable-shared
make
# configure --enable-shared now emits activation.dll on MinGW directly
# (older builds produced a PE DLL named .so -- rename it in that case)
```

## Known quirks

| Issue | Resolution |
| --- | --- |
| `make` not found outside MSYS2 | Install MSYS2 or use CMake route |
| CLI tools need `unistd.h` | Use MinGW, not raw MSVC |
| `.exe` suffix | MSYS2/MinGW produces `.exe` binaries; scripts that pass executable paths to native tools use a platform suffix (`EXESUF`) |
| Path separators in scripts | `scripts/*.sh` require MSYS2 bash |

Community: [t.me/Stack_Traces](https://t.me/Stack_Traces)
