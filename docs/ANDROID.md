# Android / NDK Integration Guide

Engrail's C99 core compiles cleanly with the Android NDK toolchain —
this repository itself is developed and tested on Android (Termux + NDK).

## Option A: NDK standalone (ndk-build style)

```bash
# From the Engrail root:
export NDK=/path/to/android-ndk
export CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
export CXX=${CC}++

./configure --cc=$CC --cxx=$CXX --disable-bench
make
make smoke        # runs ON Android if you're on Termux
make check        # 10-suite test matrix
```

## Option B: CMake + Gradle (app module)

```groovy
// app/build.gradle.kts
android {
    externalNativeBuild {
        cmake {
            path = file("path/to/engrail/CMakeLists.txt")
        }
    }
    defaultConfig {
        externalNativeBuild {
            cmake {
                arguments += "-DACT_BUILD_TOOLS=OFF"
                arguments += "-DACT_BUILD_EXAMPLE=OFF"
                arguments += "-DACT_BUILD_TESTS=OFF"
            }
        }
    }
}

dependencies {
    implementation(files("path/to/engrail/bindings/java")) // Activation.java
}
```

## Option C: Single-file amalgamation (no build system changes)

```bash
make amalgamation    # generates dist/activation.{h,c}
```

Copy `dist/activation.h` and `dist/activation.c` into your app's
`jni/` directory and add one line to `CMakeLists.txt` or `Android.mk`:

```cmake
add_library(activation STATIC jni/activation.c)
```

## JNI (Java ↔ native)

Use the ready-made JNI glue at `bindings/java/native/ActivationJNI.c`
— the same `.so` works on desktop JVM and Android:

```bash
$CC -shared -fPIC -I$NDK/sysroot/usr/include \
    -I/path/to/engrail/include \
    bindings/java/native/ActivationJNI.c \
    src/crypto/*.c src/core/{fingerprint,kdf,license,state}.c \
    -o libactivation_jni.so
```

Kotlin side (drop into `app/src/main/java/`):

```kotlin
import activation.Activation

val act = Activation(PUBKEY, DSALT, 1)
val machineCode = act.machineCode()  // show this to the vendor

// after receiving a license code:
if (act.activate(code, filesDir.absolutePath + "/app.act") == Activation.Status.OK) {
    // licensed; verify on every startup:
    act.verifySaved(filesDir.absolutePath + "/app.act")
}
```

## Machine fingerprint on Android

The collector reads `uname` fields and `/proc/sys/kernel/random/boot_id`
automatically. For stronger device binding, pass an additional salt
(e.g. `Settings.Secure.ANDROID_ID`):

```kotlin
val salt = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
val mc = act.machineCode(salt.toByteArray())   // same salt every call
```

## Known quirks

| Issue | Resolution |
| --- | --- |
| `libc++_shared.so` link error for CLI tools | `./configure` auto-adds `-static-libstdc++` |
| `/dev/urandom` in app sandbox | CSPRNG prefers `getrandom(2)` syscall first |
| `PTRACE_TRACEME` hangs | Removed in v1.5.0 — TracerPid is the sole probe |
| State file location | Use `Context.getFilesDir()`, not external storage |

Community: [t.me/Stack_Traces](https://t.me/Stack_Traces)
