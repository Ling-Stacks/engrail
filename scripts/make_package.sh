#!/usr/bin/env bash
#  make_package.sh -- unified release/speedtest packaging.
#
#  One staging tree -> BOTH archives with identical content (C6: the
#  old zip was built from inside the dir and silently dropped
#  .github/.gitignore; C7: pyc/class/platform binaries leaked in).
#
#  Usage: bash scripts/make_package.sh [version] [suffix]
#  Out:   ../engrail-v<version>-<suffix>.tar.gz and .zip
set -euo pipefail
cd "$(dirname "$0")/.."

VER="${1:-$(sed -n 's/^#define ACT_VERSION *"\([^"]*\)"/\1/p' include/activation/version.h)}"
# NB: ${2-...} (not ${2:-...}) so an explicitly empty suffix works:
# "" = release flavor, no SPEEDTEST.md, no trailing dash.
SUF="${2-speedtest}"
if [ -n "$SUF" ]; then
    NAME="engrail-v${VER}-${SUF}"
else
    NAME="engrail-v${VER}"
fi
STAGE="$(mktemp -d)/$NAME"
OUT="$(cd .. && pwd)"

echo "== staging $NAME =="
mkdir -p "$STAGE"
cp -R . "$STAGE/"

# C7: never ship build outputs, caches, per-platform binaries or the
# internal audit notes.
rm -rf "$STAGE/build" "$STAGE/dist" "$STAGE/crypto/build" \
       "$STAGE/crypto/dist" "$STAGE/bindings/rust/target" \
       "$STAGE/bindings/csharp/build" "$STAGE/bindings/wasm/dist" \
       "$STAGE/bindings/java/build" "$STAGE/Makefile" \
       "$STAGE/CMakeLists.txt" "$STAGE/config.vars" "$STAGE/config.log"
find "$STAGE" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
find "$STAGE" -name '*.class' -delete 2>/dev/null || true
find "$STAGE" -name '*.jar' -delete 2>/dev/null || true
find "$STAGE" -name '*.so' -delete 2>/dev/null || true
find "$STAGE" -name '*.dll' -delete 2>/dev/null || true
find "$STAGE" -name '*.act' -delete 2>/dev/null || true
find "$STAGE" -name '*.pyc' -delete 2>/dev/null || true
rm -f "$STAGE"/漏洞.md "$STAGE"/不足.md 2>/dev/null || true
# external issue bundles dropped into the work tree must never ship
rm -f "$STAGE"/*.zip 2>/dev/null || true
find "$STAGE" -maxdepth 1 -name 'engrail-issues-*' -delete 2>/dev/null || true

# speedtest flavor: embed the compile/bench procedure in the package
if [ "$SUF" = "speedtest" ]; then
    cat > "$STAGE/SPEEDTEST.md" <<'MD'
# Engrail 编译速度测试包

干净源码树。计时命令（Linux/MSYS2 通用）：

    time ./configure --enable-shared     # 或 Windows: --cc=gcc --cxx=g++
    time make                            # 编译 + smoke 自检
    time make check                      # 10 个测试套件
    time make e2e                        # 14 步端到端
    time sh crypto/build.sh              # 独立库生成 + 官方向量
    sh crypto/bench.sh                   # 性能基准（输出发回录入 BENCHMARKS.md）
    bash scripts/cli_pass_test.sh        # CLI 回归

Windows/MSVC（CMake 路线）：

    ./configure --cc=cl --cxx=cl --disable-tools --disable-examples --disable-bench --disable-tests
    cmake -B build-msvc -G "Visual Studio 17 2022" .
    cmake --build build-msvc --config Release -- /m

记录：每条 time 结果 + CPU 型号 / 编译器版本（cc --version）/ 核数 / 冷热编译。
MSYS2 注意：`time` 的 user/sys 不统计原生子进程，只有 real 有意义；从
PowerShell 调 MSYS2 时复杂命令必须走脚本文件，不要内联 `bash -lc "..."`。
MD
fi

echo "== tar.gz =="
tar -C "$(dirname "$STAGE")" -czf "$OUT/$NAME.tar.gz" "$NAME"
echo "== zip =="
(cd "$(dirname "$STAGE")" && zip -qr "$OUT/$NAME.zip" "$NAME")

echo
ls -la "$OUT/$NAME.tar.gz" "$OUT/$NAME.zip"
echo "== content check (must be identical) =="
diff <(tar tzf "$OUT/$NAME.tar.gz" | sort) \
     <(python3 -c "import zipfile,sys
print('\\n'.join(zipfile.ZipFile(sys.argv[1]).namelist()))" "$OUT/$NAME.zip" | sort) \
    && echo "identical file lists" \
    || { echo "PACKAGE MISMATCH"; exit 1; }
N=$(tar tzf "$OUT/$NAME.tar.gz" | grep -vc '/$')
echo "$((N - 1)) files packed"
