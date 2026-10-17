# Engrail 性能基准

独立密码学库（`crypto/`，单文件 amalgamation）的基准数据。
迭代次数固定（非自动校准），跨机器可直接对比。

## 怎么跑

| 平台 | 命令 |
| --- | --- |
| 本机原生（x86 / ARM64 / 任何 C99） | `sh crypto/bench.sh` |
| JSON 输出（CI/脚本采集） | `sh crypto/bench.sh --json` |
| WASM（需 emsdk，先 build.sh） | `sh bindings/wasm/build.sh` 然后 `node bindings/wasm/bench.mjs` |

规则：**只贴实际输出，不手改数字**。新数据连同环境（CPU/编译器/版本）一起提交。

---

## ARM64（已有真实数据）

环境：Snapdragon 8cx 类 ARM64 便携设备 · Termux · NDK clang r25c · `-O2 -std=c99` · Engrail v1.7.0

| 操作 | 耗时 |
| --- | --- |
| SHA-512 / 64B | 0.60 µs |
| SHA-512 / 1 MiB | 4.50 ms |
| SM3 / 64B | 0.99 µs |
| HMAC-SHA512 / 64B | 2.46 µs |
| ChaCha20 / 1 MiB | 4.04 ms |
| HKDF-SHA512 / 32B 输出 | 3.17 µs |
| PBKDF2 / 4096 迭代 | 6.36 ms |
| Ed25519 keypair | 1.42 ms |
| Ed25519 签名 / 64B | 1.67 ms |
| Ed25519 验证 / 64B | 4.01 ms |
| SM2 keypair | 0.87 ms |
| SM2 签名 / 64B | 2.17 ms |
| SM2 验证 / 64B | 1.75 ms |
| SM2 加密 / 32B | 1.68 ms |
| SM2 解密 / 64B | 2.14 ms |

原始输出存档：

```
operation                         iters        total        per-op
sha512/64B                       200000 iters      120.1 ms      0.601 us/op
sha512/1MiB                         200 iters      899.5 ms   4497.679 us/op
sm3/64B                          200000 iters      198.7 ms      0.993 us/op
hmac-sha512/64B                  100000 iters      245.7 ms      2.457 us/op
chacha20/1MiB                       200 iters      807.8 ms   4038.885 us/op
hkdf-sha512/32B                    5000 iters       15.8 ms      3.167 us/op
pbkdf2/4096iters                      3 iters       19.1 ms   6355.795 us/op
ed25519/keypair                     200 iters      283.8 ms   1419.155 us/op
ed25519/sign/64B                    200 iters      334.1 ms   1670.676 us/op
ed25519/verify/64B                  200 iters      801.4 ms   4007.157 us/op
sm2/keypair                         200 iters      174.5 ms    872.360 us/op
sm2/sign/64B                        200 iters      433.8 ms   2168.913 us/op
sm2/verify/64B                      200 iters      349.0 ms   1745.223 us/op
sm2/encrypt/32B                     200 iters      336.4 ms   1682.108 us/op
sm2/decrypt/64B                     200 iters      428.2 ms   2140.854 us/op
```

---

## x86-64（实测数据）

环境 A（Linux）：AMD Ryzen 7 H 260（16 逻辑核）· WSL2 Ubuntu 26.04 ext4 · GCC 15.2.0 · `-O2` · Engrail v1.7.1

| 操作 | 耗时 |
| --- | --- |
| SHA-512 / 64B | 0.30 µs |
| SHA-512 / 1 MiB | 2.05 ms |
| SM3 / 64B | 0.63 µs |
| HMAC-SHA512 / 64B | 1.16 µs |
| ChaCha20 / 1 MiB | 1.52 ms |
| HKDF-SHA512 / 32B 输出 | 2.49 µs |
| PBKDF2 / 4096 迭代 | 5.00 ms |
| Ed25519 keypair | 0.82 ms |
| Ed25519 签名 / 64B | 0.82 ms |
| Ed25519 验证 / 64B | 1.65 ms |
| SM2 keypair | 0.61 ms |
| SM2 签名 / 64B | 1.27 ms |
| SM2 验证 / 64B | 1.30 ms |
| SM2 加密 / 32B | 1.26 ms |
| SM2 解密 / 64B | 0.61 ms |

环境 B（Windows）：同一台机器 · MSYS2 UCRT64 NTFS · GCC 16.1.0 · `-O2`

| 操作 | 耗时 |
| --- | --- |
| SHA-512 / 64B | 0.28 µs |
| SHA-512 / 1 MiB | 1.99 ms |
| SM3 / 64B | 0.62 µs |
| HMAC-SHA512 / 64B | 1.11 µs |
| ChaCha20 / 1 MiB | 1.49 ms |
| HKDF-SHA512 / 32B 输出 | 2.21 µs |
| PBKDF2 / 4096 迭代 | 4.48 ms |
| Ed25519 keypair | 0.75 ms |
| Ed25519 签名 / 64B | 0.76 ms |
| Ed25519 验证 / 64B | 1.51 ms |
| SM2 keypair | 0.57 ms |
| SM2 签名 / 64B | 1.20 ms |
| SM2 验证 / 64B | 1.24 ms |
| SM2 加密 / 32B | 1.18 ms |
| SM2 解密 / 64B | 0.58 ms |

原始输出存档（环境 A，`--json`）：

```
sha512/64B       0.296 us/op    sm3/64B           0.632 us/op
sha512/1MiB      2050.6 us/op   hmac-sha512/64B   1.164 us/op
chacha20/1MiB    1521.5 us/op   hkdf-sha512/32B   2.486 us/op
pbkdf2/4096      4995.7 us/op   ed25519/keypair   824.9 us/op
ed25519/sign     822.1 us/op    ed25519/verify    1648.5 us/op
sm2/keypair      606.5 us/op    sm2/sign          1268.4 us/op
sm2/verify       1303.6 us/op   sm2/encrypt       1256.6 us/op
sm2/decrypt      613.7 us/op
```

原始输出存档（环境 B，`--json`）：

```
sha512/64B       0.275 us/op    sm3/64B           0.620 us/op
sha512/1MiB      1985.2 us/op   hmac-sha512/64B   1.109 us/op
chacha20/1MiB    1487.0 us/op   hkdf-sha512/32B   2.206 us/op
pbkdf2/4096      4477.7 us/op   ed25519/keypair   753.8 us/op
ed25519/sign     756.8 us/op    ed25519/verify    1511.1 us/op
sm2/keypair      573.4 us/op    sm2/sign          1198.9 us/op
sm2/verify       1238.4 us/op   sm2/encrypt       1178.7 us/op
sm2/decrypt      577.1 us/op
```

## WASM（实测数据）

环境：同机 WSL Ubuntu · Emscripten 3.1.69（`-O2`）· node 22 · Engrail v1.7.1

| 操作 | 耗时 |
| --- | --- |
| SHA-512 / 64B | 0.50 µs |
| SHA-512 / 1 MiB | 2.70 ms |
| SM3 / 64B | 0.75 µs |
| Ed25519 keypair | 1.10 ms |
| Ed25519 签名 / 64B | 1.10 ms |
| Ed25519 验证 / 64B | 2.21 ms |
| SM2 keypair | 0.46 ms |
| SM2 签名 / 64B | 1.01 ms |
| SM2 验证 / 64B | 0.95 ms |
| SM2 加密 / 32B | 1.06 ms |
| SM2 解密 / 64B | 0.46 ms |

原始输出存档：

```
sha512/64B       0.495 us/op    sha512/1MiB       2701.8 us/op
sm3/64B          0.747 us/op    ed25519/keypair   1096.7 us/op
ed25519/sign     1101.4 us/op   ed25519/verify    2209.7 us/op
sm2/keypair      455.8 us/op    sm2/sign          1010.4 us/op
sm2/verify       947.5 us/op    sm2/encrypt       1059.6 us/op
sm2/decrypt      459.6 us/op
```

> 解读提示：WASM 相对原生约 1.3–1.5× 慢（Ed25519 验证 2.21ms vs 1.65ms），但仍是完全可用的前端验签速度。注意 WASM 侧 `clock_gettime` 依赖 emscripten 的 winpthread 映射；无该映射的工具链会退化为 `clock()`（CPU 时间），数字不可与墙钟直接对比。

---

社区：[t.me/Stack_Traces](https://t.me/Stack_Traces)
