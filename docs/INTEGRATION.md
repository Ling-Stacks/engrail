# Engrail 对接手册

从零到产品上线，每一步该调什么。面向集成方开发者。

配套文档：[README_zh.md](../README_zh.md)（项目概览）· [ADVERSARIAL.md](../ADVERSARIAL.md)（攻防模型）· [docs/ANDROID.md](ANDROID.md) · [docs/WINDOWS.md](WINDOWS.md)

---

## 1. 三十秒决策树：选哪种形态

```
你要什么？ 
├─ 只要密码学原语（国密/Ed25519/哈希/KDF，自己搭业务）
│    → crypto/ 独立库：拷 dist/engrail_crypto.{h,c} 两个文件，完事
│
├─ 要离线授权（激活码、机器绑定、吊销）+ 任何语言
│    ├─ C/C++ 项目 → 头文件 + 源码 / amalgamation / CMake / make install
│    ├─ Python / Rust / Java / Kotlin / C# / Shell → bindings/ 对应目录
│    └─ 浏览器 / Node → bindings/wasm/
│
└─ 两者都要 → 全库（授权库内含全部密码学原语，API 同 crypto/）
```

---

## 2. 构建

### 2.1 configure + make（推荐）

```bash
./configure              # 生成 Makefile + CMakeLists.txt（94 项环境自检）
make                     # 编译 + 自动跑 smoke 测试（12 项）
make check               # 10 套件全量测试
```

常用 configure 选项：

| 选项 | 作用 |
| --- | --- |
| `--enable-shared` | 额外产出 `build/libactivation.so`（绑定必需） |
| `--cc=... --cxx=...` | 指定交叉编译器（NDK/MinGW） |
| `--prefix=/usr/local` | `make install` 的安装前缀 |
| `--disable-tests / --disable-bench / --disable-tools / --disable-examples` | 裁剪构建 |
| `NO_SMOKETEST=1 make` | 跳过构建后自检 |

常用 make 目标：`test`（快速）、`check`（全量）、`e2e`（14 步端到端演示）、`bindings`（全部语言绑定）、`amalgamation`（生成 dist/ 两文件发布物）、`install`、`bench`。

### 2.2 amalgamation（两个文件进项目）

```bash
make amalgamation
# 产出 dist/activation.h + dist/activation.c（授权+密码学全套）
#      dist/activation.hpp + dist/activation.cpp（C++17 包装，可选）
```

把 `activation.h/c` 拖进任意工程一起编译即可；C++ 再加 `hpp/cpp`。

### 2.3 CMake

`CMakeLists.txt` 由 configure 生成；或把本仓库作为子目录 `add_subdirectory` 后链接 `activation` 目标。

### 2.4 独立密码学库

```bash
sh crypto/build.sh       # 生成 crypto/dist/engrail_crypto.{h,c} + 跑官方向量
```

### 2.5 交叉编译

Android NDK / MinGW：给 configure 传 `--cc/--cxx`，其余自动（Android/Linux 自动判别）。详见 ANDROID.md / WINDOWS.md。

---

## 3. 厂商侧工作流（你的电脑）

### 3.1 生成密钥对（一次）

```bash
./build/engrail-keygen keygen vendor.key
```

- `vendor.key` 是 64 字节 Ed25519 私钥（seed||pub），**离线保存，永不进客户端**
- 加口令存储：`--pass '你的口令'`（ACTKEY2 格式：PBKDF2×200,000 + ChaCha20 + HMAC，盗走文件也打不开）
- 双栈：同一 seed 经 HKDF 派生独立的 SM2 密钥（`act_dual_from_ed25519_seed`），一套密钥管两种算法

### 3.2 导出部署参数（给客户端嵌的）

```bash
./build/engrail-keygen export-pub --pass '...' vendor.key deploy.pub
```

`deploy.pub` 含：公钥（32B）+ **部署盐 dsalt**（32B）。dsalt 决定客户端所有派生密钥与机器码——同一份代码 + 不同 dsalt = 机器码完全不同，泄漏源码也复刻不了你的部署。

### 3.3 签发授权码

```bash
./build/engrail-keygen issue vendor.key \
    --product 1 \
    --machine F8BDE075F9DE40A3-D54D62B64E4D68AC \
    --days 365            # 或 --perpetual；可加 --trial --features 0x0003
```

| 参数 | 含义 |
| --- | --- |
| `--product N` | 产品 ID，客户端校验时必须一致 |
| `--machine MC` | 客户报来的机器码（应用打印） |
| `--days N / --perpetual` | 有效期天数 / 永久 |
| `--trial` | 试用标记（语义应用自定义） |
| `--features 0xMASK` | 16 位功能层级掩码（如 0x0003 = 基础+专业） |
| `--serial HEX16` | 手工指定序列号（默认 CSPRNG 随机） |

`inspect [--json] <code>` 可离线解析任意授权码元数据。

### 3.4 吊销

```bash
./build/engrail-keygen revoke vendor.key revoke.dat <序列号|授权码>
```

`revoke.dat` 是**厂商签名的**序列号黑名单（客户端验签，删改无效），随应用更新分发。客户端一行代码接入：`act_revoke_check(path, pk, &info)`。

### 3.5 离线令牌与质询-应答

```bash
# 签名令牌（TTL 有效期的任意载荷，Base64URL）
engrail-keygen token sign  vendor.key --ttl 3600 --payload 'premium'
engrail-keygen token verify deploy.pub <token>

# 质询-应答（防重放的离线单次授权）
engrail-keygen challenge --machine MC --product 1     # 客户端产生
engrail-keygen respond   vendor.key <challenge>       # 厂商离线签
engrail-keygen verify    deploy.pub <challenge> <response> --machine MC
```

---

## 4. 应用侧 API

### 4.1 C++（推荐入口）

```cpp
#include "activation/activation.hpp"

act::Verifier v(PUBKEY, DSALT, PRODUCT_ID);

v.machine_code();                  // "XXXXXXXX-XXXXXXXX" 显示给用户
v.activate(code, "app.act");       // 验码 + 落盘（一次性）
v.verify_saved("app.act");         // 每次启动调用
v.verify_saved("app.act", "revoke.dat");  // + 吊销名单
v.verify_hardened(code);           // 反调试 + 自完整性 + 负向冗余验证
v.check_code(code, info);          // 只验不存，拿元数据
info.days_remaining(now);          // INT64_MAX=永久, 0=已过期
info.has_feature(2);               // 功能位
v.verify_token(token, now, payload);   // 离线令牌
v.challenge() / v.verify_challenge();  // 质询-应答
```

### 4.2 C API 速查（按头文件）

| 头文件 | 关键函数 |
| --- | --- |
| `license.h` | `act_license_make / encode / decode / verify(_payload)`、`act_days_remaining`、`act_has_feature` |
| `fingerprint.h` | `act_fingerprint`、`act_fp_to_string` |
| `state.h` | `act_state_save / load / check` |
| `revoke.h` | `act_revoke_save / add / load / check / contains` |
| `token.h` | `act_token_create / verify`、`act_challenge_create / respond / verify` |
| `harden.h` | `act_harden_debugger_present`、`act_harden_selfcheck`、`act_verify_hardened`、`ACT_INTEGRITY_SLOT` |
| `keyfile.h` | `act_keyfile_save / load`（口令加密密钥文件） |
| `audit.h` | `act_audit_init / append / verify`（链式 HMAC 审计日志） |
| `ed25519.h / sm2.h / sm3.h` | `act_ed25519_*`、`act_sm2_*`、`act_sm3*` |
| `sha512.h / hmac.h / kdf.h / chacha20.h` | `act_sha512*`、`act_hmac_sha512`、`act_hkdf_*`、`act_pbkdf2_*`、`act_chacha20_xor`、`act_secure_wipe/memcmp` |

### 4.3 错误码全表

| 码 | 名称 | 含义 |
| --- | --- | --- |
| 0 | `ACT_OK` | 成功 |
| -1 | `ACT_ERR_ARG` | 参数为 NULL / 非法 |
| -2 | `ACT_ERR_FORMAT` | 授权码/密文格式不合法 |
| -3 | `ACT_ERR_VERSION` | 载荷版本不支持 |
| -4 | `ACT_ERR_PRODUCT` | 产品 ID 不匹配 |
| -5 | `ACT_ERR_SIGNATURE` | 签名错误（伪造/篡改） |
| -6 | `ACT_ERR_MACHINE` | 机器码不匹配 |
| -7 | `ACT_ERR_EXPIRED` | 已过期 |
| -8 | `ACT_ERR_STATE_MISSING` | 状态文件不存在 |
| -9 | `ACT_ERR_STATE_IO` | 状态文件读写失败 |
| -10 | `ACT_ERR_STATE_CORRUPT` | 状态文件损坏/被改 |
| -11 | `ACT_ERR_REVOKED` | 序列号在吊销名单 |
| -12 | `ACT_ERR_DEBUGGER` | 检测到调试器 |
| -13 | `ACT_ERR_INTEGRITY` | 自完整性校验失败 |
| -14 | `ACT_ERR_MISMATCH` | 负向冗余验证不一致 |
| -15 | `ACT_ERR_ENTROPY` | 系统熵源故障 |

---

## 5. 八种语言绑定速查

所有绑定调同一个纯 C ABI，能力一致。位置 `bindings/`。

| 语言 | 目录 | 环境 | 试运行 |
| --- | --- | --- | --- |
| Python | `python/` | python3（纯 ctypes，零构建） | `ACTIVATION_LIB=... python3 python/example.py` |
| Rust | `rust/` | cargo（零依赖 crate，连 cc 都不用） | `cd rust && cargo run --example demo` |
| Java | `java/` | javac + java（JNI） | `sh java/... `（见目录内说明） |
| Kotlin | `kotlin/` | kotlinc（复用 Java JNI 库） | `kotlinc ../kotlin/Demo.kt ...` |
| C# | `csharp/` | dotnet 6+ / mono（netstandard2.0，Unity 可用） | `sh csharp/build.sh` |
| Shell | `shell/` | bash + keygen CLI | `sh shell/demo.sh` |
| JS/WASM | `wasm/` | emsdk 构建 + node 18+/现代浏览器 | `sh wasm/build.sh` |
| C/C++ | 主库 | 任意 C99/C++17 编译器 | `./configure && make` |

统一入口测试（缺哪个工具链自动跳过并报告）：

```bash
./configure --enable-shared && make && make bindings
```

### Python 示例

```python
from activation import Activation
act = Activation(pubkey_hex, dsalt_hex, product_id=1)
print(act.machine_code())
ok, info = act.verify_code("08000-...")
act.activate("08000-...", "app.act")
print(act.verify_saved("app.act"))
```

### WASM 示例

```js
import { Engrail } from "./engrail_wasm.mjs";
const eng = await Engrail.load();
const kp = eng.ed25519Keypair();
eng.ed25519Verify(eng.ed25519Sign(msg, kp.privkey), msg, kp.pubkey);  // true
const v = eng.licenseVerify(code, kp.pubkey, 1, machineBytes, now);   // {ok, info}
```

### C# 示例

```csharp
var act = new Activation(pubkeyHex, dsaltHex, productId: 42);
Console.WriteLine(act.MachineCode());
var (st, info) = act.VerifyCode(code);
act.Activate(code, "app.act");
act.VerifySaved("app.act");
```

---

## 6. 加固三件套（可选，推荐发行版启用）

1. **反调试**：`act_harden_debugger_present()` —— Linux/Android 查 TracerPid，macOS 查 P_TRACED，Windows 查 IsDebuggerPresent
2. **自完整性**：源码放一个 `ACT_INTEGRITY_SLOT;`（99 字节槽位）→ 发布前 `./build/engrail-integrity patch app.exe` 把全文件 SHA-512 嵌进槽位 → 运行时 `act_harden_selfcheck()` 重算比对
3. **负向冗余验证**：`act_verify_hardened()` / `v.verify_hardened(code)` —— 除正常验码外，故意喂一个坏签名并断言验证器拒绝它；验证逻辑被 patch 时立即暴露

三件独立可叠加，任一失败返回 -12/-13/-14。

---

## 7. 部署安全模型要点

- **dsalt**：部署唯一。泄漏公钥+dsalt 不泄漏私钥，只影响该部署机器码可复算——轮换 dsalt 即可换血
- **私钥**：永不出现在客户端二进制、内存快照之外的地方；keyfile 口令加密只是运输层防御
- **机器码采集源**（POSIX）：uname 全字段 / USER·登录名 / machine-id·boot_id / hostid / CPU 信息；三轮 HKDF 级联压缩为 16 字节。普通用户改 `USER` 环境变量可变机器码（已知弱点，试用限频在厂商侧兜底——见 ADVERSARIAL.md §2）
- **线程安全**：所有 `act_*` 无隐藏可变全局状态（SM2 常量初始化内部已做原子保护），可多线程并发调用
- **熵源**：getrandom / ProcessPrng 直取；带全 0/全 FF 退化检测；故障即 abort，绝不降级到弱随机

---

## 8. 性能参考

独立基准（固定迭代、跨平台可比）：`sh crypto/bench.sh`（原生）、
`node bindings/wasm/bench.mjs`（WASM）。方法与各平台数据见
[docs/BENCHMARKS.md](BENCHMARKS.md)。

ARM64 便携实测摘要：Ed25519 签名 ~1.7ms / 验证 ~4.0ms；
SM2 签名/验证 ~1.7–2.2ms；SHA-512 64B ~0.6µs。

跑 `make bench` 得到全库在你机器上的数字。

---

## 9. 常见问题

**Q: 用户换电脑了怎么办？**
旧码绑定旧机器码，直接给新机器码重新 `issue` 一张。要阻止旧机器继续用就 `revoke` 旧序列号。

**Q: 授权码被截图传播？**
码绑机器指纹，别的机器验不过（-6）。

**Q: 客户改系统时间绕过期？**
单机对抗时钟回拨没有完美方案；可记录"见过的最大时间"到状态文件（自带签名，改了会检出 -10）作为低成本缓解。

**Q: 能完全防破解吗？**
不能——任何本地验证理论上都可被 patch 二进制绕过，本库把伪造授权码做到密码学不可行（ECDLP），把 patch 成本用三件套抬高。需要绝对控制就加服务器二次校验，本库不阻止混合模式。

**Q: WASM 里能用机器码绑定吗？**
浏览器没有稳定硬件指纹，WASM 构建定位是密码学原语 + 授权码验签（机器码由前端自行生成传入）。文件类 API（state/fingerprint）不在 WASM 导出列表。

---

社区支持：[t.me/Stack_Traces](https://t.me/Stack_Traces)
