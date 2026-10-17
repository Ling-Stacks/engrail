# Engrail

**离线授权引擎 + 独立现代密码学工具箱。纯 C 和 C++，零依赖，MIT。**

应用里嵌公钥，授权码用私钥签发——没有私钥想造出能通过验证的码，其难度在随机预言机模型下归约到椭圆曲线离散对数问题。SM2/SM3/Ed25519 全套以独立单文件密码学库的形式随仓库发布，可以完全不管授权单独拿去用。

支持 Linux、macOS、Windows、Android，以及浏览器（WebAssembly）。

[English](README.md) · [对接手册](docs/INTEGRATION.md)

---

## 为什么值得一个 Star

### 一个 C 文件装下国密 + 现代密码学全套

`engrail_crypto.c` 是单个编译单元，里面有 SM2 签名、SM2 公钥加密（C1C3C2）、SM3、Ed25519、SHA-512、HMAC、HKDF、PBKDF2、ChaCha20 和 fail-closed 的系统 CSPRNG 接口。两个文件拷进任何 C99 项目就完事——不用 configure、不用子模块、不用 OpenSSL、不用运行时。交叉编译到嵌入式、NDK、MinGW、MSVC、wasm，你这边一个 `#ifdef` 都不用写。

### 浏览器里跑国密

WebAssembly 构建把 SM2/SM3/Ed25519 和完整授权码验证全部搬到前端本地 WebAssembly 里跑：零网络请求、零依赖、零 CDN。前端直接验签不需要后端——GB/T 32918 的实现里能这么干的，之前基本没有。

### 九种语言，一套 ABI

C、C++、Python、Rust、Java、Kotlin、C#（含 Unity）、Shell、JavaScript/WASM，全部绑定**同一个**纯 C 核心。没有重写、没有翻译层、没有各自漂移的多份实现——Rust 验的签名和 Java 签的和浏览器查的完全一致。一套测试覆盖所有语言。

### 密码学上正确，且被独立验证过

每个原语都过官方测试向量：FIPS 180-4（SHA-512）、RFC 4231（HMAC）、RFC 5869（HKDF）、RFC 8018（PBKDF2）、RFC 8032（Ed25519）、RFC 8439（ChaCha20）、GB/T 32905（SM3）、GB/T 32918（SM2）。此外 SM2/SM3 与独立 Python 实现**双向**交叉验证：C 签的名 Python 验、Python 加的密 C 解。单比特翻转模糊测试穷举全部 512 个签名位和 288 个载荷位。

### 源码全公开也泄漏不了任何东西

代码库里没有任何秘密常量。所有运行时密钥经三轮 HKDF 级联 + 部署盐（dsalt）派生：同一份源码、同一台机器、两个部署——机器码完全不同。你 fork 公开、模板丢失、发行 debug 版，全都复刻不出你的密钥。唯一要紧的东西永远离线：你的 Ed25519 seed。

### 假定攻击者读过源码的反逆向

三个独立可叠加的层：

1. **反调试探测** —— Linux/Android 查 TracerPid，macOS 查 P_TRACED，Windows 查 IsDebuggerPresent
2. **可执行文件自完整性** —— 发布前把全文件 SHA-512 嵌进 99 字节槽位，启动时重算比对。动了二进制，摘要就对不上
3. **负向控制冗余验证** —— 加固路径故意喂一个已知坏签名，并断言验证器**拒绝**它。有人 NOP 掉你的校验，负向控制立刻暴露。部署成本几乎为零，绕过成本实实在在

### 熵源宁可死也不降级

密钥直取 `getrandom(2)` / `ProcessPrng`，带退化输出健康检查（全 0 / 全 FF 检测）。熵源坏了库直接中止——绝不静默退化成把所有密钥拱手送人的弱随机。

### 对威胁模型诚实的授权库

[ADVERSARIAL.md](ADVERSARIAL.md) 写明了每一条可行的攻击路径，包括对我们自己有效的——root 能伪造什么、patch 二进制能跳过什么、攻防成本各在哪。宣称"不可破解"的安全工具是营销；本仓库直接把攻防账本随代码一起发。

---

## 授权侧给你什么

- **机器绑定** —— 平台标识三轮 HKDF 级联压成 16 字节指纹；A 机器的码到 B 机器就是废纸
- **限时 / 永久 / 试用 / 功能分层** —— 16 位功能掩码、锚定 2020-01-01 UTC 的过期字段、标记位
- **签名吊销名单** —— 退款/泄漏处理：签一张序列号黑名单随更新发下去，客户端拿你的公钥验名单。用户删不掉自己的序列号
- **离线令牌** —— Ed25519 签名的 Base64URL 令牌带 TTL，用于权益下发；另有防重放的质询-应答做一次性离线授权
- **加固状态存储** —— 激活状态文件带厂商签名，改一个字节验证即失败
- **加密的厂商密钥文件** —— 静态口令加密（PBKDF2×200,000 + ChaCha20 + HMAC，加密后认证）
- **链式 HMAC 审计日志** —— 防篡改事件流，合规场景友好

---

## 快速开始

```bash
./configure
make
make test
```

需要 C99 和 C++17 编译器，其他什么都不用装。configure 会跑 94 项环境自检，并从全变量模板生成 Makefile 和 CMakeLists.txt。

## 怎么用

厂商侧（你自己电脑上跑）：

```bash
./build/engrail-keygen keygen vendor.key    # 一次；离线保存
./build/engrail-keygen issue vendor.key \
    --product 1 \
    --machine F8BDE075F9DE40A3-D54D62B64E4D68AC \
    --days 365
```

应用侧（嵌在你产品里的代码）：

```cpp
#include "activation/activation.hpp"

static const uint8_t PUBKEY[32] = { /* keygen 打印的那个 */ };
static const uint8_t DSALT[32]  = { /* keygen 打印的那个 */ };

act::Verifier verifier(PUBKEY, DSALT, 1);

verifier.activate(code, "app.act");   // 用户输入授权码，一次

if (verifier.verify_saved("app.act") == act::Status::Ok) {
    // 已授权——每次启动复查
}
```

只要密码学不要授权？两个文件拷走：

```bash
sh crypto/build.sh    # 生成 crypto/dist/engrail_crypto.{h,c} 并跑官方向量
```

每种语言、每个平台的完整步骤：**[对接手册](docs/INTEGRATION.md)** —— 构建方式、CLI 全参考、API 表、错误码、加固部署、FAQ。

## 集成方式

| 方式 | 适合场景 |
| --- | --- |
| 两个文件（`crypto/dist/engrail_crypto.{h,c}`） | 只要密码学原语 |
| 两个文件（`dist/activation.{h,c}`） | 授权 + 密码学全套 |
| CMake 子目录 | 已用 CMake 的项目 |
| `make install` + pkg-config | 系统级安装 |
| `bindings/` 八种语言绑定 | Python、Rust、Java、Kotlin、C#、Shell、JS/WASM |

## 文档

- [对接手册](docs/INTEGRATION.md) —— 完整集成指南
- [独立密码学库](crypto/README.md)
- [性能基准](docs/BENCHMARKS.md) —— x86 / ARM64 / WASM 方法与数据
- [Android 接入](docs/ANDROID.md) · [Windows 编译](docs/WINDOWS.md)
- [攻防分析](ADVERSARIAL.md) —— 给安全研究者
- [变更记录](CHANGELOG.md)

## 测试

```bash
make check      # 10 个测试套件，207+ 用例
make e2e        # 14 步端到端演示
make bindings   # 全部语言绑定 + 独立库向量测试
crypto/build.sh # 独立库一致性向量
```

## 社区

问题、需求、更新：[t.me/Stack_Traces](https://t.me/Stack_Traces)

## 许可

MIT，见 [LICENSE](LICENSE)。Ed25519 域算术基于 TweetNaCl（公有领域）移植并加固——增加规范化检查、常时比较收尾、密钥擦除；其余原语全部独立实现。
