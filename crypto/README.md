# Engrail Crypto

现代密码学工具箱，两个文件，零依赖，C99。SM2 / SM3 / Ed25519 / SHA-512 / HMAC / HKDF / PBKDF2 / ChaCha20，外加操作系统级安全随机数。

```c
#include "engrail_crypto.h"

uint8_t pub[64], priv[32];
act_sm2_keypair(NULL, pub, priv);            /* 国密密钥对 */

uint8_t sig[64];
act_sm2_sign(sig, msg, len, priv, NULL);     /* GB/T 32918 签名 */
act_sm2_verify(sig, msg, len, pub, NULL);    /* == ACT_OK */
```

## 拿走

```
dist/engrail_crypto.h    头文件
dist/engrail_crypto.c    实现（单个编译单元）
```

拷进任何 C99 项目，和你的源码一起编译。没有配置脚本，没有子模块，没有第三方库。Linux / macOS / Windows / Android / WASM 一样跑。

重新生成两个文件：`sh build.sh`（顺带跑全套官方向量测试）。

## 都有什么

| 原语 | 标准 | 用途 |
| --- | --- | --- |
| Ed25519 | RFC 8032 | 签名/验签（32 字节公钥，64 字节签名） |
| SM2 | GB/T 32918 | 国密签名 + 公钥加密（C1C3C2） |
| SM3 | GB/T 32905 | 国密哈希 |
| SHA-512 | FIPS 180-4 | 通用哈希 |
| HMAC-SHA512 | RFC 4231 | 消息认证 |
| HKDF | RFC 5869 | 密钥派生 |
| PBKDF2 | RFC 8018 | 口令转密钥（内置 1000 万次迭代上限防 DoS） |
| ChaCha20 | RFC 8439 | 流加密 |
| CSPRNG | OS | getrandom / ProcessPrng，失败即中止，绝不降级 |

全部通过官方测试向量（`test/vectors.c`），SM2/SM3 另与独立 Python 实现双向交叉验证过。

## 和 Engrail 主库的关系

这是 Engrail 授权系统里密码学层的独立发布形态。API 一致、错误码一致、测试同源。你可以：

- 只拿这两个文件当通用密码学工具箱（不碰任何授权功能）
- 或拿主库获得完整离线授权（机器码、授权码、吊销、令牌）

## 许可

MIT。TweetNaCl 公有领域代码（Ed25519 域算术基础）已注明出处并加固。

社区：[t.me/Stack_Traces](https://t.me/Stack_Traces)
