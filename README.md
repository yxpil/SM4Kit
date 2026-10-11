# SM4Kit

一套 SM4 分组密码（**GB/T 32907-2016**）的多语言组件库：同一套 API 设计、同一组标准测试向量，8 种语言实现，全部零第三方依赖。

[![tests](https://github.com/yxpil/SM4Kit/actions/workflows/tests.yml/badge.svg)](https://github.com/yxpil/SM4Kit/actions/workflows/tests.yml)
![license](https://img.shields.io/badge/license-MIT-green)

## 特性

- **算法**：SM4 加解密（32 轮、S 盒、CK 常量按公式生成）、ECB / CBC 模式、PKCS7 填充
- **8 种语言**：JavaScript / TypeScript · Python · Go · Java · Rust · PHP · Ruby · C
- **零依赖**：全部只用标准库 / 纯语言实现，可直接拷贝单文件集成
- **同一套测试**：每种实现内置标准测试向量自测（`ALL PASS` 即通过）：
  - KAT1：GB/T 32907-2016 附录 A 示例 1（单块密文 `681edf34d206965e86b3e94f536e4246`）
  - KAT2：GB/T 32907-2016 附录 A 示例 2（同密钥连续加密 1,000,000 次 → `595298c7c6fd271f0402f804c33d3f66`）
  - CBC 链式验证 + 多边界长度往返（0/1/15/16/17/100 字节）
- **跨语言一致**：任意语言加密的密文可在其它语言正确解密（CI 覆盖）

## 语言与用法

| 语言 | 目录 | 运行自测 |
|---|---|---|
| JavaScript | [`javascript/`](javascript/) | `node sm4.js` |
| Python | [`python/`](python/) | `python sm4_kit.py` |
| Go | [`go/`](go/) | `go run .` |
| Java | [`java/`](java/) | `javac SM4.java && java SM4` |
| Rust | [`rust/`](rust/) | `cargo test --release` |
| PHP | [`php/`](php/) | `php sm4.php` |
| Ruby | [`ruby/`](ruby/) | `ruby sm4.rb` |
| C | [`c/`](c/) | `gcc -O2 -o sm4_test sm4.c test_main.c && ./sm4_test` |

> 追加 `--long` 参数（JS/Python/PHP/Ruby/C）会额外跑 100 万次迭代标准向量，更慢但更全面。

### JavaScript / TypeScript

```js
const { cbcEncrypt, cbcDecrypt } = require('./sm4.js'); // 浏览器 <script> 引入后为 window.sm4kit
const key = new Uint8Array(16);  // 16 字节密钥，务必用安全随机源
const iv = new Uint8Array(16);   // 16 字节 IV，每次加密应随机
const ct = cbcEncrypt(key, iv, new TextEncoder().encode('你好，SM4'));
const pt = new TextDecoder().decode(cbcDecrypt(key, iv, ct));
```

TypeScript 类型见 [`javascript/sm4.d.ts`](javascript/sm4.d.ts)。

### Python

```python
from sm4_kit import cbc_encrypt, cbc_decrypt
ct = cbc_encrypt(key16, iv16, "你好，SM4".encode())
pt = cbc_decrypt(key16, iv16, ct)
```

### Go

```go
ct, _ := CbcEncrypt(key, iv, []byte("你好，SM4"))
pt, _ := CbcDecrypt(key, iv, ct)
```

### Java

```java
byte[] ct = SM4.cbcEncrypt(key, iv, "你好，SM4".getBytes(StandardCharsets.UTF_8));
byte[] pt = SM4.cbcDecrypt(key, iv, ct);
```

### Rust

```rust
use sm4kit::{cbc_encrypt, cbc_decrypt};
let ct = cbc_encrypt(&key, &iv, b"hello");
let pt = cbc_decrypt(&key, &iv, &ct).unwrap();
```

### PHP / Ruby / C

函数命名与上述一致（`sm4_cbc_encrypt` / `SM4Kit.cbc_encrypt` / `sm4_cbc_encrypt`），均为单文件拷贝即用。C 接口使用 `malloc` 返回缓冲区、通过 `err` 指针报错，详见 [`c/sm4.h`](c/sm4.h)。

## 标准测试向量

| 向量 | 密钥 | 明文 | 结果 |
|---|---|---|---|
| GB/T 32907 附录A 例1 | `0123456789abcdeffedcba9876543210` | `0123456789abcdeffedcba9876543210` | `681edf34d206965e86b3e94f536e4246` |
| GB/T 32907 附录A 例2（加密 10⁶ 次） | 同上 | 同上（迭代） | `595298c7c6fd271f0402f804c33d3f66` |

## 安全提醒

- ECB 模式不隐藏明文模式，生产环境优先使用 CBC（随机 IV）或再外层组合认证加密
- 本库只实现机密性，**不含消息认证（MAC）**；需要防篡改请自行组合 HMAC/SM3 或使用 AEAD 方案
- 密钥与 IV 必须来自密码学安全随机源；IV 每次加密都应更换且无需保密
- 侧信道防护（恒定时间表查找等）不在目标范围内，高对抗场景请使用硬件/密码库实现

## 来源

本库核心源自 [yxpil.com](https://yxpil.com) 生产环境密钥封存模块（SM4-CBC 内层 + AES-GCM 外层的 `ENC2` 信封），按标准 SM4 接口抽出并移植为多语言实现。

## License

[MIT](LICENSE)
