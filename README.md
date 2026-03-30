# GMKit - 国密算法 Java 工具库

[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)
[![JDK](https://img.shields.io/badge/JDK-1.8+-green.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)

GMKit 是一个基于 BouncyCastle 的国密算法工具库，提供 SM2、SM3、SM4 的对象式 API 和静态工具 API，兼容 JDK 8+。

## 特性

- 单一运行时 artifact，接入和发布更简单
- 一个算法一个主入口类，同时保留对象式和静态工具式两套调用方式
- `SM2Util`、`SM3Util`、`SM4Util` 作为静态工具入口，适合原有工具类调用习惯
- 内部按职责拆分实现，外部 API 保持直接、清晰
- 内置测试覆盖 SM2/SM3/SM4 常见路径和兼容别名

## 支持算法

| 算法  | 说明         | 主入口                |
|-----|------------|--------------------|
| SM2 | 椭圆曲线公钥密码算法 | `cn.gmkit.sm2.SM2` |
| SM3 | 密码杂凑算法     | `cn.gmkit.sm3.SM3` |
| SM4 | 分组密码算法     | `cn.gmkit.sm4.SM4` |

## Maven 引入

```xml
<dependency>
    <groupId>cn.gmkit</groupId>
    <artifactId>gmkit</artifactId>
    <version>0.9.4-SNAPSHOT</version>
</dependency>
```

## 快速开始

### SM2 对象式

```java
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.core.SM2SignatureFormat;
import cn.gmkit.sm2.SM2;
import cn.gmkit.sm2.SM2KeyPair;
import cn.gmkit.sm2.SM2SignOptions;

import java.nio.charset.StandardCharsets;

SM2 sm2 = new SM2();
SM2KeyPair keyPair = sm2.generateKeyPair(false);
byte[] plaintext = "Hello GMKit!".getBytes(StandardCharsets.UTF_8);

byte[] ciphertext = sm2.encrypt(keyPair.publicKey(), plaintext, SM2CipherMode.C1C3C2);
byte[] decrypted = sm2.decrypt(keyPair.privateKey(), ciphertext, SM2CipherMode.C1C3C2);

byte[] signature = sm2.sign(
    keyPair.privateKey(),
    plaintext,
    SM2SignOptions.builder()
        .signatureFormat(SM2SignatureFormat.RAW)
        .build());
boolean valid = sm2.verify(keyPair.publicKey(), plaintext, signature);
```

### SM3 对象式

```java
import cn.gmkit.sm3.SM3;

import java.nio.charset.StandardCharsets;

SM3 sm3 = new SM3();
String hash = sm3.digestHex("Hello GMKit!");
String hmac = sm3.hmacHex("secret".getBytes(StandardCharsets.UTF_8), "Hello GMKit!");
```

### SM4 对象式

```java
import cn.gmkit.core.SM4CipherMode;
import cn.gmkit.core.SM4Padding;
import cn.gmkit.sm4.SM4;
import cn.gmkit.sm4.SM4CipherResult;
import cn.gmkit.sm4.SM4Options;

import java.nio.charset.StandardCharsets;

SM4 sm4 = new SM4();
byte[] key = sm4.generateKey();
byte[] iv = new byte[16];

SM4Options options = SM4Options.builder()
    .mode(SM4CipherMode.CBC)
    .padding(SM4Padding.PKCS7)
    .iv(iv)
    .build();

SM4CipherResult encrypted = sm4.encrypt(key, "Hello GMKit!".getBytes(StandardCharsets.UTF_8), options);
String decrypted = sm4.decryptToUtf8(key, encrypted, options);
```

### 静态工具式

```java
import cn.gmkit.sm2.SM2Util;
import cn.gmkit.sm2.SM2KeyPair;
import cn.gmkit.sm3.SM3Util;
import cn.gmkit.sm4.SM4Util;

SM2KeyPair keyPair = SM2Util.generateKeyPair(false);
String hash = SM3Util.digestHex("Hello GMKit!");
byte[] key = SM4Util.generateKey();
```

### 与 gmkit / gmkitx 对齐的前缀式别名

为方便和 `gmkits/gmkit` 的函数式暴露习惯对齐，Java 版补充了语义更直接的前缀式入口；旧 API 保持不变。

```java
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.sm2.SM2KeyPair;
import cn.gmkit.sm2.SM2Util;
import cn.gmkit.sm3.SM3Util;
import cn.gmkit.sm4.SM4CipherResult;
import cn.gmkit.sm4.SM4Options;
import cn.gmkit.sm4.SM4Util;

SM2KeyPair keyPair = SM2Util.sm2GenerateKeyPair(false);
byte[] cipher = SM2Util.sm2Encrypt(keyPair.publicKey(), "Hello GMKit!".getBytes(StandardCharsets.UTF_8), SM2CipherMode.C1C3C2);
byte[] plain = SM2Util.sm2Decrypt(keyPair.privateKey(), cipher, SM2CipherMode.C1C3C2);
byte[] sign = SM2Util.sm2Sign(keyPair.privateKey(), plain);
boolean ok = SM2Util.sm2Verify(keyPair.publicKey(), plain, sign);

byte[] digest = SM3Util.sm3Digest("Hello GMKit!");
byte[] mac = SM3Util.sm3Hmac("secret".getBytes(StandardCharsets.UTF_8), "Hello GMKit!");

SM4CipherResult sm4Cipher = SM4Util.sm4Encrypt(key, "payload", SM4Options.builder().build());
byte[] sm4Plain = SM4Util.sm4Decrypt(key, sm4Cipher, SM4Options.builder().build());
```

### 后端混合加密封装（SM2 + SM4）

后端常见场景是：用 `SM2` 保护一次性 `SM4` 会话密钥，再用 `SM4` 加密业务数据。现在可以直接使用统一封装，避免业务层手工拼装多个字段。

```java
import cn.gmkit.integration.SM2Sm4Hybrid;
import cn.gmkit.integration.SM2Sm4HybridPayload;
import cn.gmkit.sm2.SM2;
import cn.gmkit.sm2.SM2KeyPair;

SM2 sm2 = new SM2();
SM2KeyPair keyPair = sm2.generateKeyPair(false);
SM2Sm4Hybrid hybrid = new SM2Sm4Hybrid();

SM2Sm4HybridPayload payload = hybrid.encrypt(keyPair.publicKey(), "后端统一混合加密");
String plain = hybrid.decryptToUtf8(keyPair.privateKey(), payload);
```

默认情况下该封装会使用 `SM4-GCM + 随机 nonce + 16 字节 tag`，并把 `encryptedKey / ciphertext / iv / aad / tag / mode / padding`
统一放入 `SM2Sm4HybridPayload`，更适合后端服务间传输或落库。

## 迁移说明

- `SM2`、`SM3`、`SM4` 为对象式主入口，适合通过 `new` 绑定上下文或复用实例。
- `SM2Util`、`SM3Util`、`SM4Util` 为静态工具入口，适合工具类调用风格。
- `SM2Util.sm2GenerateKeyPair / sm2Encrypt / sm2Decrypt / sm2Sign / sm2Verify`
  与 `SM3Util.sm3Digest / sm3Hmac`、`SM4Util.sm4Encrypt / sm4Decrypt` 为前缀式兼容入口，便于和
  `gmkits/gmkit` 的函数命名保持一致。
- `SM2EncryptOptions`、`SM2DecryptOptions`、`SM4DecryptOptions` 已移除：
    - SM2 加解密改为默认重载或直接传 `SM2CipherMode`
    - SM4 解密和加密统一使用 `SM4Options`，AEAD tag 通过 `tag(...)` 传入
- 所有公开命名统一使用大写缩写 `SM*` 风格，例如 `SM2KeyPair`、`SM4Options`。

## 编码与格式工具

如果需要在后端侧统一处理 Hex / Base64 输入输出，可直接使用 `ByteEncodings`、`InputFormat`、`OutputFormat`：

```java
import cn.gmkit.core.ByteEncodings;
import cn.gmkit.core.InputFormat;
import cn.gmkit.core.OutputFormat;

String base64 = ByteEncodings.encode("abc".getBytes(StandardCharsets.UTF_8), OutputFormat.BASE64);
byte[] decoded = ByteEncodings.decode(base64, InputFormat.BASE64, "payload");
```

## 仓库结构

```text
gmkit-java/
├── gmkit/               # 单一运行时模块
│   └── src/
├── docs/
├── pom.xml              # 父工程
└── README.md
```

## 构建

```bash
mvn clean test
mvn -DskipTests verify
```

## GitHub Actions

仓库已提供 CI、Release Verify、GitHub Packages 发布和 Maven Central 发布工作流，使用方法见 [docs/github-actions.md](docs/github-actions.md)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源协议。
