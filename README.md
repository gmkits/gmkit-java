# GMKit - 国密算法 Java 工具库

[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)
[![JDK](https://img.shields.io/badge/JDK-1.8+-green.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)

GMKit 是一个基于 BouncyCastle 的国密算法工具库，当前提供 SM2、SM3、SM4 的静态工具 API，兼容 JDK 8+。

## 特性

- 单一运行时 artifact，接入和发布更简单
- 一个算法一个主工具类，避免门面类和轻量 options 过度堆叠
- 保留 `SM2Util`、`SM3Util`、`SM4Util` 兼容入口，便于平滑迁移
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

### SM2

```java
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.core.SM2SignatureFormat;
import cn.gmkit.sm2.SM2;
import cn.gmkit.sm2.SM2KeyPair;
import cn.gmkit.sm2.SM2SignOptions;

import java.nio.charset.StandardCharsets;

SM2KeyPair keyPair = SM2.generateKeyPair(false);
byte[] plaintext = "Hello GMKit!".getBytes(StandardCharsets.UTF_8);

byte[] ciphertext = SM2.encrypt(keyPair.publicKey(), plaintext, SM2CipherMode.C1C3C2);
byte[] decrypted = SM2.decrypt(keyPair.privateKey(), ciphertext, SM2CipherMode.C1C3C2);

byte[] signature = SM2.sign(
    keyPair.privateKey(),
    plaintext,
    SM2SignOptions.builder()
        .signatureFormat(SM2SignatureFormat.RAW)
        .build());
boolean valid = SM2.verify(keyPair.publicKey(), plaintext, signature);
```

### SM3

```java
import cn.gmkit.sm3.SM3;

import java.nio.charset.StandardCharsets;

String hash = SM3.digestHex("Hello GMKit!");
String hmac = SM3.hmacHex("secret".getBytes(StandardCharsets.UTF_8), "Hello GMKit!");
```

### SM4

```java
import cn.gmkit.core.SM4CipherMode;
import cn.gmkit.core.SM4Padding;
import cn.gmkit.sm4.SM4;
import cn.gmkit.sm4.SM4CipherResult;
import cn.gmkit.sm4.SM4Options;

import java.nio.charset.StandardCharsets;

byte[] key = SM4.generateKey();
byte[] iv = new byte[16];

SM4Options options = SM4Options.builder()
    .mode(SM4CipherMode.CBC)
    .padding(SM4Padding.PKCS7)
    .iv(iv)
    .build();

SM4CipherResult encrypted = SM4.encrypt(key, "Hello GMKit!".getBytes(StandardCharsets.UTF_8), options);
String decrypted = SM4.decryptToUtf8(key, encrypted, options);
```

## 迁移说明

- 新主入口为 `SM2`、`SM3`、`SM4` 静态工具类。
- `SM2Util`、`SM3Util`、`SM4Util` 仍保留，但已标记为 `@Deprecated`。
- `SM2EncryptOptions`、`SM2DecryptOptions`、`SM4DecryptOptions` 已移除：
    - SM2 加解密改为默认重载或直接传 `SM2CipherMode`
    - SM4 解密和加密统一使用 `SM4Options`，AEAD tag 通过 `tag(...)` 传入
- 对象式 API（如 `new SM3(...)`、`new SM4(...)`、`SM2.generate()`）已不再作为主设计保留；当前对外统一使用大写缩写命名的 `SM*` 入口。

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

