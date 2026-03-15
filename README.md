# GMKit - 国密算法Java实现库

[![License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)
[![JDK](https://img.shields.io/badge/JDK-1.8+-green.svg)](https://www.oracle.com/java/technologies/javase-downloads.html)

GMKit 是一个高性能、易用的国密算法Java实现库，基于 BouncyCastle 提供 SM2、SM3、SM4 等国密算法的完整支持。

## ✨ 特性

- 🚀 **高性能** - 基于 BouncyCastle 优化实现，性能优异
- 🎯 **易用性** - 简洁的 API 设计，支持链式调用
- 🔒 **安全性** - 完整实现国密标准，通过安全审计
- 🧩 **模块化** - 独立模块设计，按需引入
- 📚 **完整文档** - 详细的 Javadoc 和使用示例
- ✅ **充分测试** - 完善的单元测试覆盖

## 🎯 支持的算法

| 算法      | 说明         | 模块          |
|---------|------------|-------------|
| **SM2** | 椭圆曲线公钥密码算法 | `gmkit-sm2` |
| **SM3** | 密码杂凑算法     | `gmkit-sm3` |
| **SM4** | 分组密码算法     | `gmkit-sm4` |

## 📦 快速开始

### Maven 引入

```xml
<dependency>
    <groupId>cn.gmkit</groupId>
    <artifactId>gmkit-sm2</artifactId>
    <version>0.9.4-SNAPSHOT</version>
</dependency>

<dependency>
    <groupId>cn.gmkit</groupId>
    <artifactId>gmkit-sm3</artifactId>
    <version>0.9.4-SNAPSHOT</version>
</dependency>

<dependency>
    <groupId>cn.gmkit</groupId>
    <artifactId>gmkit-sm4</artifactId>
    <version>0.9.4-SNAPSHOT</version>
</dependency>
```

### SM2 使用示例

```java
import cn.gmkit.sm2.Sm2;

// 生成密钥对
Sm2 sm2 = Sm2.generate();

// 加密
String plaintext = "Hello GMKit!";
String ciphertext = sm2.encrypt(plaintext);

// 解密
String decrypted = sm2.decrypt(ciphertext);

// 签名
String signature = sm2.sign(plaintext);

// 验签
boolean valid = sm2.verify(plaintext, signature);
```

### SM3 使用示例

```java
import cn.gmkit.sm3.Sm3Util;

// 计算摘要
String hash = Sm3Util.digestHex("Hello GMKit!");

// HMAC
byte[] key = new byte[32];
String hmac = Sm3Util.hmacHex(key, "Hello GMKit!");
```

### SM4 使用示例

```java
import cn.gmkit.sm4.Sm4;
import cn.gmkit.sm4.Sm4Options;
import cn.gmkit.core.Sm4CipherMode;

// 生成密钥
Sm4 sm4 = new Sm4();

// ECB模式加密
String ciphertext = sm4.encrypt("Hello GMKit!");

// CBC模式加密
Sm4Options options = Sm4Options.builder()
    .mode(Sm4CipherMode.CBC)
    .build();
String encrypted = sm4.encrypt("Hello GMKit!", options);
```

## 🏗️ 模块结构

```
gmkit-java/
├── gmkit-core/          # 核心模块 - 通用工具类和枚举
├── gmkit-sm2/           # SM2算法实现
├── gmkit-sm3/           # SM3算法实现
├── gmkit-sm4/           # SM4算法实现
└── gmkit-bom/           # 依赖管理BOM
```

## 🔧 构建项目

```bash
# 克隆项目
git clone https://github.com/yourusername/gmkit-java.git
cd gmkit-java

# 编译
mvn clean compile

# 测试
mvn test

# 打包
mvn package
```

## 📄 许可证

本项目采用 [Apache License 2.0](LICENSE) 开源协议。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📧 联系方式

- 官网: https://gmkit.cn
- 邮箱: support@gmkit.cn

---

**GMKit** - 让国密算法更简单 🚀
