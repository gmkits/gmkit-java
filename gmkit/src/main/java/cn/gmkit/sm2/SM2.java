package cn.gmkit.sm2;

import cn.gmkit.core.*;

/**
 * SM2 静态工具入口。
 * <p>
 * 对外保留直接可用的静态 API，内部实现拆分到密钥、加解密、签名和密钥交换等包内协作类。
 */
public final class SM2 {

    /**
     * 默认用户标识，兼容历史实现。
     */
    public static final String DEFAULT_USER_ID = "1234567812345678";

    /**
     * 历史版本默认用户标识别名。
     */
    public static final String LEGACY_USER_ID = DEFAULT_USER_ID;

    /**
     * 2023 版规范下可选的空用户标识。
     */
    public static final String GM_2023_USER_ID = "";

    /**
     * SM2 标准曲线名称。
     */
    public static final String CURVE_NAME = "sm2p256v1";

    /**
     * SM3 摘要长度，单位为字节。
     */
    public static final int SM3_DIGEST_LENGTH = 32;

    private SM2() {
    }

    /**
     * 生成一组 SM2 密钥，默认输出未压缩公钥。
     *
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair() {
        return generateKeyPair(false, GmSecurityContexts.defaults());
    }

    /**
     * 生成一组 SM2 密钥。
     *
     * @param compressedPublicKey 是否输出压缩公钥
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey) {
        return generateKeyPair(compressedPublicKey, GmSecurityContexts.defaults());
    }

    /**
     * 使用指定安全上下文生成 SM2 密钥。
     *
     * @param securityContext Provider 和随机源配置
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair(GmSecurityContext securityContext) {
        return generateKeyPair(false, securityContext);
    }

    /**
     * 使用指定安全上下文生成 SM2 密钥。
     *
     * @param compressedPublicKey 是否输出压缩公钥
     * @param securityContext     Provider 和随机源配置
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey, GmSecurityContext securityContext) {
        return SM2KeyOps.generateKeyPair(compressedPublicKey, securityContext);
    }

    /**
     * 根据私钥推导公钥。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param compressed    是否输出压缩公钥
     * @return 公钥十六进制字符串
     */
    public static String getPublicKeyFromPrivateKey(String privateKeyHex, boolean compressed) {
        return SM2KeyOps.getPublicKeyFromPrivateKey(privateKeyHex, compressed);
    }

    /**
     * 将未压缩公钥压缩编码。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @return 压缩公钥
     */
    public static String compressPublicKey(String publicKeyHex) {
        return SM2KeyOps.compressPublicKey(publicKeyHex);
    }

    /**
     * 将压缩公钥恢复为未压缩编码。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @return 未压缩公钥
     */
    public static String decompressPublicKey(String publicKeyHex) {
        return SM2KeyOps.decompressPublicKey(publicKeyHex);
    }

    /**
     * 使用默认密文布局 {@code C1C3C2} 加密。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @return 原始密文
     */
    public static byte[] encrypt(String publicKeyHex, byte[] data) {
        return encrypt(publicKeyHex, data, SM2CipherMode.C1C3C2);
    }

    /**
     * 使用指定密文布局加密。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @param mode         密文布局，传入 {@code null} 时默认 {@code C1C3C2}
     * @return 原始密文
     */
    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return encrypt(publicKeyHex, data, mode, GmSecurityContexts.defaults());
    }

    /**
     * 使用指定密文布局和安全上下文加密。
     *
     * @param publicKeyHex    公钥十六进制字符串
     * @param data            明文字节数组
     * @param mode            密文布局，传入 {@code null} 时默认 {@code C1C3C2}
     * @param securityContext Provider 和随机源配置
     * @return 原始密文
     */
    public static byte[] encrypt(
        String publicKeyHex,
        byte[] data,
        SM2CipherMode mode,
        GmSecurityContext securityContext) {
        return SM2Cryptor.encrypt(publicKeyHex, data, mode, securityContext);
    }

    /**
     * 加密并输出十六进制密文。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @return 十六进制密文
     */
    public static String encryptHex(String publicKeyHex, byte[] data) {
        return encryptHex(publicKeyHex, data, SM2CipherMode.C1C3C2);
    }

    /**
     * 加密并输出十六进制密文。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @param mode         密文布局
     * @return 十六进制密文
     */
    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return encryptHex(publicKeyHex, data, mode, GmSecurityContexts.defaults());
    }

    /**
     * 加密并输出十六进制密文。
     *
     * @param publicKeyHex    公钥十六进制字符串
     * @param data            明文字节数组
     * @param mode            密文布局
     * @param securityContext Provider 和随机源配置
     * @return 十六进制密文
     */
    public static String encryptHex(
        String publicKeyHex,
        byte[] data,
        SM2CipherMode mode,
        GmSecurityContext securityContext) {
        return SM2Cryptor.encryptHex(publicKeyHex, data, mode, securityContext);
    }

    /**
     * 加密并输出 Base64 密文。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @return Base64 密文
     */
    public static String encryptBase64(String publicKeyHex, byte[] data) {
        return encryptBase64(publicKeyHex, data, SM2CipherMode.C1C3C2);
    }

    /**
     * 加密并输出 Base64 密文。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @param mode         密文布局
     * @return Base64 密文
     */
    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return encryptBase64(publicKeyHex, data, mode, GmSecurityContexts.defaults());
    }

    /**
     * 加密并输出 Base64 密文。
     *
     * @param publicKeyHex    公钥十六进制字符串
     * @param data            明文字节数组
     * @param mode            密文布局
     * @param securityContext Provider 和随机源配置
     * @return Base64 密文
     */
    public static String encryptBase64(
        String publicKeyHex,
        byte[] data,
        SM2CipherMode mode,
        GmSecurityContext securityContext) {
        return SM2Cryptor.encryptBase64(publicKeyHex, data, mode, securityContext);
    }

    /**
     * 使用默认密文布局 {@code C1C3C2} 解密。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param ciphertext    原始密文字节数组，支持自动识别 ASN.1 DER
     * @return 明文字节数组
     */
    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext) {
        return decrypt(privateKeyHex, ciphertext, SM2CipherMode.C1C3C2);
    }

    /**
     * 使用指定密文布局解密。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param ciphertext    原始密文字节数组，支持自动识别 ASN.1 DER
     * @param mode          密文布局
     * @return 明文字节数组
     */
    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return SM2Cryptor.decrypt(privateKeyHex, ciphertext, mode);
    }

    /**
     * 解密十六进制或 Base64 形式的密文字符串。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param ciphertext    十六进制或 Base64 密文
     * @return 明文字节数组
     */
    public static byte[] decrypt(String privateKeyHex, String ciphertext) {
        return decrypt(privateKeyHex, ciphertext, SM2CipherMode.C1C3C2);
    }

    /**
     * 解密十六进制或 Base64 形式的密文字符串。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param ciphertext    十六进制或 Base64 密文
     * @param mode          密文布局
     * @return 明文字节数组
     */
    public static byte[] decrypt(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return SM2Cryptor.decrypt(privateKeyHex, ciphertext, mode);
    }

    /**
     * 使用默认签名参数签名，默认输出 RAW {@code r||s}。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param message       原文消息
     * @return 签名字节数组
     */
    public static byte[] sign(String privateKeyHex, byte[] message) {
        return sign(privateKeyHex, message, SM2SignOptions.builder().build());
    }

    /**
     * 使用指定签名参数签名。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param message       原文消息
     * @param options       签名参数，传入 {@code null} 时使用默认值
     * @return 签名字节数组
     */
    public static byte[] sign(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return SM2SignerSupport.sign(privateKeyHex, message, options);
    }

    /**
     * 签名并输出十六进制结果。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param message       原文消息
     * @param options       签名参数
     * @return 十六进制签名
     */
    public static String signHex(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return SM2SignerSupport.signHex(privateKeyHex, message, options);
    }

    /**
     * 签名并输出 Base64 结果。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param message       原文消息
     * @param options       签名参数
     * @return Base64 签名
     */
    public static String signBase64(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return SM2SignerSupport.signBase64(privateKeyHex, message, options);
    }

    /**
     * 直接对消息做 SM3 后签名，不计算 Z 值。
     *
     * @param privateKeyHex   私钥十六进制字符串
     * @param message         原文消息
     * @param signatureFormat 输出签名格式
     * @return 签名字节数组
     */
    public static byte[] signWithoutZ(String privateKeyHex, byte[] message, SM2SignatureFormat signatureFormat) {
        return sign(
            privateKeyHex,
            message,
            SM2SignOptions.builder()
                .signatureFormat(signatureFormat)
                .skipZComputation(true)
                .build());
    }

    /**
     * 对外部已计算好的 e 值直接签名。
     *
     * @param privateKeyHex   私钥十六进制字符串
     * @param eHash           已计算好的 e 值
     * @param signatureFormat 输出签名格式
     * @return 签名字节数组
     */
    public static byte[] signDigest(String privateKeyHex, byte[] eHash, SM2SignatureFormat signatureFormat) {
        return signDigest(privateKeyHex, eHash, signatureFormat, GmSecurityContexts.defaults());
    }

    /**
     * 对外部已计算好的 e 值直接签名。
     *
     * @param privateKeyHex   私钥十六进制字符串
     * @param eHash           已计算好的 e 值
     * @param signatureFormat 输出签名格式
     * @param securityContext Provider 和随机源配置
     * @return 签名字节数组
     */
    public static byte[] signDigest(
        String privateKeyHex,
        byte[] eHash,
        SM2SignatureFormat signatureFormat,
        GmSecurityContext securityContext) {
        return SM2SignerSupport.signDigest(privateKeyHex, eHash, signatureFormat, securityContext);
    }

    /**
     * 使用默认验签参数验签。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param message      原文消息
     * @param signature    签名字节数组，支持 RAW/DER 自动识别
     * @return 验签结果
     */
    public static boolean verify(String publicKeyHex, byte[] message, byte[] signature) {
        return verify(publicKeyHex, message, signature, SM2VerifyOptions.builder().build());
    }

    /**
     * 使用指定验签参数验签。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param message      原文消息
     * @param signature    签名字节数组，支持 RAW/DER 自动识别
     * @param options      验签参数
     * @return 验签结果
     */
    public static boolean verify(String publicKeyHex, byte[] message, byte[] signature, SM2VerifyOptions options) {
        return SM2SignerSupport.verify(publicKeyHex, message, signature, options);
    }

    /**
     * 验签十六进制或 Base64 形式的签名字符串。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param message      原文消息
     * @param signature    十六进制或 Base64 形式的签名
     * @param options      验签参数
     * @return 验签结果
     */
    public static boolean verify(String publicKeyHex, byte[] message, String signature, SM2VerifyOptions options) {
        return SM2SignerSupport.verify(publicKeyHex, message, signature, options);
    }

    /**
     * 直接以不含 Z 的 e 值语义验签。
     *
     * @param publicKeyHex    公钥十六进制字符串
     * @param message         原文消息
     * @param signature       签名字节数组
     * @param signatureFormat 签名输入格式
     * @return 验签结果
     */
    public static boolean verifyWithoutZ(
        String publicKeyHex,
        byte[] message,
        byte[] signature,
        SM2SignatureInputFormat signatureFormat) {
        return verify(
            publicKeyHex,
            message,
            signature,
            SM2VerifyOptions.builder()
                .signatureFormat(signatureFormat)
                .skipZComputation(true)
                .build());
    }

    /**
     * 对外部提供的 e 值和 DER 签名直接验签。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param eHash        已计算好的 e 值
     * @param derSignature ASN.1 DER 签名
     * @return 验签结果
     */
    public static boolean verifyDigest(String publicKeyHex, byte[] eHash, byte[] derSignature) {
        return SM2SignerSupport.verifyDigest(publicKeyHex, eHash, derSignature);
    }

    /**
     * 计算 SM2 Z 值。
     *
     * @param userId       用户标识，传入 {@code null} 时使用默认值
     * @param publicKeyHex 公钥十六进制字符串
     * @return Z 值
     */
    public static byte[] computeZ(String userId, String publicKeyHex) {
        return SM2SignerSupport.computeZ(userId, publicKeyHex);
    }

    /**
     * 计算 SM2 中用于签名的 e 值。
     *
     * @param publicKeyHex     公钥十六进制字符串
     * @param message          原文消息
     * @param userId           用户标识
     * @param skipZComputation 是否跳过 Z 计算
     * @return e 值
     */
    public static byte[] computeE(String publicKeyHex, byte[] message, String userId, boolean skipZComputation) {
        return SM2SignerSupport.computeE(publicKeyHex, message, userId, skipZComputation);
    }

    /**
     * 直接对消息做 SM3 摘要，作为不含 Z 的 e 值。
     *
     * @param message 原文消息
     * @return e 值
     */
    public static byte[] computeEWithoutZ(byte[] message) {
        return SM2SignerSupport.computeEWithoutZ(message);
    }

    /**
     * 执行 SM2 密钥交换。
     *
     * @param selfStaticPrivateKeyHex    己方静态私钥
     * @param selfEphemeralPrivateKeyHex 己方临时私钥
     * @param peerStaticPublicKeyHex     对方静态公钥
     * @param peerEphemeralPublicKeyHex  对方临时公钥
     * @param options                    交换参数
     * @return 共享密钥
     */
    public static byte[] keyExchange(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        SM2KeyExchangeOptions options) {
        return SM2KeyAgreements.keyExchange(
            selfStaticPrivateKeyHex,
            selfEphemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    /**
     * 执行带确认信息的 SM2 密钥交换。
     *
     * @param selfStaticPrivateKeyHex    己方静态私钥
     * @param selfEphemeralPrivateKeyHex 己方临时私钥
     * @param peerStaticPublicKeyHex     对方静态公钥
     * @param peerEphemeralPublicKeyHex  对方临时公钥
     * @param options                    交换参数
     * @return 共享密钥和确认标签
     */
    public static SM2KeyExchangeResult keyExchangeWithConfirmation(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        SM2KeyExchangeOptions options) {
        return SM2KeyAgreements.keyExchangeWithConfirmation(
            selfStaticPrivateKeyHex,
            selfEphemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    /**
     * 常量时间比较响应方确认标签。
     *
     * @param expectedS2      本地计算出的 S2
     * @param confirmationTag 对端返回的确认标签
     * @return 一致时返回 {@code true}
     */
    public static boolean confirmResponder(byte[] expectedS2, byte[] confirmationTag) {
        return SM2SignerSupport.confirmResponder(expectedS2, confirmationTag);
    }
}

