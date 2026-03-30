package cn.gmkit.sm2;

import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.core.SM2SignatureFormat;
import cn.gmkit.core.SM2SignatureInputFormat;

import java.nio.charset.Charset;

/**
 * SM2 静态工具入口。
 * <p>
 * 这个类提供与 {@link SM2} 对象式入口等价的静态方法，适合以下场景：
 * 老项目中已经大量使用工具类调用方式，或调用链本身不需要显式持有实例。
 * <p>
 * 除了调用风格不同外，静态接口与对象式接口的行为、默认值和异常语义保持一致。
 * 当需要显式绑定 {@link GmSecurityContext} 时，可使用带上下文参数的静态重载。
 */
public final class SM2Util {

    public static final String DEFAULT_USER_ID = SM2.DEFAULT_USER_ID;
    public static final String LEGACY_USER_ID = SM2.LEGACY_USER_ID;
    public static final String GM_2023_USER_ID = SM2.GM_2023_USER_ID;
    public static final String CURVE_NAME = SM2.CURVE_NAME;
    public static final int SM3_DIGEST_LENGTH = SM2.SM3_DIGEST_LENGTH;
    private static final SM2 DEFAULT = new SM2();

    private SM2Util() {
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 密钥生成入口。
     *
     * @return SM2 密钥对
     */
    public static SM2KeyPair sm2GenerateKeyPair() {
        return generateKeyPair();
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 密钥生成入口。
     *
     * @param compressedPublicKey 是否输出压缩公钥
     * @return SM2 密钥对
     */
    public static SM2KeyPair sm2GenerateKeyPair(boolean compressedPublicKey) {
        return generateKeyPair(compressedPublicKey);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 加密入口。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @return 原始密文
     */
    public static byte[] sm2Encrypt(String publicKeyHex, byte[] data) {
        return encrypt(publicKeyHex, data);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 加密入口。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param data         明文字节数组
     * @param mode         密文布局
     * @return 原始密文
     */
    public static byte[] sm2Encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return encrypt(publicKeyHex, data, mode);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 解密入口。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param ciphertext    密文
     * @return 明文字节数组
     */
    public static byte[] sm2Decrypt(String privateKeyHex, byte[] ciphertext) {
        return decrypt(privateKeyHex, ciphertext);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 解密入口。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param ciphertext    密文
     * @param mode          密文布局
     * @return 明文字节数组
     */
    public static byte[] sm2Decrypt(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return decrypt(privateKeyHex, ciphertext, mode);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 签名入口。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param message       原文消息
     * @return 签名字节数组
     */
    public static byte[] sm2Sign(String privateKeyHex, byte[] message) {
        return DEFAULT.sign(privateKeyHex, message);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 签名入口。
     *
     * @param privateKeyHex 私钥十六进制字符串
     * @param message       原文消息
     * @param options       签名参数
     * @return 签名字节数组
     */
    public static byte[] sm2Sign(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return sign(privateKeyHex, message, options);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 验签入口。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param message      原文消息
     * @param signature    签名字节数组
     * @return 验签结果
     */
    public static boolean sm2Verify(String publicKeyHex, byte[] message, byte[] signature) {
        return DEFAULT.verify(publicKeyHex, message, signature);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 SM2 验签入口。
     *
     * @param publicKeyHex 公钥十六进制字符串
     * @param message      原文消息
     * @param signature    签名字节数组
     * @param options      验签参数
     * @return 验签结果
     */
    public static boolean sm2Verify(String publicKeyHex, byte[] message, byte[] signature, SM2VerifyOptions options) {
        return verify(publicKeyHex, message, signature, options);
    }

    /**
     * 生成一组未压缩公钥形式的 SM2 密钥对。
     *
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair() {
        return DEFAULT.generateKeyPair();
    }

    /**
     * 生成一组 SM2 密钥对。
     *
     * @param compressedPublicKey 是否输出压缩公钥
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey) {
        return DEFAULT.generateKeyPair(compressedPublicKey);
    }

    public static SM2KeyPair generateKeyPair(GmSecurityContext securityContext) {
        return new SM2(securityContext).generateKeyPair();
    }

    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey, GmSecurityContext securityContext) {
        return new SM2(securityContext).generateKeyPair(compressedPublicKey);
    }

    public static String getPublicKeyFromPrivateKey(String privateKeyHex, boolean compressed) {
        return DEFAULT.getPublicKeyFromPrivateKey(privateKeyHex, compressed);
    }

    public static String compressPublicKey(String publicKeyHex) {
        return DEFAULT.compressPublicKey(publicKeyHex);
    }

    public static String decompressPublicKey(String publicKeyHex) {
        return DEFAULT.decompressPublicKey(publicKeyHex);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data) {
        return DEFAULT.encrypt(publicKeyHex, data);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return DEFAULT.encrypt(publicKeyHex, data, mode);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return new SM2(securityContext).encrypt(publicKeyHex, data, mode);
    }

    public static byte[] encrypt(String publicKeyHex, String data) {
        return DEFAULT.encrypt(publicKeyHex, data);
    }

    public static byte[] encrypt(String publicKeyHex, String data, Charset charset, SM2CipherMode mode) {
        return DEFAULT.encrypt(publicKeyHex, data, charset, mode);
    }

    public static String encryptHex(String publicKeyHex, byte[] data) {
        return DEFAULT.encryptHex(publicKeyHex, data);
    }

    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return DEFAULT.encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return new SM2(securityContext).encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, String data, SM2CipherMode mode) {
        return DEFAULT.encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, String data, Charset charset, SM2CipherMode mode) {
        return DEFAULT.encryptHex(publicKeyHex, data, charset, mode);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data) {
        return DEFAULT.encryptBase64(publicKeyHex, data);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return DEFAULT.encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return new SM2(securityContext).encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, String data, SM2CipherMode mode) {
        return DEFAULT.encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, String data, Charset charset, SM2CipherMode mode) {
        return DEFAULT.encryptBase64(publicKeyHex, data, charset, mode);
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext) {
        return DEFAULT.decrypt(privateKeyHex, ciphertext);
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return DEFAULT.decrypt(privateKeyHex, ciphertext, mode);
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext) {
        return DEFAULT.decrypt(privateKeyHex, ciphertext);
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return DEFAULT.decrypt(privateKeyHex, ciphertext, mode);
    }

    public static String decryptToUtf8(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return DEFAULT.decryptToUtf8(privateKeyHex, ciphertext, mode);
    }

    public static String decryptToUtf8(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return DEFAULT.decryptToUtf8(privateKeyHex, ciphertext, mode);
    }

    public static String decryptToString(String privateKeyHex, byte[] ciphertext, Charset charset, SM2CipherMode mode) {
        return DEFAULT.decryptToString(privateKeyHex, ciphertext, charset, mode);
    }

    public static byte[] sign(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return DEFAULT.sign(privateKeyHex, message, options);
    }

    public static byte[] sign(String privateKeyHex, String message, SM2SignOptions options) {
        return DEFAULT.sign(privateKeyHex, message, options);
    }

    public static byte[] sign(String privateKeyHex, String message, Charset charset, SM2SignOptions options) {
        return DEFAULT.sign(privateKeyHex, message, charset, options);
    }

    public static String signHex(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return DEFAULT.signHex(privateKeyHex, message, options);
    }

    public static String signHex(String privateKeyHex, String message, SM2SignOptions options) {
        return DEFAULT.signHex(privateKeyHex, message, options);
    }

    public static String signHex(String privateKeyHex, String message, Charset charset, SM2SignOptions options) {
        return DEFAULT.signHex(privateKeyHex, message, charset, options);
    }

    public static String signBase64(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return DEFAULT.signBase64(privateKeyHex, message, options);
    }

    public static String signBase64(String privateKeyHex, String message, SM2SignOptions options) {
        return DEFAULT.signBase64(privateKeyHex, message, options);
    }

    public static String signBase64(String privateKeyHex, String message, Charset charset, SM2SignOptions options) {
        return DEFAULT.signBase64(privateKeyHex, message, charset, options);
    }

    public static byte[] signWithoutZ(String privateKeyHex, byte[] message, SM2SignatureFormat signatureFormat) {
        return DEFAULT.signWithoutZ(privateKeyHex, message, signatureFormat);
    }

    public static byte[] signDigest(String privateKeyHex, byte[] eHash, SM2SignatureFormat signatureFormat) {
        return DEFAULT.signDigest(privateKeyHex, eHash, signatureFormat);
    }

    public static byte[] signDigest(
        String privateKeyHex,
        byte[] eHash,
        SM2SignatureFormat signatureFormat,
        GmSecurityContext securityContext) {
        return new SM2(securityContext).signDigest(privateKeyHex, eHash, signatureFormat);
    }

    public static boolean verify(String publicKeyHex, byte[] message, byte[] signature, SM2VerifyOptions options) {
        return DEFAULT.verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, byte[] message, String signature, SM2VerifyOptions options) {
        return DEFAULT.verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, String message, byte[] signature, SM2VerifyOptions options) {
        return DEFAULT.verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, String message, Charset charset, byte[] signature, SM2VerifyOptions options) {
        return DEFAULT.verify(publicKeyHex, message, charset, signature, options);
    }

    public static boolean verify(String publicKeyHex, String message, String signature, SM2VerifyOptions options) {
        return DEFAULT.verify(publicKeyHex, message, signature, options);
    }

    public static boolean verifyWithoutZ(
        String publicKeyHex,
        byte[] message,
        byte[] signature,
        SM2SignatureInputFormat signatureFormat) {
        return DEFAULT.verifyWithoutZ(publicKeyHex, message, signature, signatureFormat);
    }

    public static boolean verifyDigest(String publicKeyHex, byte[] eHash, byte[] derSignature) {
        return DEFAULT.verifyDigest(publicKeyHex, eHash, derSignature);
    }

    public static byte[] computeZ(String userId, String publicKeyHex) {
        return DEFAULT.computeZ(userId, publicKeyHex);
    }

    public static byte[] computeE(String publicKeyHex, byte[] message, String userId, boolean skipZComputation) {
        return DEFAULT.computeE(publicKeyHex, message, userId, skipZComputation);
    }

    public static byte[] computeE(String publicKeyHex, String message, Charset charset, String userId, boolean skipZComputation) {
        return DEFAULT.computeE(publicKeyHex, message, charset, userId, skipZComputation);
    }

    public static byte[] computeEWithoutZ(byte[] message) {
        return DEFAULT.computeEWithoutZ(message);
    }

    public static byte[] computeEWithoutZ(String message, Charset charset) {
        return DEFAULT.computeEWithoutZ(message, charset);
    }

    public static byte[] keyExchange(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        SM2KeyExchangeOptions options) {
        return DEFAULT.keyExchange(
            selfStaticPrivateKeyHex,
            selfEphemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    public static SM2KeyExchangeResult keyExchangeWithConfirmation(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        SM2KeyExchangeOptions options) {
        return DEFAULT.keyExchangeWithConfirmation(
            selfStaticPrivateKeyHex,
            selfEphemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    public static boolean confirmResponder(byte[] expectedS2, byte[] confirmationTag) {
        return DEFAULT.confirmResponder(expectedS2, confirmationTag);
    }
}
