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

    private SM2Util() {
    }

    /**
     * 生成一组未压缩公钥形式的 SM2 密钥对。
     *
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair() {
        return new SM2().generateKeyPair();
    }

    /**
     * 生成一组 SM2 密钥对。
     *
     * @param compressedPublicKey 是否输出压缩公钥
     * @return SM2 密钥对
     */
    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey) {
        return new SM2().generateKeyPair(compressedPublicKey);
    }

    public static SM2KeyPair generateKeyPair(GmSecurityContext securityContext) {
        return new SM2(securityContext).generateKeyPair();
    }

    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey, GmSecurityContext securityContext) {
        return new SM2(securityContext).generateKeyPair(compressedPublicKey);
    }

    public static String getPublicKeyFromPrivateKey(String privateKeyHex, boolean compressed) {
        return new SM2().getPublicKeyFromPrivateKey(privateKeyHex, compressed);
    }

    public static String compressPublicKey(String publicKeyHex) {
        return new SM2().compressPublicKey(publicKeyHex);
    }

    public static String decompressPublicKey(String publicKeyHex) {
        return new SM2().decompressPublicKey(publicKeyHex);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data) {
        return new SM2().encrypt(publicKeyHex, data);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return new SM2().encrypt(publicKeyHex, data, mode);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return new SM2(securityContext).encrypt(publicKeyHex, data, mode);
    }

    public static byte[] encrypt(String publicKeyHex, String data) {
        return new SM2().encrypt(publicKeyHex, data);
    }

    public static byte[] encrypt(String publicKeyHex, String data, Charset charset, SM2CipherMode mode) {
        return new SM2().encrypt(publicKeyHex, data, charset, mode);
    }

    public static String encryptHex(String publicKeyHex, byte[] data) {
        return new SM2().encryptHex(publicKeyHex, data);
    }

    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return new SM2().encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return new SM2(securityContext).encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, String data, SM2CipherMode mode) {
        return new SM2().encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, String data, Charset charset, SM2CipherMode mode) {
        return new SM2().encryptHex(publicKeyHex, data, charset, mode);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data) {
        return new SM2().encryptBase64(publicKeyHex, data);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return new SM2().encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return new SM2(securityContext).encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, String data, SM2CipherMode mode) {
        return new SM2().encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, String data, Charset charset, SM2CipherMode mode) {
        return new SM2().encryptBase64(publicKeyHex, data, charset, mode);
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext) {
        return new SM2().decrypt(privateKeyHex, ciphertext);
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return new SM2().decrypt(privateKeyHex, ciphertext, mode);
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext) {
        return new SM2().decrypt(privateKeyHex, ciphertext);
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return new SM2().decrypt(privateKeyHex, ciphertext, mode);
    }

    public static String decryptToUtf8(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return new SM2().decryptToUtf8(privateKeyHex, ciphertext, mode);
    }

    public static String decryptToUtf8(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return new SM2().decryptToUtf8(privateKeyHex, ciphertext, mode);
    }

    public static String decryptToString(String privateKeyHex, byte[] ciphertext, Charset charset, SM2CipherMode mode) {
        return new SM2().decryptToString(privateKeyHex, ciphertext, charset, mode);
    }

    public static byte[] sign(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return new SM2().sign(privateKeyHex, message, options);
    }

    public static byte[] sign(String privateKeyHex, String message, SM2SignOptions options) {
        return new SM2().sign(privateKeyHex, message, options);
    }

    public static byte[] sign(String privateKeyHex, String message, Charset charset, SM2SignOptions options) {
        return new SM2().sign(privateKeyHex, message, charset, options);
    }

    public static String signHex(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return new SM2().signHex(privateKeyHex, message, options);
    }

    public static String signHex(String privateKeyHex, String message, SM2SignOptions options) {
        return new SM2().signHex(privateKeyHex, message, options);
    }

    public static String signHex(String privateKeyHex, String message, Charset charset, SM2SignOptions options) {
        return new SM2().signHex(privateKeyHex, message, charset, options);
    }

    public static String signBase64(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return new SM2().signBase64(privateKeyHex, message, options);
    }

    public static String signBase64(String privateKeyHex, String message, SM2SignOptions options) {
        return new SM2().signBase64(privateKeyHex, message, options);
    }

    public static String signBase64(String privateKeyHex, String message, Charset charset, SM2SignOptions options) {
        return new SM2().signBase64(privateKeyHex, message, charset, options);
    }

    public static byte[] signWithoutZ(String privateKeyHex, byte[] message, SM2SignatureFormat signatureFormat) {
        return new SM2().signWithoutZ(privateKeyHex, message, signatureFormat);
    }

    public static byte[] signDigest(String privateKeyHex, byte[] eHash, SM2SignatureFormat signatureFormat) {
        return new SM2().signDigest(privateKeyHex, eHash, signatureFormat);
    }

    public static byte[] signDigest(
        String privateKeyHex,
        byte[] eHash,
        SM2SignatureFormat signatureFormat,
        GmSecurityContext securityContext) {
        return new SM2(securityContext).signDigest(privateKeyHex, eHash, signatureFormat);
    }

    public static boolean verify(String publicKeyHex, byte[] message, byte[] signature, SM2VerifyOptions options) {
        return new SM2().verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, byte[] message, String signature, SM2VerifyOptions options) {
        return new SM2().verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, String message, byte[] signature, SM2VerifyOptions options) {
        return new SM2().verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, String message, Charset charset, byte[] signature, SM2VerifyOptions options) {
        return new SM2().verify(publicKeyHex, message, charset, signature, options);
    }

    public static boolean verify(String publicKeyHex, String message, String signature, SM2VerifyOptions options) {
        return new SM2().verify(publicKeyHex, message, signature, options);
    }

    public static boolean verifyWithoutZ(
        String publicKeyHex,
        byte[] message,
        byte[] signature,
        SM2SignatureInputFormat signatureFormat) {
        return new SM2().verifyWithoutZ(publicKeyHex, message, signature, signatureFormat);
    }

    public static boolean verifyDigest(String publicKeyHex, byte[] eHash, byte[] derSignature) {
        return new SM2().verifyDigest(publicKeyHex, eHash, derSignature);
    }

    public static byte[] computeZ(String userId, String publicKeyHex) {
        return new SM2().computeZ(userId, publicKeyHex);
    }

    public static byte[] computeE(String publicKeyHex, byte[] message, String userId, boolean skipZComputation) {
        return new SM2().computeE(publicKeyHex, message, userId, skipZComputation);
    }

    public static byte[] computeE(String publicKeyHex, String message, Charset charset, String userId, boolean skipZComputation) {
        return new SM2().computeE(publicKeyHex, message, charset, userId, skipZComputation);
    }

    public static byte[] computeEWithoutZ(byte[] message) {
        return new SM2().computeEWithoutZ(message);
    }

    public static byte[] computeEWithoutZ(String message, Charset charset) {
        return new SM2().computeEWithoutZ(message, charset);
    }

    public static byte[] keyExchange(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        SM2KeyExchangeOptions options) {
        return new SM2().keyExchange(
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
        return new SM2().keyExchangeWithConfirmation(
            selfStaticPrivateKeyHex,
            selfEphemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    public static boolean confirmResponder(byte[] expectedS2, byte[] confirmationTag) {
        return new SM2().confirmResponder(expectedS2, confirmationTag);
    }
}
