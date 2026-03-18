package cn.gmkit.sm2;

import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.core.SM2SignatureFormat;
import cn.gmkit.core.SM2SignatureInputFormat;

/**
 * SM2 兼容工具入口。
 *
 * @deprecated 请改用 {@link SM2}
 */
@Deprecated
public final class SM2Util {

    public static final String DEFAULT_USER_ID = SM2.DEFAULT_USER_ID;
    public static final String LEGACY_USER_ID = SM2.LEGACY_USER_ID;
    public static final String GM_2023_USER_ID = SM2.GM_2023_USER_ID;
    public static final String CURVE_NAME = SM2.CURVE_NAME;
    public static final int SM3_DIGEST_LENGTH = SM2.SM3_DIGEST_LENGTH;

    private SM2Util() {
    }

    public static SM2KeyPair generateKeyPair() {
        return SM2.generateKeyPair();
    }

    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey) {
        return SM2.generateKeyPair(compressedPublicKey);
    }

    public static SM2KeyPair generateKeyPair(GmSecurityContext securityContext) {
        return SM2.generateKeyPair(securityContext);
    }

    public static SM2KeyPair generateKeyPair(boolean compressedPublicKey, GmSecurityContext securityContext) {
        return SM2.generateKeyPair(compressedPublicKey, securityContext);
    }

    public static String getPublicKeyFromPrivateKey(String privateKeyHex, boolean compressed) {
        return SM2.getPublicKeyFromPrivateKey(privateKeyHex, compressed);
    }

    public static String compressPublicKey(String publicKeyHex) {
        return SM2.compressPublicKey(publicKeyHex);
    }

    public static String decompressPublicKey(String publicKeyHex) {
        return SM2.decompressPublicKey(publicKeyHex);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data) {
        return SM2.encrypt(publicKeyHex, data);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return SM2.encrypt(publicKeyHex, data, mode);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return SM2.encrypt(publicKeyHex, data, mode, securityContext);
    }

    public static String encryptHex(String publicKeyHex, byte[] data) {
        return SM2.encryptHex(publicKeyHex, data);
    }

    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return SM2.encryptHex(publicKeyHex, data, mode);
    }

    public static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return SM2.encryptHex(publicKeyHex, data, mode, securityContext);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data) {
        return SM2.encryptBase64(publicKeyHex, data);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode) {
        return SM2.encryptBase64(publicKeyHex, data, mode);
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return SM2.encryptBase64(publicKeyHex, data, mode, securityContext);
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext) {
        return SM2.decrypt(privateKeyHex, ciphertext);
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        return SM2.decrypt(privateKeyHex, ciphertext, mode);
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext) {
        return SM2.decrypt(privateKeyHex, ciphertext);
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return SM2.decrypt(privateKeyHex, ciphertext, mode);
    }

    public static byte[] sign(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return SM2.sign(privateKeyHex, message, options);
    }

    public static String signHex(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return SM2.signHex(privateKeyHex, message, options);
    }

    public static String signBase64(String privateKeyHex, byte[] message, SM2SignOptions options) {
        return SM2.signBase64(privateKeyHex, message, options);
    }

    public static byte[] signWithoutZ(String privateKeyHex, byte[] message, SM2SignatureFormat signatureFormat) {
        return SM2.signWithoutZ(privateKeyHex, message, signatureFormat);
    }

    public static byte[] signDigest(String privateKeyHex, byte[] eHash, SM2SignatureFormat signatureFormat) {
        return SM2.signDigest(privateKeyHex, eHash, signatureFormat);
    }

    public static byte[] signDigest(
        String privateKeyHex,
        byte[] eHash,
        SM2SignatureFormat signatureFormat,
        GmSecurityContext securityContext) {
        return SM2.signDigest(privateKeyHex, eHash, signatureFormat, securityContext);
    }

    public static boolean verify(String publicKeyHex, byte[] message, byte[] signature, SM2VerifyOptions options) {
        return SM2.verify(publicKeyHex, message, signature, options);
    }

    public static boolean verify(String publicKeyHex, byte[] message, String signature, SM2VerifyOptions options) {
        return SM2.verify(publicKeyHex, message, signature, options);
    }

    public static boolean verifyWithoutZ(
        String publicKeyHex,
        byte[] message,
        byte[] signature,
        SM2SignatureInputFormat signatureFormat) {
        return SM2.verifyWithoutZ(publicKeyHex, message, signature, signatureFormat);
    }

    public static boolean verifyDigest(String publicKeyHex, byte[] eHash, byte[] derSignature) {
        return SM2.verifyDigest(publicKeyHex, eHash, derSignature);
    }

    public static byte[] computeZ(String userId, String publicKeyHex) {
        return SM2.computeZ(userId, publicKeyHex);
    }

    public static byte[] computeE(String publicKeyHex, byte[] message, String userId, boolean skipZComputation) {
        return SM2.computeE(publicKeyHex, message, userId, skipZComputation);
    }

    public static byte[] computeEWithoutZ(byte[] message) {
        return SM2.computeEWithoutZ(message);
    }

    public static byte[] keyExchange(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        SM2KeyExchangeOptions options) {
        return SM2.keyExchange(
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
        return SM2.keyExchangeWithConfirmation(
            selfStaticPrivateKeyHex,
            selfEphemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    public static boolean confirmResponder(byte[] expectedS2, byte[] confirmationTag) {
        return SM2.confirmResponder(expectedS2, confirmationTag);
    }
}

