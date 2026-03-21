package cn.gmkit.sm4;

import cn.gmkit.core.GmSecurityContext;

import java.nio.charset.Charset;

/**
 * SM4 静态工具入口。
 * <p>
 * 适合将 SM4 当作纯工具能力使用的场景，例如一次性加解密、历史代码兼容或不希望显式维护实例时。
 * <p>
 * 本类与 {@link SM4} 对象式入口共享同一套实现，默认配置、参数校验和异常语义保持一致。
 */
public final class SM4Util {

    private SM4Util() {
    }

    public static byte[] generateKey() {
        return new SM4().generateKey();
    }

    public static byte[] generateKey(GmSecurityContext securityContext) {
        return new SM4(securityContext).generateKey();
    }

    public static String generateKeyHex() {
        return new SM4().generateKeyHex();
    }

    public static String generateKeyHex(GmSecurityContext securityContext) {
        return new SM4(securityContext).generateKeyHex();
    }

    public static SM4CipherResult encryptHex(String keyHex, String data, SM4Options options) {
        return new SM4().encryptHex(keyHex, data, options);
    }

    public static SM4CipherResult encryptHex(String keyHex, byte[] data, SM4Options options) {
        return new SM4().encryptHex(keyHex, data, options);
    }

    public static SM4CipherResult encrypt(byte[] key, byte[] data, SM4Options options) {
        return new SM4().encrypt(key, data, options);
    }

    public static SM4CipherResult encrypt(byte[] key, String data, SM4Options options) {
        return new SM4().encrypt(key, data, options);
    }

    public static SM4CipherResult encrypt(byte[] key, String data, Charset charset, SM4Options options) {
        return new SM4().encrypt(key, data, charset, options);
    }

    public static byte[] decryptHex(String keyHex, String ciphertextHex, SM4Options options) {
        return new SM4().decryptHex(keyHex, ciphertextHex, options);
    }

    public static String decryptToUtf8(byte[] key, byte[] ciphertext, SM4Options options) {
        return new SM4().decryptToUtf8(key, ciphertext, options);
    }

    public static String decryptToUtf8(byte[] key, SM4CipherResult result, SM4Options options) {
        return new SM4().decryptToUtf8(key, result, options);
    }

    public static String decryptToString(byte[] key, byte[] ciphertext, Charset charset, SM4Options options) {
        return new SM4().decryptToString(key, ciphertext, charset, options);
    }

    public static String decryptToString(byte[] key, SM4CipherResult result, Charset charset, SM4Options options) {
        return new SM4().decryptToString(key, result, charset, options);
    }

    public static byte[] decrypt(byte[] key, SM4CipherResult result, SM4Options options) {
        return new SM4().decrypt(key, result, options);
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext, SM4Options options) {
        return new SM4().decrypt(key, ciphertext, options);
    }
}
