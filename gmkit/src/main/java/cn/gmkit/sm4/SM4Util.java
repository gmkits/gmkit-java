package cn.gmkit.sm4;

import cn.gmkit.core.GmSecurityContext;

/**
 * SM4 兼容工具入口。
 *
 * @deprecated 请改用 {@link SM4}
 */
@Deprecated
public final class SM4Util {

    private SM4Util() {
    }

    public static byte[] generateKey() {
        return SM4.generateKey();
    }

    public static byte[] generateKey(GmSecurityContext securityContext) {
        return SM4.generateKey(securityContext);
    }

    public static String generateKeyHex() {
        return SM4.generateKeyHex();
    }

    public static String generateKeyHex(GmSecurityContext securityContext) {
        return SM4.generateKeyHex(securityContext);
    }

    public static SM4CipherResult encryptHex(String keyHex, String data, SM4Options options) {
        return SM4.encryptHex(keyHex, data, options);
    }

    public static SM4CipherResult encryptHex(String keyHex, byte[] data, SM4Options options) {
        return SM4.encryptHex(keyHex, data, options);
    }

    public static SM4CipherResult encrypt(byte[] key, byte[] data, SM4Options options) {
        return SM4.encrypt(key, data, options);
    }

    public static byte[] decryptHex(String keyHex, String ciphertextHex, SM4Options options) {
        return SM4.decryptHex(keyHex, ciphertextHex, options);
    }

    public static String decryptToUtf8(byte[] key, byte[] ciphertext, SM4Options options) {
        return SM4.decryptToUtf8(key, ciphertext, options);
    }

    public static String decryptToUtf8(byte[] key, SM4CipherResult result, SM4Options options) {
        return SM4.decryptToUtf8(key, result, options);
    }

    public static byte[] decrypt(byte[] key, SM4CipherResult result, SM4Options options) {
        return SM4.decrypt(key, result, options);
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext, SM4Options options) {
        return SM4.decrypt(key, ciphertext, options);
    }
}

