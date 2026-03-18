package cn.gmkit.sm4;

import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;

/**
 * SM4 静态工具入口。
 */
public final class SM4 {

    private SM4() {
    }

    /**
     * 生成 SM4 密钥。
     *
     * @return 16 字节密钥
     */
    public static byte[] generateKey() {
        return SM4CipherProcessor.generateKey(null);
    }

    /**
     * 使用指定安全上下文生成 SM4 密钥。
     *
     * @param securityContext Provider 和随机源配置
     * @return 16 字节密钥
     */
    public static byte[] generateKey(GmSecurityContext securityContext) {
        return SM4CipherProcessor.generateKey(securityContext);
    }

    /**
     * 生成十六进制形式的 SM4 密钥。
     *
     * @return 十六进制密钥
     */
    public static String generateKeyHex() {
        return HexCodec.encode(generateKey());
    }

    /**
     * 使用指定安全上下文生成十六进制形式的 SM4 密钥。
     *
     * @param securityContext Provider 和随机源配置
     * @return 十六进制密钥
     */
    public static String generateKeyHex(GmSecurityContext securityContext) {
        return HexCodec.encode(generateKey(securityContext));
    }

    /**
     * 使用十六进制密钥加密 UTF-8 文本。
     *
     * @param keyHex  十六进制密钥
     * @param data    UTF-8 文本
     * @param options 加密配置
     * @return 密文结果
     */
    public static SM4CipherResult encryptHex(String keyHex, String data, SM4Options options) {
        return encrypt(HexCodec.decodeStrict(keyHex, "SM4 key"), Texts.utf8(data), options);
    }

    /**
     * 使用十六进制密钥加密字节数组。
     *
     * @param keyHex  十六进制密钥
     * @param data    明文字节数组
     * @param options 加密配置
     * @return 密文结果
     */
    public static SM4CipherResult encryptHex(String keyHex, byte[] data, SM4Options options) {
        return encrypt(HexCodec.decodeStrict(keyHex, "SM4 key"), data, options);
    }

    /**
     * 使用默认配置加密。
     *
     * @param key  16 字节密钥
     * @param data 明文字节数组
     * @return 密文结果
     */
    public static SM4CipherResult encrypt(byte[] key, byte[] data) {
        return encrypt(key, data, null);
    }

    /**
     * 使用指定配置加密。
     *
     * @param key     16 字节密钥
     * @param data    明文字节数组
     * @param options 加密配置，传入 {@code null} 时使用默认值
     * @return 密文结果
     */
    public static SM4CipherResult encrypt(byte[] key, byte[] data, SM4Options options) {
        return SM4CipherProcessor.encrypt(key, data, options);
    }

    /**
     * 使用十六进制密钥解密十六进制密文。
     *
     * @param keyHex        十六进制密钥
     * @param ciphertextHex 十六进制密文
     * @param options       解密配置
     * @return 明文字节数组
     */
    public static byte[] decryptHex(String keyHex, String ciphertextHex, SM4Options options) {
        return decrypt(
            HexCodec.decodeStrict(keyHex, "SM4 key"),
            HexCodec.decodeStrict(ciphertextHex, "ciphertext"),
            options);
    }

    /**
     * 解密并按 UTF-8 解码返回字符串。
     *
     * @param key        16 字节密钥
     * @param ciphertext 密文字节数组
     * @param options    解密配置
     * @return UTF-8 字符串
     */
    public static String decryptToUtf8(byte[] key, byte[] ciphertext, SM4Options options) {
        return Texts.utf8(decrypt(key, ciphertext, options));
    }

    /**
     * 解密 {@link SM4CipherResult} 并按 UTF-8 解码返回字符串。
     *
     * @param key     16 字节密钥
     * @param result  密文结果，若包含 AEAD tag 会自动并入配置
     * @param options 解密配置
     * @return UTF-8 字符串
     */
    public static String decryptToUtf8(byte[] key, SM4CipherResult result, SM4Options options) {
        return Texts.utf8(decrypt(key, result, options));
    }

    /**
     * 解密 {@link SM4CipherResult}。
     *
     * @param key     16 字节密钥
     * @param result  密文结果，若包含 AEAD tag 会自动并入配置
     * @param options 解密配置
     * @return 明文字节数组
     */
    public static byte[] decrypt(byte[] key, SM4CipherResult result, SM4Options options) {
        return decrypt(key, result.ciphertext(), SM4AeadSupport.withResultTag(options, result.tag()));
    }

    /**
     * 使用默认配置解密。
     *
     * @param key        16 字节密钥
     * @param ciphertext 密文字节数组
     * @return 明文字节数组
     */
    public static byte[] decrypt(byte[] key, byte[] ciphertext) {
        return decrypt(key, ciphertext, null);
    }

    /**
     * 使用指定配置解密。
     *
     * @param key        16 字节密钥
     * @param ciphertext 密文字节数组
     * @param options    解密配置，传入 {@code null} 时使用默认值
     * @return 明文字节数组
     */
    public static byte[] decrypt(byte[] key, byte[] ciphertext, SM4Options options) {
        return SM4CipherProcessor.decrypt(key, ciphertext, options);
    }
}

