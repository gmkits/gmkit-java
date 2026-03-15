package cn.gmkit.sm3;

/**
 * @author mumu
 * @description SM3工具类（已废弃），提供SM3摘要和HMAC计算功能
 * @since 1.0.0
 * @deprecated 已废弃，请使用 {@link Sm3Util} 替代
 */
@Deprecated
public final class Sm3s {

    private Sm3s() {
    }

    /**
     * 计算SM3摘要
     *
     * @param data 待计算的数据
     * @return 摘要字节数组
     * @deprecated 使用 {@link Sm3Util#digest(byte[])} 替代
     */
    public static byte[] digest(byte[] data) {
        return Sm3Util.digest(data);
    }

    /**
     * 计算SM3摘要
     *
     * @param data 待计算的字符串
     * @return 摘要字节数组
     * @deprecated 使用 {@link Sm3Util#digest(String)} 替代
     */
    public static byte[] digest(String data) {
        return Sm3Util.digest(data);
    }

    /**
     * 计算SM3摘要并返回十六进制字符串
     *
     * @param data 待计算的数据
     * @return 摘要的十六进制字符串
     * @deprecated 使用 {@link Sm3Util#digestHex(byte[])} 替代
     */
    public static String digestHex(byte[] data) {
        return Sm3Util.digestHex(data);
    }

    /**
     * 计算SM3摘要并返回十六进制字符串
     *
     * @param data 待计算的字符串
     * @return 摘要的十六进制字符串
     * @deprecated 使用 {@link Sm3Util#digestHex(String)} 替代
     */
    public static String digestHex(String data) {
        return Sm3Util.digestHex(data);
    }

    /**
     * 计算SM3摘要并返回Base64字符串
     *
     * @param data 待计算的数据
     * @return 摘要的Base64字符串
     * @deprecated 使用 {@link Sm3Util#digestBase64(byte[])} 替代
     */
    public static String digestBase64(byte[] data) {
        return Sm3Util.digestBase64(data);
    }

    /**
     * 计算SM3-HMAC
     *
     * @param key  密钥
     * @param data 待计算的数据
     * @return HMAC字节数组
     * @deprecated 使用 {@link Sm3Util#hmac(byte[], byte[])} 替代
     */
    public static byte[] hmac(byte[] key, byte[] data) {
        return Sm3Util.hmac(key, data);
    }

    /**
     * 计算SM3-HMAC
     *
     * @param key  密钥
     * @param data 待计算的字符串
     * @return HMAC字节数组
     * @deprecated 使用 {@link Sm3Util#hmac(byte[], String)} 替代
     */
    public static byte[] hmac(byte[] key, String data) {
        return Sm3Util.hmac(key, data);
    }

    /**
     * 计算SM3-HMAC并返回十六进制字符串
     *
     * @param key  密钥
     * @param data 待计算的数据
     * @return HMAC的十六进制字符串
     * @deprecated 使用 {@link Sm3Util#hmacHex(byte[], byte[])} 替代
     */
    public static String hmacHex(byte[] key, byte[] data) {
        return Sm3Util.hmacHex(key, data);
    }

    /**
     * 计算SM3-HMAC并返回十六进制字符串
     *
     * @param key  密钥
     * @param data 待计算的字符串
     * @return HMAC的十六进制字符串
     * @deprecated 使用 {@link Sm3Util#hmacHex(byte[], String)} 替代
     */
    public static String hmacHex(byte[] key, String data) {
        return Sm3Util.hmacHex(key, data);
    }

    /**
     * 计算SM3-HMAC并返回Base64字符串
     *
     * @param key  密钥
     * @param data 待计算的数据
     * @return HMAC的Base64字符串
     * @deprecated 使用 {@link Sm3Util#hmacBase64(byte[], byte[])} 替代
     */
    public static String hmacBase64(byte[] key, byte[] data) {
        return Sm3Util.hmacBase64(key, data);
    }
}

