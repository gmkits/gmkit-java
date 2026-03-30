package cn.gmkit.sm3;

import java.nio.charset.Charset;

/**
 * SM3 静态工具入口。
 * <p>
 * 适合直接按工具类方式计算摘要或 HMAC，例如在工具方法、表达式链或历史代码中快速接入。
 * <p>
 * 本类与 {@link SM3} 的对象式接口在能力上完全一致，仅调用形式不同。
 */
public final class SM3Util {

    public static final int DIGEST_LENGTH = SM3.DIGEST_LENGTH;
    private static final SM3 DEFAULT = new SM3();

    private SM3Util() {
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式摘要入口。
     *
     * @param data 输入数据，不能为 {@code null}
     * @return 32 字节摘要
     */
    public static byte[] sm3Digest(byte[] data) {
        return digest(data);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式摘要入口。
     *
     * @param data 输入字符串
     * @return 32 字节摘要
     */
    public static byte[] sm3Digest(String data) {
        return digest(data);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 HMAC 入口。
     *
     * @param key  HMAC 密钥
     * @param data 输入字节数组
     * @return HMAC 结果
     */
    public static byte[] sm3Hmac(byte[] key, byte[] data) {
        return hmac(key, data);
    }

    /**
     * mumu 2026-03-30：对齐 gmkitx 的前缀式 HMAC 入口。
     *
     * @param key  HMAC 密钥
     * @param data 输入字符串
     * @return HMAC 结果
     */
    public static byte[] sm3Hmac(byte[] key, String data) {
        return hmac(key, data);
    }

    /**
     * 计算字节数组的 SM3 摘要。
     *
     * @param data 输入数据，不能为 {@code null}
     * @return 32 字节摘要
     */
    public static byte[] digest(byte[] data) {
        return SM3Support.digest(data);
    }

    public static byte[] digest(String data) {
        return DEFAULT.digest(data);
    }

    public static byte[] digest(String data, Charset charset) {
        return DEFAULT.digest(data, charset);
    }

    public static String digestHex(byte[] data) {
        return DEFAULT.digestHex(data);
    }

    public static String digestHex(String data) {
        return DEFAULT.digestHex(data);
    }

    public static String digestHex(String data, Charset charset) {
        return DEFAULT.digestHex(data, charset);
    }

    public static String digestBase64(byte[] data) {
        return DEFAULT.digestBase64(data);
    }

    public static String digestBase64(String data) {
        return DEFAULT.digestBase64(data);
    }

    public static String digestBase64(String data, Charset charset) {
        return DEFAULT.digestBase64(data, charset);
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        return SM3Support.hmac(key, data);
    }

    public static byte[] hmac(byte[] key, String data) {
        return DEFAULT.hmac(key, data);
    }

    public static byte[] hmac(byte[] key, String data, Charset charset) {
        return DEFAULT.hmac(key, data, charset);
    }

    public static String hmacHex(byte[] key, byte[] data) {
        return DEFAULT.hmacHex(key, data);
    }

    public static String hmacHex(byte[] key, String data) {
        return DEFAULT.hmacHex(key, data);
    }

    public static String hmacHex(byte[] key, String data, Charset charset) {
        return DEFAULT.hmacHex(key, data, charset);
    }

    public static String hmacBase64(byte[] key, byte[] data) {
        return DEFAULT.hmacBase64(key, data);
    }

    public static String hmacBase64(byte[] key, String data) {
        return DEFAULT.hmacBase64(key, data);
    }

    public static String hmacBase64(byte[] key, String data, Charset charset) {
        return DEFAULT.hmacBase64(key, data, charset);
    }
}
