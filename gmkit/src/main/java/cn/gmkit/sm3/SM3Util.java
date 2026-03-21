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

    private SM3Util() {
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
        return new SM3().digest(data);
    }

    public static byte[] digest(String data, Charset charset) {
        return new SM3().digest(data, charset);
    }

    public static String digestHex(byte[] data) {
        return new SM3().digestHex(data);
    }

    public static String digestHex(String data) {
        return new SM3().digestHex(data);
    }

    public static String digestHex(String data, Charset charset) {
        return new SM3().digestHex(data, charset);
    }

    public static String digestBase64(byte[] data) {
        return new SM3().digestBase64(data);
    }

    public static String digestBase64(String data) {
        return new SM3().digestBase64(data);
    }

    public static String digestBase64(String data, Charset charset) {
        return new SM3().digestBase64(data, charset);
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        return SM3Support.hmac(key, data);
    }

    public static byte[] hmac(byte[] key, String data) {
        return new SM3().hmac(key, data);
    }

    public static byte[] hmac(byte[] key, String data, Charset charset) {
        return new SM3().hmac(key, data, charset);
    }

    public static String hmacHex(byte[] key, byte[] data) {
        return new SM3().hmacHex(key, data);
    }

    public static String hmacHex(byte[] key, String data) {
        return new SM3().hmacHex(key, data);
    }

    public static String hmacHex(byte[] key, String data, Charset charset) {
        return new SM3().hmacHex(key, data, charset);
    }

    public static String hmacBase64(byte[] key, byte[] data) {
        return new SM3().hmacBase64(key, data);
    }

    public static String hmacBase64(byte[] key, String data) {
        return new SM3().hmacBase64(key, data);
    }

    public static String hmacBase64(byte[] key, String data, Charset charset) {
        return new SM3().hmacBase64(key, data, charset);
    }
}
