package cn.gmkit.sm3;

/**
 * SM3 兼容工具入口。
 *
 * @deprecated 请改用 {@link SM3}
 */
@Deprecated
public final class SM3Util {

    public static final int DIGEST_LENGTH = SM3.DIGEST_LENGTH;

    private SM3Util() {
    }

    public static byte[] digest(byte[] data) {
        return SM3.digest(data);
    }

    public static byte[] digest(String data) {
        return SM3.digest(data);
    }

    public static String digestHex(byte[] data) {
        return SM3.digestHex(data);
    }

    public static String digestHex(String data) {
        return SM3.digestHex(data);
    }

    public static String digestBase64(byte[] data) {
        return SM3.digestBase64(data);
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        return SM3.hmac(key, data);
    }

    public static byte[] hmac(byte[] key, String data) {
        return SM3.hmac(key, data);
    }

    public static String hmacHex(byte[] key, byte[] data) {
        return SM3.hmacHex(key, data);
    }

    public static String hmacHex(byte[] key, String data) {
        return SM3.hmacHex(key, data);
    }

    public static String hmacBase64(byte[] key, byte[] data) {
        return SM3.hmacBase64(key, data);
    }
}
