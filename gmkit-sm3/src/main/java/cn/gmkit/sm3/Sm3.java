package cn.gmkit.sm3;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.GmkitException;

/**
 * @author mumu
 * @description SM3消息摘要算法工具类，提供SM3哈希和HMAC功能
 * @since 1.0.0
 */
public final class Sm3 {

    private final byte[] hmacKey;

    public Sm3() {
        this(null);
    }

    public Sm3(byte[] hmacKey) {
        this.hmacKey = Bytes.clone(hmacKey);
    }

    public byte[] digest(byte[] data) {
        return Sm3Util.digest(data);
    }

    public byte[] digest(String data) {
        return Sm3Util.digest(data);
    }

    public String digestHex(byte[] data) {
        return Sm3Util.digestHex(data);
    }

    public String digestHex(String data) {
        return Sm3Util.digestHex(data);
    }

    public String digestBase64(byte[] data) {
        return Sm3Util.digestBase64(data);
    }

    public byte[] hmac(byte[] data) {
        return Sm3Util.hmac(requireHmacKey(), data);
    }

    public byte[] hmac(String data) {
        return Sm3Util.hmac(requireHmacKey(), data);
    }

    public String hmacHex(byte[] data) {
        return Sm3Util.hmacHex(requireHmacKey(), data);
    }

    public String hmacHex(String data) {
        return Sm3Util.hmacHex(requireHmacKey(), data);
    }

    public String hmacBase64(byte[] data) {
        return Sm3Util.hmacBase64(requireHmacKey(), data);
    }

    public boolean hmacEnabled() {
        return hmacKey != null;
    }

    private byte[] requireHmacKey() {
        if (!hmacEnabled()) {
            throw new GmkitException("SM3 HMAC key is not configured");
        }
        return Bytes.clone(hmacKey);
    }
}

