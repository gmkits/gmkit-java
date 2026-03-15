package cn.gmkit.sm3;

import cn.gmkit.core.Base64Codec;
import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * @author mumu
 * @description SM3消息摘要算法工具类，提供SM3哈希和HMAC功能
 * @since 1.0.0
 */
public final class Sm3Util {

    public static final int DIGEST_LENGTH = 32;

    private Sm3Util() {
    }

    public static byte[] digest(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] output = new byte[DIGEST_LENGTH];
        digest.doFinal(output, 0);
        return output;
    }

    public static byte[] digest(String data) {
        return digest(Texts.utf8(data));
    }

    public static String digestHex(byte[] data) {
        return HexCodec.encode(digest(data));
    }

    public static String digestHex(String data) {
        return HexCodec.encode(digest(data));
    }

    public static String digestBase64(byte[] data) {
        return Base64Codec.encode(digest(data));
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        HMac hmac = new HMac(new SM3Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] output = new byte[DIGEST_LENGTH];
        hmac.doFinal(output, 0);
        return output;
    }

    public static byte[] hmac(byte[] key, String data) {
        return hmac(key, Texts.utf8(data));
    }

    public static String hmacHex(byte[] key, byte[] data) {
        return HexCodec.encode(hmac(key, data));
    }

    public static String hmacHex(byte[] key, String data) {
        return HexCodec.encode(hmac(key, Texts.utf8(data)));
    }

    public static String hmacBase64(byte[] key, byte[] data) {
        return Base64Codec.encode(hmac(key, data));
    }
}

