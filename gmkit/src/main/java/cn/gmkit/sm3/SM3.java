package cn.gmkit.sm3;

import cn.gmkit.core.Base64Codec;
import cn.gmkit.core.GmkitException;
import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * SM3 静态工具入口。
 */
public final class SM3 {

    /**
     * SM3 摘要长度，单位为字节。
     */
    public static final int DIGEST_LENGTH = 32;

    private SM3() {
    }

    /**
     * 计算 SM3 摘要。
     *
     * @param data 输入字节数组
     * @return 摘要结果
     */
    public static byte[] digest(byte[] data) {
        if (data == null) {
            throw new GmkitException("SM3 input must not be null");
        }
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] output = new byte[DIGEST_LENGTH];
        digest.doFinal(output, 0);
        return output;
    }

    /**
     * 计算 UTF-8 字符串的 SM3 摘要。
     *
     * @param data 输入字符串
     * @return 摘要结果
     */
    public static byte[] digest(String data) {
        return digest(Texts.utf8(data));
    }

    /**
     * 计算 SM3 摘要并输出十六进制字符串。
     *
     * @param data 输入字节数组
     * @return 十六进制摘要
     */
    public static String digestHex(byte[] data) {
        return HexCodec.encode(digest(data));
    }

    /**
     * 计算 UTF-8 字符串的 SM3 摘要并输出十六进制字符串。
     *
     * @param data 输入字符串
     * @return 十六进制摘要
     */
    public static String digestHex(String data) {
        return HexCodec.encode(digest(data));
    }

    /**
     * 计算 SM3 摘要并输出 Base64 字符串。
     *
     * @param data 输入字节数组
     * @return Base64 摘要
     */
    public static String digestBase64(byte[] data) {
        return Base64Codec.encode(digest(data));
    }

    /**
     * 计算 HMAC-SM3。
     *
     * @param key  HMAC 密钥
     * @param data 输入字节数组
     * @return HMAC 结果
     */
    public static byte[] hmac(byte[] key, byte[] data) {
        if (key == null || data == null) {
            throw new GmkitException("SM3 HMAC key and input must not be null");
        }
        HMac hmac = new HMac(new SM3Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] output = new byte[DIGEST_LENGTH];
        hmac.doFinal(output, 0);
        return output;
    }

    /**
     * 计算 UTF-8 字符串的 HMAC-SM3。
     *
     * @param key  HMAC 密钥
     * @param data 输入字符串
     * @return HMAC 结果
     */
    public static byte[] hmac(byte[] key, String data) {
        return hmac(key, Texts.utf8(data));
    }

    /**
     * 计算 HMAC-SM3 并输出十六进制字符串。
     *
     * @param key  HMAC 密钥
     * @param data 输入字节数组
     * @return 十六进制 HMAC
     */
    public static String hmacHex(byte[] key, byte[] data) {
        return HexCodec.encode(hmac(key, data));
    }

    /**
     * 计算 UTF-8 字符串的 HMAC-SM3 并输出十六进制字符串。
     *
     * @param key  HMAC 密钥
     * @param data 输入字符串
     * @return 十六进制 HMAC
     */
    public static String hmacHex(byte[] key, String data) {
        return HexCodec.encode(hmac(key, Texts.utf8(data)));
    }

    /**
     * 计算 HMAC-SM3 并输出 Base64 字符串。
     *
     * @param key  HMAC 密钥
     * @param data 输入字节数组
     * @return Base64 HMAC
     */
    public static String hmacBase64(byte[] key, byte[] data) {
        return Base64Codec.encode(hmac(key, data));
    }
}
