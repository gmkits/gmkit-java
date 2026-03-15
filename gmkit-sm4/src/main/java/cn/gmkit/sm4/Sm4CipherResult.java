package cn.gmkit.sm4;

import cn.gmkit.core.Base64Codec;
import cn.gmkit.core.Bytes;
import cn.gmkit.core.HexCodec;

/**
 * @author mumu
 * @description SM4加密结果封装类
 * @since 1.0.0
 */
public final class Sm4CipherResult {

    private final byte[] ciphertext;
    private final byte[] tag;

    /**
     * 构造SM4加密结果对象
     *
     * @param ciphertext 密文数据
     * @param tag        认证标签（用于AEAD模式如GCM、CCM）
     */
    public Sm4CipherResult(byte[] ciphertext, byte[] tag) {
        this.ciphertext = Bytes.clone(ciphertext);
        this.tag = Bytes.clone(tag);
    }

    /**
     * 获取密文数据
     *
     * @return 密文字节数组的克隆
     */
    public byte[] ciphertext() {
        return Bytes.clone(ciphertext);
    }

    /**
     * 获取认证标签
     *
     * @return 认证标签字节数组的克隆
     */
    public byte[] tag() {
        return Bytes.clone(tag);
    }

    /**
     * 判断是否包含认证标签
     *
     * @return 如果包含认证标签返回true，否则返回false
     */
    public boolean hasTag() {
        return tag != null && tag.length > 0;
    }

    /**
     * 获取密文的十六进制字符串
     *
     * @return 密文的十六进制表示
     */
    public String ciphertextHex() {
        return HexCodec.encode(ciphertext);
    }

    /**
     * 获取密文的Base64字符串
     *
     * @return 密文的Base64表示
     */
    public String ciphertextBase64() {
        return Base64Codec.encode(ciphertext);
    }

    /**
     * 获取认证标签的十六进制字符串
     *
     * @return 认证标签的十六进制表示，如果不存在则返回null
     */
    public String tagHex() {
        return hasTag() ? HexCodec.encode(tag) : null;
    }

    /**
     * 获取认证标签的Base64字符串
     *
     * @return 认证标签的Base64表示，如果不存在则返回null
     */
    public String tagBase64() {
        return hasTag() ? Base64Codec.encode(tag) : null;
    }
}


