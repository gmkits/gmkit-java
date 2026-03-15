package cn.gmkit.sm2;

import cn.gmkit.core.Base64Codec;
import cn.gmkit.core.Bytes;
import cn.gmkit.core.HexCodec;

/**
 * @author mumu
 * @description SM2密钥交换结果封装类
 * @since 1.0.0
 */
public final class Sm2KeyExchangeResult {

    private final byte[] key;
    private final byte[] s1;
    private final byte[] s2;

    /**
     * 构造密钥交换结果对象
     *
     * @param key 协商出的共享密钥
     * @param s1  己方确认标签
     * @param s2  对方确认标签
     */
    public Sm2KeyExchangeResult(byte[] key, byte[] s1, byte[] s2) {
        this.key = Bytes.clone(key);
        this.s1 = Bytes.clone(s1);
        this.s2 = Bytes.clone(s2);
    }

    /**
     * 获取协商出的密钥
     *
     * @return 密钥字节数组的克隆
     */
    public byte[] key() {
        return Bytes.clone(key);
    }

    /**
     * 获取己方确认标签S1
     *
     * @return S1字节数组的克隆
     */
    public byte[] s1() {
        return Bytes.clone(s1);
    }

    /**
     * 获取对方确认标签S2
     *
     * @return S2字节数组的克隆
     */
    public byte[] s2() {
        return Bytes.clone(s2);
    }

    /**
     * 判断是否存在S1
     *
     * @return 如果存在S1返回true，否则返回false
     */
    public boolean hasS1() {
        return s1 != null && s1.length > 0;
    }

    /**
     * 判断是否存在S2
     *
     * @return 如果存在S2返回true，否则返回false
     */
    public boolean hasS2() {
        return s2 != null && s2.length > 0;
    }

    /**
     * 获取密钥的十六进制字符串
     *
     * @return 密钥的十六进制表示
     */
    public String keyHex() {
        return HexCodec.encode(key);
    }

    /**
     * 获取密钥的Base64字符串
     *
     * @return 密钥的Base64表示
     */
    public String keyBase64() {
        return Base64Codec.encode(key);
    }

    /**
     * 获取S1的十六进制字符串
     *
     * @return S1的十六进制表示，如果不存在则返回null
     */
    public String s1Hex() {
        return hasS1() ? HexCodec.encode(s1) : null;
    }

    /**
     * 获取S2的十六进制字符串
     *
     * @return S2的十六进制表示，如果不存在则返回null
     */
    public String s2Hex() {
        return hasS2() ? HexCodec.encode(s2) : null;
    }
}

