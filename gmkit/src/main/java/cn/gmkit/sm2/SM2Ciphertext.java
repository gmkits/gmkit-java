package cn.gmkit.sm2;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.SM2CipherMode;

/**
 * @author mumu
 * @description SM2密文数据结构封装类
 * @since 1.0.0
 */
public final class SM2Ciphertext {

    private final byte[] c1;
    private final byte[] c2;
    private final byte[] c3;
    private final SM2CipherMode mode;

    /**
     * 构造SM2密文对象
     *
     * @param c1   椭圆曲线点（公钥部分）
     * @param c2   密文数据
     * @param c3   消息摘要值
     * @param mode 密文排列模式
     */
    public SM2Ciphertext(byte[] c1, byte[] c2, byte[] c3, SM2CipherMode mode) {
        this.c1 = Bytes.clone(c1);
        this.c2 = Bytes.clone(c2);
        this.c3 = Bytes.clone(c3);
        this.mode = mode;
    }

    /**
     * 获取C1部分（椭圆曲线点）
     *
     * @return C1字节数组的克隆
     */
    public byte[] c1() {
        return Bytes.clone(c1);
    }

    /**
     * 获取C2部分（密文数据）
     *
     * @return C2字节数组的克隆
     */
    public byte[] c2() {
        return Bytes.clone(c2);
    }

    /**
     * 获取C3部分（消息摘要）
     *
     * @return C3字节数组的克隆
     */
    public byte[] c3() {
        return Bytes.clone(c3);
    }

    /**
     * 获取密文排列模式
     *
     * @return 密文排列模式
     */
    public SM2CipherMode mode() {
        return mode;
    }
}


