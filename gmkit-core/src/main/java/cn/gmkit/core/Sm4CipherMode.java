package cn.gmkit.core;

/**
 * @author mumu
 * @description SM4加密算法的工作模式枚举
 * @since 1.0.0
 */
public enum Sm4CipherMode {
    /**
     * 电子密码本模式（Electronic Codebook）
     */
    ECB,
    /**
     * 密码分组链接模式（Cipher Block Chaining）
     */
    CBC,
    /**
     * 计数器模式（Counter）
     */
    CTR,
    /**
     * 密文反馈模式（Cipher Feedback）
     */
    CFB,
    /**
     * 输出反馈模式（Output Feedback）
     */
    OFB,
    /**
     * 伽罗瓦/计数器模式（Galois/Counter Mode）
     */
    GCM,
    /**
     * 计数器与CBC-MAC模式（Counter with CBC-MAC）
     */
    CCM;

    /**
     * 判断是否为流式加密模式
     *
     * @return 如果是流式加密模式返回true，否则返回false
     */
    public boolean isStreamLike() {
        return this == CTR || this == CFB || this == OFB || this == GCM || this == CCM;
    }
}


