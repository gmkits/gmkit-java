package cn.gmkit.core;

/**
 * @author mumu
 * @description SM4 加密算法的填充模式枚举
 * @since 1.0.0
 */
public enum SM4Padding {
    /**
     * PKCS7填充模式，自动填充数据到块大小的整数倍
     */
    PKCS7,
    /**
     * 不填充模式，要求数据长度必须是块大小的整数倍
     */
    NONE,
    /**
     * 零填充模式，使用0x00填充数据到块大小的整数倍
     */
    ZERO
}



