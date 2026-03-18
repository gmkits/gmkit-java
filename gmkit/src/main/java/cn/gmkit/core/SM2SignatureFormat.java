package cn.gmkit.core;

/**
 * @author mumu
 * @description SM2 签名输出格式枚举
 * @since 1.0.0
 */
public enum SM2SignatureFormat {
    /**
     * 原始格式，64字节的R和S值拼接
     */
    RAW,
    /**
     * DER编码格式，ASN.1标准编码
     */
    DER
}



