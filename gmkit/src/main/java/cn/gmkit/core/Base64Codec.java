package cn.gmkit.core;

import java.util.Base64;

/**
 * @author mumu
 * @description Base64编解码工具类
 * @since 1.0.0
 */
public final class Base64Codec {

    private static final Base64.Decoder DECODER = Base64.getDecoder();
    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    private Base64Codec() {
    }

    /**
     * Base64解码
     *
     * @param input Base64编码的字符串
     * @param label 错误提示标签
     * @return 解码后的字节数组
     * @throws GmkitException 如果输入不是有效的Base64字符串
     */
    public static byte[] decode(String input, String label) {
        if (input == null) {
            throw new GmkitException("Invalid " + label + ": input must not be null");
        }
        try {
            return DECODER.decode(input.trim());
        } catch (IllegalArgumentException ex) {
            throw new GmkitException("Invalid " + label + ": must be base64", ex);
        }
    }

    /**
     * Base64编码
     *
     * @param input 待编码的字节数组
     * @return Base64编码后的字符串
     */
    public static String encode(byte[] input) {
        return ENCODER.encodeToString(Bytes.requireNonNull(input, "Base64 input"));
    }

    /**
     * 判断字符串是否为有效的Base64编码
     *
     * @param input 待判断的字符串
     * @return 如果是有效的Base64编码返回true，否则返回false
     */
    public static boolean isBase64(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }
        try {
            DECODER.decode(input.trim());
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }
}

