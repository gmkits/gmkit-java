package cn.gmkit.core;

import org.bouncycastle.util.encoders.Hex;

/**
 * @author mumu
 * @description 十六进制编解码工具类
 * @since 1.0.0
 */
public final class HexCodec {

    private HexCodec() {
    }

    /**
     * 严格模式的十六进制解码
     *
     * @param input 十六进制字符串
     * @param label 错误提示标签
     * @return 解码后的字节数组
     * @throws GmkitException 如果输入不是有效的十六进制字符串
     */
    public static byte[] decodeStrict(String input, String label) {
        String normalized = normalize(input);
        if ((normalized.length() & 1) != 0) {
            throw new GmkitException("Invalid " + label + ": hexadecimal strings must have an even length");
        }
        if (!isHex(normalized)) {
            throw new GmkitException("Invalid " + label + ": must be a hexadecimal string");
        }
        return Hex.decode(normalized);
    }

    /**
     * 十六进制编码
     *
     * @param input 待编码的字节数组
     * @return 十六进制字符串
     */
    public static String encode(byte[] input) {
        return Hex.toHexString(input);
    }

    /**
     * 判断字符串是否为有效的十六进制
     *
     * @param input 待判断的字符串
     * @return 如果是有效的十六进制返回true，否则返回false
     */
    public static boolean isHex(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            boolean digit = ch >= '0' && ch <= '9';
            boolean lower = ch >= 'a' && ch <= 'f';
            boolean upper = ch >= 'A' && ch <= 'F';
            if (!digit && !lower && !upper) {
                return false;
            }
        }
        return true;
    }

    /**
     * 规范化十六进制字符串，去除前缀和空白字符
     *
     * @param input 待规范化的字符串
     * @return 规范化后的十六进制字符串
     * @throws GmkitException 如果输入为null
     */
    public static String normalize(String input) {
        if (input == null) {
            throw new GmkitException("Hex input must not be null");
        }
        String normalized = input.trim();
        if (normalized.startsWith("0x") || normalized.startsWith("0X")) {
            normalized = normalized.substring(2);
        }
        return normalized;
    }
}


