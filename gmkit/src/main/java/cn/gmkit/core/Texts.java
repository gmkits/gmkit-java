package cn.gmkit.core;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * @author mumu
 * @description 文本编码工具类，提供字符串与字节数组之间的转换
 * @since 1.0.0
 */
public final class Texts {

    /**
     * UTF-8字符集常量
     */
    public static final Charset UTF_8 = StandardCharsets.UTF_8;

    private Texts() {
    }

    /**
     * 将字符串编码为UTF-8字节数组
     *
     * @param input 待编码的字符串
     * @return UTF-8编码的字节数组
     * @throws GmkitException 如果输入为null
     */
    public static byte[] utf8(String input) {
        if (input == null) {
            throw new GmkitException("Text input must not be null");
        }
        return input.getBytes(UTF_8);
    }

    /**
     * 将UTF-8字节数组解码为字符串
     *
     * @param input UTF-8编码的字节数组
     * @return 解码后的字符串
     * @throws GmkitException 如果输入为null
     */
    public static String utf8(byte[] input) {
        if (input == null) {
            throw new GmkitException("Text input must not be null");
        }
        return new String(input, UTF_8);
    }
}

