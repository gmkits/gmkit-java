package cn.gmkit.core;

/**
 * @author mumu
 * @description 字节数组编码工具类，提供字节数组与字符串之间的编码转换
 * @since 1.0.0
 */
public final class ByteEncodings {

    private ByteEncodings() {
    }

    /**
     * 将字节数组编码为字符串
     *
     * @param input        待编码的字节数组
     * @param outputFormat 输出格式，支持HEX和BASE64
     * @return 编码后的字符串
     */
    public static String encode(byte[] input, OutputFormat outputFormat) {
        OutputFormat format = outputFormat != null ? outputFormat : OutputFormat.HEX;
        if (format == OutputFormat.HEX) {
            return HexCodec.encode(input);
        }
        if (format == OutputFormat.BASE64) {
            return Base64Codec.encode(input);
        }
        throw new GmkitException("Unsupported output format: " + format);
    }

    /**
     * 将字符串解码为字节数组
     *
     * @param input       待解码的字符串
     * @param inputFormat 输入格式，支持HEX和BASE64，为null时自动检测
     * @param label       错误提示标签
     * @return 解码后的字节数组
     */
    public static byte[] decode(String input, InputFormat inputFormat, String label) {
        if (inputFormat == null) {
            return decodeAuto(input, label);
        }
        if (inputFormat == InputFormat.HEX) {
            return HexCodec.decodeStrict(input, label);
        }
        if (inputFormat == InputFormat.BASE64) {
            return Base64Codec.decode(input, label);
        }
        throw new GmkitException("Unsupported input format: " + inputFormat);
    }

    /**
     * 自动检测输入格式并解码为字节数组
     *
     * @param input 待解码的字符串
     * @param label 错误提示标签
     * @return 解码后的字节数组
     */
    public static byte[] decodeAuto(String input, String label) {
        String trimmed = input != null ? input.trim() : null;
        if (trimmed == null) {
            throw new GmkitException("Invalid " + label + ": input must not be null");
        }
        String normalizedHex = HexCodec.normalize(trimmed);
        if ((normalizedHex.length() & 1) == 0 && HexCodec.isHex(normalizedHex)) {
            return HexCodec.decodeStrict(normalizedHex, label);
        }
        if (Base64Codec.isBase64(trimmed)) {
            return Base64Codec.decode(trimmed, label);
        }
        return HexCodec.decodeStrict(trimmed, label);
    }
}


