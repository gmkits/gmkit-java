package cn.gmkit.core;

/**
 * 统一的中英双语消息工具。
 * <p>
 * 中文优先用于直接展示，英文保留用于日志检索、搜索 issue 或与第三方实现对照。
 */
public final class Messages {

    private Messages() {
    }

    public static String bilingual(String zh, String en) {
        return zh + " / " + en;
    }

    public static String nullValue(String label) {
        return bilingual(label + " 不能为空", label + " must not be null");
    }

    public static String blankValue(String label) {
        return bilingual(label + " 不能为空白", label + " must not be blank");
    }

    public static String invalidHexEven(String label) {
        return bilingual(label + " 必须是偶数长度的十六进制字符串", "Invalid " + label + ": hexadecimal strings must have an even length");
    }

    public static String invalidHex(String label) {
        return bilingual(label + " 必须是十六进制字符串", "Invalid " + label + ": must be a hexadecimal string");
    }

    public static String invalidBase64(String label) {
        return bilingual(label + " 必须是 Base64 字符串", "Invalid " + label + ": must be base64");
    }

    public static String invalidHexOrBase64(String label) {
        return bilingual(label + " 必须是十六进制或 Base64 字符串", "Invalid " + label + ": must be hexadecimal or base64");
    }

    public static String invalidBlankInput(String label) {
        return bilingual(label + " 输入不能为空白", "Invalid " + label + ": input must not be blank");
    }

    public static String expectedLength(String label, int expectedLength, int actualLength) {
        return bilingual(
            label + " 长度必须为 " + expectedLength + " 字节，实际为 " + actualLength + " 字节",
            label + " must be " + expectedLength + " bytes, but was " + actualLength);
    }

    public static String multipleOf(String label, int blockSize) {
        return bilingual(
            label + " 长度必须是 " + blockSize + " 字节的整数倍",
            label + " length must be a multiple of " + blockSize + " bytes");
    }
}
