package cn.gmkit.core;

/**
 * GMKit 运行时异常。
 * <p>
 * 公开 API 的参数错误、编码错误、加解密失败和签名失败等场景都会尽量统一为这个异常类型，
 * 便于业务侧按一个入口兜底处理。
 */
public class GmkitException extends RuntimeException {

    public GmkitException(String message) {
        super(message);
    }

    public GmkitException(String message, Throwable cause) {
        super(message, cause);
    }
}

