package cn.gmkit.core;

/**
 * GMKit核心异常类，表示GMKit相关的运行时异常。
 *
 * @author mumu
 * @since 1.0.0
 */
public class GmkitException extends RuntimeException {

    public GmkitException(String message) {
        super(message);
    }

    public GmkitException(String message, Throwable cause) {
        super(message, cause);
    }
}


