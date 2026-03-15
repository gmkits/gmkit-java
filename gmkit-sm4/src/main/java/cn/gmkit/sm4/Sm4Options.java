package cn.gmkit.sm4;

import cn.gmkit.core.*;

/**
 * @author mumu
 * @description SM4加密算法选项配置基类
 * @since 1.0.0
 */
public class Sm4Options {

    private final Sm4CipherMode mode;
    private final Sm4Padding padding;
    private final byte[] iv;
    private final byte[] aad;
    private final Integer tagLength;
    private final GmSecurityContext securityContext;

    protected Sm4Options(Builder builder) {
        this.mode = builder.mode;
        this.padding = builder.padding;
        this.iv = Bytes.clone(builder.iv);
        this.aad = Bytes.clone(builder.aad);
        this.tagLength = builder.tagLength;
        this.securityContext = builder.securityContext;
    }

    /**
     * 创建构建器
     *
     * @return 构建器实例
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * 获取加密模式
     *
     * @return 加密模式
     */
    public Sm4CipherMode mode() {
        return mode;
    }

    /**
     * 获取填充模式
     *
     * @return 填充模式
     */
    public Sm4Padding padding() {
        return padding;
    }

    /**
     * 获取初始化向量
     *
     * @return 初始化向量字节数组的克隆
     */
    public byte[] iv() {
        return Bytes.clone(iv);
    }

    /**
     * 获取附加认证数据（用于AEAD模式）
     *
     * @return 附加认证数据字节数组的克隆
     */
    public byte[] aad() {
        return Bytes.clone(aad);
    }

    /**
     * 获取认证标签长度（用于AEAD模式）
     *
     * @return 标签长度，可能为null
     */
    public Integer tagLength() {
        return tagLength;
    }

    /**
     * 获取安全上下文
     *
     * @return 安全上下文实例
     */
    public GmSecurityContext securityContext() {
        return securityContext;
    }

    /**
     * SM4选项构建器
     */
    public static class Builder {
        protected Sm4CipherMode mode = Sm4CipherMode.ECB;
        protected Sm4Padding padding = Sm4Padding.PKCS7;
        protected byte[] iv;
        protected byte[] aad;
        protected Integer tagLength;
        protected GmSecurityContext securityContext = GmSecurityContexts.defaults();

        /**
         * 设置加密模式
         *
         * @param mode 加密模式
         * @return 构建器实例
         */
        public Builder mode(Sm4CipherMode mode) {
            this.mode = mode != null ? mode : Sm4CipherMode.ECB;
            return this;
        }

        /**
         * 设置填充模式
         *
         * @param padding 填充模式
         * @return 构建器实例
         */
        public Builder padding(Sm4Padding padding) {
            this.padding = padding != null ? padding : Sm4Padding.PKCS7;
            return this;
        }

        /**
         * 设置初始化向量
         *
         * @param iv 初始化向量
         * @return 构建器实例
         */
        public Builder iv(byte[] iv) {
            this.iv = Bytes.clone(iv);
            return this;
        }

        /**
         * 设置附加认证数据
         *
         * @param aad 附加认证数据
         * @return 构建器实例
         */
        public Builder aad(byte[] aad) {
            this.aad = Bytes.clone(aad);
            return this;
        }

        /**
         * 设置认证标签长度
         *
         * @param tagLength 标签长度
         * @return 构建器实例
         */
        public Builder tagLength(Integer tagLength) {
            this.tagLength = tagLength;
            return this;
        }

        /**
         * 设置安全上下文
         *
         * @param securityContext 安全上下文
         * @return 构建器实例
         */
        public Builder securityContext(GmSecurityContext securityContext) {
            this.securityContext = securityContext != null ? securityContext : GmSecurityContexts.defaults();
            return this;
        }

        /**
         * 构建选项对象
         *
         * @return SM4选项实例
         */
        public Sm4Options build() {
            return new Sm4Options(this);
        }
    }
}

