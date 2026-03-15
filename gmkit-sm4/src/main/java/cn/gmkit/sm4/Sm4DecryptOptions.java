package cn.gmkit.sm4;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.Sm4CipherMode;
import cn.gmkit.core.Sm4Padding;

/**
 * @author mumu
 * @description SM4解密选项配置类
 * @since 1.0.0
 */
public final class Sm4DecryptOptions extends Sm4Options {

    private final byte[] tag;

    private Sm4DecryptOptions(Builder builder) {
        super(builder);
        this.tag = Bytes.clone(builder.tag);
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
     * 获取认证标签（用于AEAD模式验证）
     *
     * @return 认证标签字节数组的克隆
     */
    public byte[] tag() {
        return Bytes.clone(tag);
    }

    /**
     * SM4解密选项构建器
     */
    public static final class Builder extends Sm4Options.Builder {
        private byte[] tag;

        private Builder() {
        }

        @Override
        public Builder mode(Sm4CipherMode mode) {
            super.mode(mode);
            return this;
        }

        @Override
        public Builder padding(Sm4Padding padding) {
            super.padding(padding);
            return this;
        }

        @Override
        public Builder iv(byte[] iv) {
            super.iv(iv);
            return this;
        }

        @Override
        public Builder aad(byte[] aad) {
            super.aad(aad);
            return this;
        }

        @Override
        public Builder tagLength(Integer tagLength) {
            super.tagLength(tagLength);
            return this;
        }

        @Override
        public Builder securityContext(GmSecurityContext securityContext) {
            super.securityContext(securityContext);
            return this;
        }

        /**
         * 设置认证标签（用于AEAD模式）
         *
         * @param tag 认证标签
         * @return 构建器实例
         */
        public Builder tag(byte[] tag) {
            this.tag = Bytes.clone(tag);
            return this;
        }

        @Override
        public Sm4DecryptOptions build() {
            return new Sm4DecryptOptions(this);
        }
    }
}

