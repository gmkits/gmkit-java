package cn.gmkit.sm2;

import cn.gmkit.core.SM2SignatureInputFormat;

/**
 * @author mumu
 * @description SM2验签选项配置类
 * @since 1.0.0
 */
public final class SM2VerifyOptions {

    private final SM2SignatureInputFormat signatureFormat;
    private final String userId;
    private final boolean skipZComputation;

    private SM2VerifyOptions(Builder builder) {
        this.signatureFormat = builder.signatureFormat;
        this.userId = builder.userId;
        this.skipZComputation = builder.skipZComputation;
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
     * 获取签名输入格式
     *
     * @return 签名输入格式
     */
    public SM2SignatureInputFormat signatureFormat() {
        return signatureFormat;
    }

    /**
     * 获取用户ID
     *
     * @return 用户ID
     */
    public String userId() {
        return userId;
    }

    /**
     * 是否跳过Z值计算
     *
     * @return 如果跳过返回true，否则返回false
     */
    public boolean skipZComputation() {
        return skipZComputation;
    }

    /**
     * SM2验签选项构建器
     */
    public static final class Builder {
        private SM2SignatureInputFormat signatureFormat = SM2SignatureInputFormat.AUTO;
        private String userId = SM2.DEFAULT_USER_ID;
        private boolean skipZComputation;

        private Builder() {
        }

        /**
         * 设置签名输入格式
         *
         * @param signatureFormat 签名输入格式
         * @return 构建器实例
         */
        public Builder signatureFormat(SM2SignatureInputFormat signatureFormat) {
            this.signatureFormat = signatureFormat != null ? signatureFormat : SM2SignatureInputFormat.AUTO;
            return this;
        }

        /**
         * 设置用户ID
         *
         * @param userId 用户ID
         * @return 构建器实例
         */
        public Builder userId(String userId) {
            this.userId = userId != null ? userId : SM2.DEFAULT_USER_ID;
            return this;
        }

        /**
         * 设置是否跳过Z值计算
         *
         * @param skipZComputation 是否跳过Z值计算
         * @return 构建器实例
         */
        public Builder skipZComputation(boolean skipZComputation) {
            this.skipZComputation = skipZComputation;
            return this;
        }

        /**
         * 构建验签选项对象
         *
         * @return 验签选项实例
         */
        public SM2VerifyOptions build() {
            return new SM2VerifyOptions(this);
        }
    }
}

