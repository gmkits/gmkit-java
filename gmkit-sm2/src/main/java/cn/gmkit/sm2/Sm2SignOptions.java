package cn.gmkit.sm2;

import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.GmSecurityContexts;
import cn.gmkit.core.Sm2SignatureFormat;

/**
 * @author mumu
 * @description SM2签名选项配置类
 * @since 1.0.0
 */
public final class Sm2SignOptions {

    private final Sm2SignatureFormat signatureFormat;
    private final String userId;
    private final boolean skipZComputation;
    private final GmSecurityContext securityContext;

    private Sm2SignOptions(Builder builder) {
        this.signatureFormat = builder.signatureFormat;
        this.userId = builder.userId;
        this.skipZComputation = builder.skipZComputation;
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
     * 获取签名格式
     *
     * @return 签名格式
     */
    public Sm2SignatureFormat signatureFormat() {
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
     * 获取安全上下文
     *
     * @return 安全上下文
     */
    public GmSecurityContext securityContext() {
        return securityContext;
    }

    /**
     * SM2签名选项构建器
     */
    public static final class Builder {
        private Sm2SignatureFormat signatureFormat = Sm2SignatureFormat.RAW;
        private String userId = Sm2Util.DEFAULT_USER_ID;
        private boolean skipZComputation;
        private GmSecurityContext securityContext = GmSecurityContexts.defaults();

        private Builder() {
        }

        /**
         * 设置签名格式
         *
         * @param signatureFormat 签名格式
         * @return 构建器实例
         */
        public Builder signatureFormat(Sm2SignatureFormat signatureFormat) {
            this.signatureFormat = signatureFormat != null ? signatureFormat : Sm2SignatureFormat.RAW;
            return this;
        }

        /**
         * 设置用户ID
         *
         * @param userId 用户ID
         * @return 构建器实例
         */
        public Builder userId(String userId) {
            this.userId = userId != null ? userId : Sm2Util.DEFAULT_USER_ID;
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
         * 构建签名选项对象
         *
         * @return 签名选项实例
         */
        public Sm2SignOptions build() {
            return new Sm2SignOptions(this);
        }
    }
}

