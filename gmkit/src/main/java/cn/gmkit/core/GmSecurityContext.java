package cn.gmkit.core;

import java.security.Provider;
import java.security.SecureRandom;

/**
 * @author mumu
 * @description 国密算法安全上下文，封装加密操作所需的安全组件
 * @since 1.0.0
 */
public final class GmSecurityContext {

    private final Provider provider;
    private final SecureRandom secureRandom;
    private final boolean registerProvider;

    private GmSecurityContext(Builder builder) {
        this.provider = Checks.defaultIfNull(builder.provider, BcProviders.defaultProvider());
        this.secureRandom = Checks.defaultIfNull(builder.secureRandom, new SecureRandom());
        this.registerProvider = builder.registerProvider;
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
     * 获取加密提供者
     *
     * @return 加密提供者实例
     */
    public Provider provider() {
        if (!registerProvider) {
            return provider;
        }
        return BcProviders.registerIfNeeded(provider);
    }

    /**
     * 获取安全随机数生成器
     *
     * @return SecureRandom实例
     */
    public SecureRandom secureRandom() {
        return secureRandom;
    }

    /**
     * 是否注册Provider
     *
     * @return 如果需要注册返回true，否则返回false
     */
    public boolean registerProvider() {
        return registerProvider;
    }

    /**
     * 安全上下文构建器
     */
    public static final class Builder {
        private Provider provider;
        private SecureRandom secureRandom;
        private boolean registerProvider = true;

        private Builder() {
        }

        /**
         * 设置加密提供者
         *
         * @param provider 加密提供者
         * @return 构建器实例
         */
        public Builder provider(Provider provider) {
            this.provider = provider;
            return this;
        }

        /**
         * 设置安全随机数生成器
         *
         * @param secureRandom 安全随机数生成器
         * @return 构建器实例
         */
        public Builder secureRandom(SecureRandom secureRandom) {
            this.secureRandom = secureRandom;
            return this;
        }

        /**
         * 设置是否注册Provider
         *
         * @param registerProvider 是否注册Provider
         * @return 构建器实例
         */
        public Builder registerProvider(boolean registerProvider) {
            this.registerProvider = registerProvider;
            return this;
        }

        /**
         * 构建安全上下文对象
         *
         * @return 安全上下文实例
         */
        public GmSecurityContext build() {
            return new GmSecurityContext(this);
        }
    }
}

