package cn.gmkit.core;

import java.security.Provider;
import java.security.SecureRandom;

/**
 * @author mumu
 * @description 国密安全上下文工厂类，提供常用的安全上下文配置
 * @since 1.0.0
 */
public final class GmSecurityContexts {

    private static final GmSecurityContext DEFAULT_CONTEXT = GmSecurityContext.builder()
        .provider(BcProviders.defaultProvider())
        .registerProvider(true)
        .build();

    private GmSecurityContexts() {
    }

    /**
     * 获取默认的安全上下文
     *
     * @return 默认安全上下文实例
     */
    public static GmSecurityContext defaults() {
        return DEFAULT_CONTEXT;
    }

    /**
     * 创建指定Provider的安全上下文
     *
     * @param provider 加密提供者
     * @return 安全上下文实例
     */
    public static GmSecurityContext withProvider(Provider provider) {
        return GmSecurityContext.builder()
            .provider(provider)
            .registerProvider(false)
            .build();
    }

    /**
     * 创建指定Provider和SecureRandom的安全上下文
     *
     * @param provider     加密提供者
     * @param secureRandom 安全随机数生成器
     * @return 安全上下文实例
     */
    public static GmSecurityContext withProviderAndRandom(Provider provider, SecureRandom secureRandom) {
        return GmSecurityContext.builder()
            .provider(provider)
            .secureRandom(secureRandom)
            .registerProvider(false)
            .build();
    }

    /**
     * 创建指定SecureRandom的安全上下文
     *
     * @param secureRandom 安全随机数生成器
     * @return 安全上下文实例
     */
    public static GmSecurityContext withSecureRandom(SecureRandom secureRandom) {
        return GmSecurityContext.builder()
            .provider(BcProviders.defaultProvider())
            .secureRandom(secureRandom)
            .registerProvider(true)
            .build();
    }
}


