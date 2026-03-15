package cn.gmkit.core;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * @author mumu
 * @description BouncyCastle Provider辅助工具类，用于管理加密提供者
 * @since 1.0.0
 */
public final class BcProviders {

    private static final Object LOCK = new Object();

    private BcProviders() {
    }

    /**
     * 创建一个新的BouncyCastle Provider实例
     *
     * @return BouncyCastle Provider实例
     */
    public static Provider create() {
        return new BouncyCastleProvider();
    }

    /**
     * 获取已注册的BouncyCastle Provider
     *
     * @return 如果已注册则返回Provider实例，否则返回null
     */
    public static Provider getIfPresent() {
        return Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * 获取默认的Provider，如果未注册则创建新实例
     *
     * @return BouncyCastle Provider实例
     */
    public static Provider defaultProvider() {
        Provider provider = getIfPresent();
        return provider != null ? provider : create();
    }

    /**
     * 确保BouncyCastle Provider已注册，如果未注册则自动注册
     *
     * @return 已注册的BouncyCastle Provider实例
     */
    public static Provider ensureRegistered() {
        Provider provider = getIfPresent();
        if (provider != null) {
            return provider;
        }
        synchronized (LOCK) {
            provider = getIfPresent();
            if (provider != null) {
                return provider;
            }
            Provider created = create();
            Security.addProvider(created);
            Provider registered = getIfPresent();
            return registered != null ? registered : created;
        }
    }

    /**
     * 如果需要则注册Provider
     *
     * @param provider 待注册的Provider实例
     * @return 已注册的Provider实例
     */
    public static Provider registerIfNeeded(Provider provider) {
        Provider existing = Security.getProvider(provider.getName());
        if (existing != null) {
            return existing;
        }
        synchronized (LOCK) {
            existing = Security.getProvider(provider.getName());
            if (existing != null) {
                return existing;
            }
            Security.addProvider(provider);
            Provider registered = Security.getProvider(provider.getName());
            return registered != null ? registered : provider;
        }
    }
}


