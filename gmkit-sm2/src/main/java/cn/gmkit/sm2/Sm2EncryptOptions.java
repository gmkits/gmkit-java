package cn.gmkit.sm2;

import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.GmSecurityContexts;
import cn.gmkit.core.Sm2CipherMode;

/**
 * @author mumu
 * @description SM2加密选项配置类
 * @since 1.0.0
 */
public final class Sm2EncryptOptions {

    private final Sm2CipherMode mode;
    private final GmSecurityContext securityContext;

    private Sm2EncryptOptions(Builder builder) {
        this.mode = builder.mode;
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
     * 获取密文排列模式
     *
     * @return 密文排列模式
     */
    public Sm2CipherMode mode() {
        return mode;
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
     * SM2加密选项构建器
     */
    public static final class Builder {
        private Sm2CipherMode mode = Sm2CipherMode.C1C3C2;
        private GmSecurityContext securityContext = GmSecurityContexts.defaults();

        private Builder() {
        }

        /**
         * 设置密文排列模式
         *
         * @param mode 密文排列模式
         * @return 构建器实例
         */
        public Builder mode(Sm2CipherMode mode) {
            this.mode = mode != null ? mode : Sm2CipherMode.C1C3C2;
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
         * 构建加密选项对象
         *
         * @return 加密选项实例
         */
        public Sm2EncryptOptions build() {
            return new Sm2EncryptOptions(this);
        }
    }
}


