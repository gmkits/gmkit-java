package cn.gmkit.sm2;

import cn.gmkit.core.Sm2CipherMode;

/**
 * @author mumu
 * @description SM2解密选项配置类
 * @since 1.0.0
 */
public final class Sm2DecryptOptions {

    private final Sm2CipherMode mode;

    private Sm2DecryptOptions(Builder builder) {
        this.mode = builder.mode;
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
     * SM2解密选项构建器
     */
    public static final class Builder {
        private Sm2CipherMode mode = Sm2CipherMode.C1C3C2;

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
         * 构建解密选项对象
         *
         * @return 解密选项实例
         */
        public Sm2DecryptOptions build() {
            return new Sm2DecryptOptions(this);
        }
    }
}


