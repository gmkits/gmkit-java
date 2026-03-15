package cn.gmkit.core;

import org.bouncycastle.crypto.engines.SM2Engine;

/**
 * @author mumu
 * @description SM2加密密文排列模式枚举
 * @since 1.0.0
 */
public enum Sm2CipherMode {
    /**
     * C1C3C2排列模式，国密标准推荐模式
     */
    C1C3C2(SM2Engine.Mode.C1C3C2),
    /**
     * C1C2C3排列模式
     */
    C1C2C3(SM2Engine.Mode.C1C2C3);

    private final SM2Engine.Mode bcMode;

    Sm2CipherMode(SM2Engine.Mode bcMode) {
        this.bcMode = bcMode;
    }

    /**
     * 转换为BouncyCastle的SM2Engine模式
     *
     * @return BouncyCastle的SM2Engine.Mode
     */
    public SM2Engine.Mode toBcMode() {
        return bcMode;
    }
}


