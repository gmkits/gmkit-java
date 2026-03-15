package cn.gmkit.sm2;

/**
 * @author mumu
 * @description SM2密钥对封装类
 * @since 1.0.0
 */
public final class Sm2KeyPair {

    private final String publicKey;
    private final String privateKey;

    /**
     * 构造SM2密钥对
     *
     * @param publicKey  公钥字符串
     * @param privateKey 私钥字符串
     */
    public Sm2KeyPair(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * 获取公钥
     *
     * @return 公钥字符串
     */
    public String publicKey() {
        return publicKey;
    }

    /**
     * 获取私钥
     *
     * @return 私钥字符串
     */
    public String privateKey() {
        return privateKey;
    }
}


