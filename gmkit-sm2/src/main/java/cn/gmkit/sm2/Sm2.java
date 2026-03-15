package cn.gmkit.sm2;

import cn.gmkit.core.GmkitException;
import cn.gmkit.core.Sm2SignatureFormat;
import cn.gmkit.core.Sm2SignatureInputFormat;

/**
 * @author mumu
 * @description SM2椭圆曲线公钥密码算法工具类，提供加密、解密、签名、验证和密钥交换功能
 * @since 1.0.0
 */
public final class Sm2 {

    private final String privateKey;
    private final String publicKey;

    public Sm2() {
        this(Sm2Util.generateKeyPair(false));
    }

    public Sm2(Sm2KeyPair keyPair) {
        this(keyPair.privateKey(), keyPair.publicKey());
    }

    public Sm2(String privateKeyHex, String publicKeyHex) {
        this.privateKey = privateKeyHex;
        this.publicKey = publicKeyHex != null
            ? publicKeyHex
            : privateKeyHex != null ? Sm2Util.getPublicKeyFromPrivateKey(privateKeyHex, false) : null;
    }

    public static Sm2 generate() {
        return new Sm2();
    }

    public static Sm2 generate(boolean compressedPublicKey) {
        return new Sm2(Sm2Util.generateKeyPair(compressedPublicKey));
    }

    public static Sm2 ofKeyPair(Sm2KeyPair keyPair) {
        return new Sm2(keyPair);
    }

    public static Sm2 ofPrivateKey(String privateKeyHex) {
        return new Sm2(privateKeyHex, null);
    }

    public static Sm2 ofPublicKey(String publicKeyHex) {
        return new Sm2(null, publicKeyHex);
    }

    public String privateKey() {
        return privateKey;
    }

    public String publicKey() {
        return publicKey;
    }

    public Sm2KeyPair keyPair() {
        return new Sm2KeyPair(requirePublicKey(), requirePrivateKey());
    }

    public byte[] encrypt(byte[] data, Sm2EncryptOptions options) {
        return Sm2Util.encrypt(requirePublicKey(), data, options);
    }

    public byte[] decrypt(byte[] ciphertext, Sm2DecryptOptions options) {
        return Sm2Util.decrypt(requirePrivateKey(), ciphertext, options);
    }

    public byte[] decrypt(String ciphertext, Sm2DecryptOptions options) {
        return Sm2Util.decrypt(requirePrivateKey(), ciphertext, options);
    }

    public byte[] sign(byte[] message, Sm2SignOptions options) {
        return Sm2Util.sign(requirePrivateKey(), message, options);
    }

    public byte[] signWithoutZ(byte[] message, Sm2SignatureFormat signatureFormat) {
        return Sm2Util.signWithoutZ(requirePrivateKey(), message, signatureFormat);
    }

    public boolean verify(byte[] message, byte[] signature, Sm2VerifyOptions options) {
        return Sm2Util.verify(requirePublicKey(), message, signature, options);
    }

    public boolean verify(byte[] message, String signature, Sm2VerifyOptions options) {
        return Sm2Util.verify(requirePublicKey(), message, signature, options);
    }

    public boolean verifyWithoutZ(byte[] message, byte[] signature, Sm2SignatureInputFormat signatureFormat) {
        return Sm2Util.verifyWithoutZ(requirePublicKey(), message, signature, signatureFormat);
    }

    public byte[] computeZ(String userId) {
        return Sm2Util.computeZ(userId, requirePublicKey());
    }

    public byte[] computeE(byte[] message, String userId, boolean skipZComputation) {
        return Sm2Util.computeE(requirePublicKey(), message, userId, skipZComputation);
    }

    public byte[] keyExchange(
        String ephemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        Sm2KeyExchangeOptions options) {
        return Sm2Util.keyExchange(
            requirePrivateKey(),
            ephemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    public Sm2KeyExchangeResult keyExchangeWithConfirmation(
        String ephemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        Sm2KeyExchangeOptions options) {
        return Sm2Util.keyExchangeWithConfirmation(
            requirePrivateKey(),
            ephemeralPrivateKeyHex,
            peerStaticPublicKeyHex,
            peerEphemeralPublicKeyHex,
            options);
    }

    private String requirePrivateKey() {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new GmkitException("SM2 private key is not configured");
        }
        return privateKey;
    }

    private String requirePublicKey() {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new GmkitException("SM2 public key is not configured");
        }
        return publicKey;
    }
}

