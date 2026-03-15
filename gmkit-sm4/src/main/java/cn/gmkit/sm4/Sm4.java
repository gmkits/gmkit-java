package cn.gmkit.sm4;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;

/**
 * @author mumu
 * @description SM4对称加密算法工具类，提供加密和解密功能
 * @since 1.0.0
 */
public final class Sm4 {

    private final byte[] key;

    public Sm4() {
        this(Sm4Util.generateKey());
    }

    public Sm4(byte[] key) {
        this.key = Bytes.clone(key);
    }

    public Sm4(String keyHex) {
        this(HexCodec.decodeStrict(keyHex, "SM4 key"));
    }

    public byte[] key() {
        return Bytes.clone(key);
    }

    public String keyHex() {
        return HexCodec.encode(key);
    }

    public Sm4CipherResult encrypt(byte[] data, Sm4Options options) {
        return Sm4Util.encrypt(key, data, options);
    }

    public Sm4CipherResult encrypt(String data, Sm4Options options) {
        return Sm4Util.encrypt(key, Texts.utf8(data), options);
    }

    public byte[] decrypt(byte[] ciphertext, Sm4DecryptOptions options) {
        return Sm4Util.decrypt(key, ciphertext, options);
    }

    public byte[] decrypt(Sm4CipherResult result, Sm4DecryptOptions options) {
        return Sm4Util.decrypt(key, result, options);
    }

    public String decryptToUtf8(byte[] ciphertext, Sm4DecryptOptions options) {
        return Sm4Util.decryptToUtf8(key, ciphertext, options);
    }

    public String decryptToUtf8(Sm4CipherResult result, Sm4DecryptOptions options) {
        return Sm4Util.decryptToUtf8(key, result, options);
    }
}

