package cn.gmkit.integration;

import cn.gmkit.core.Base64Codec;
import cn.gmkit.core.ByteEncodings;
import cn.gmkit.core.Bytes;
import cn.gmkit.core.Checks;
import cn.gmkit.core.OutputFormat;
import cn.gmkit.core.SM4CipherMode;
import cn.gmkit.core.SM4Padding;

/**
 * @author mumu
 * @description SM2 + SM4 混合加密载荷，便于后端直接传输加密后的会话密钥、业务密文与必要元数据
 * @since 1.0.0
 *
 * mumu 2026-03-30：新增统一载荷对象，减少业务层自行拼装多个字段时的出错概率。
 */
public final class SM2Sm4HybridPayload {

    private final byte[] encryptedKey;
    private final byte[] ciphertext;
    private final byte[] iv;
    private final byte[] aad;
    private final byte[] tag;
    private final SM4CipherMode mode;
    private final SM4Padding padding;

    public SM2Sm4HybridPayload(
        byte[] encryptedKey,
        byte[] ciphertext,
        byte[] iv,
        byte[] aad,
        byte[] tag,
        SM4CipherMode mode,
        SM4Padding padding) {
        this.encryptedKey = Bytes.clone(Checks.requireNonNull(encryptedKey, "encrypted SM4 key"));
        this.ciphertext = Bytes.clone(Checks.requireNonNull(ciphertext, "hybrid ciphertext"));
        this.iv = Bytes.clone(iv);
        this.aad = Bytes.clone(aad);
        this.tag = Bytes.clone(tag);
        this.mode = Checks.requireNonNull(mode, "SM4 mode");
        this.padding = Checks.requireNonNull(padding, "SM4 padding");
    }

    public byte[] encryptedKey() {
        return Bytes.clone(encryptedKey);
    }

    public String encryptedKeyHex() {
        return ByteEncodings.encode(encryptedKey, OutputFormat.HEX);
    }

    public String encryptedKeyBase64() {
        return ByteEncodings.encode(encryptedKey, OutputFormat.BASE64);
    }

    public byte[] ciphertext() {
        return Bytes.clone(ciphertext);
    }

    public String ciphertextHex() {
        return ByteEncodings.encode(ciphertext, OutputFormat.HEX);
    }

    public String ciphertextBase64() {
        return ByteEncodings.encode(ciphertext, OutputFormat.BASE64);
    }

    public byte[] iv() {
        return Bytes.clone(iv);
    }

    public boolean hasIv() {
        return Checks.hasBytes(iv);
    }

    public String ivHex() {
        return hasIv() ? ByteEncodings.encode(iv, OutputFormat.HEX) : null;
    }

    public byte[] aad() {
        return Bytes.clone(aad);
    }

    public boolean hasAad() {
        return Checks.hasBytes(aad);
    }

    public byte[] tag() {
        return Bytes.clone(tag);
    }

    public boolean hasTag() {
        return Checks.hasBytes(tag);
    }

    public String tagHex() {
        return hasTag() ? ByteEncodings.encode(tag, OutputFormat.HEX) : null;
    }

    public String tagBase64() {
        return hasTag() ? Base64Codec.encode(tag) : null;
    }

    public SM4CipherMode mode() {
        return mode;
    }

    public SM4Padding padding() {
        return padding;
    }
}
