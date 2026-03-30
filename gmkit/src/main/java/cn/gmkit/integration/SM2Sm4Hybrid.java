package cn.gmkit.integration;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.Checks;
import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.GmSecurityContexts;
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.core.SM4CipherMode;
import cn.gmkit.core.SM4Padding;
import cn.gmkit.core.Texts;
import cn.gmkit.sm2.SM2;
import cn.gmkit.sm4.SM4;
import cn.gmkit.sm4.SM4CipherResult;
import cn.gmkit.sm4.SM4Options;

import java.nio.charset.Charset;

/**
 * @author mumu
 * @description 面向后端的 SM2 + SM4 混合加密入口，统一封装会话密钥保护、业务密文和必要元数据
 * @since 1.0.0
 *
 * mumu 2026-03-30：默认采用 SM4-GCM + 随机 nonce，前端只需消费结果字段，后端可集中掌握模式细节。
 */
public final class SM2Sm4Hybrid {

    private static final int BLOCK_IV_LENGTH = 16;
    private static final int AEAD_IV_LENGTH = 12;
    private static final int DEFAULT_TAG_LENGTH = 16;

    private final GmSecurityContext securityContext;
    private final SM2 sm2;
    private final SM4 sm4;

    public SM2Sm4Hybrid() {
        this(null);
    }

    public SM2Sm4Hybrid(GmSecurityContext securityContext) {
        this.securityContext = Checks.defaultIfNull(securityContext, GmSecurityContexts.defaults());
        this.sm2 = new SM2(this.securityContext);
        this.sm4 = new SM4(this.securityContext);
    }

    public SM2Sm4HybridPayload encrypt(String publicKeyHex, byte[] plaintext) {
        return encrypt(publicKeyHex, plaintext, null);
    }

    public SM2Sm4HybridPayload encrypt(String publicKeyHex, String plaintext) {
        return encrypt(publicKeyHex, plaintext, Texts.UTF_8, null);
    }

    public SM2Sm4HybridPayload encrypt(String publicKeyHex, String plaintext, Charset charset, SM4Options options) {
        return encrypt(publicKeyHex, Texts.bytes(plaintext, charset), options);
    }

    public SM2Sm4HybridPayload encrypt(String publicKeyHex, byte[] plaintext, SM4Options options) {
        Checks.requireNonBlank(publicKeyHex, "SM2 public key");
        byte[] plain = Bytes.requireNonNull(plaintext, "hybrid plaintext");
        SM4Options resolvedOptions = resolveEncryptOptions(options);
        byte[] sessionKey = sm4.generateKey();
        SM4CipherResult cipherResult = sm4.encrypt(sessionKey, plain, resolvedOptions);
        byte[] encryptedKey = sm2.encrypt(publicKeyHex, sessionKey, SM2CipherMode.C1C3C2);
        return new SM2Sm4HybridPayload(
            encryptedKey,
            cipherResult.ciphertext(),
            resolvedOptions.iv(),
            resolvedOptions.aad(),
            cipherResult.tag(),
            resolvedOptions.mode(),
            resolvedOptions.padding());
    }

    public byte[] decrypt(String privateKeyHex, SM2Sm4HybridPayload payload) {
        Checks.requireNonBlank(privateKeyHex, "SM2 private key");
        Checks.requireNonNull(payload, "hybrid payload");
        byte[] sessionKey = sm2.decrypt(privateKeyHex, payload.encryptedKey(), SM2CipherMode.C1C3C2);
        return sm4.decrypt(sessionKey, payload.ciphertext(), optionsFromPayload(payload));
    }

    public String decryptToUtf8(String privateKeyHex, SM2Sm4HybridPayload payload) {
        return Texts.utf8(decrypt(privateKeyHex, payload));
    }

    public String decryptToString(String privateKeyHex, SM2Sm4HybridPayload payload, Charset charset) {
        return Texts.text(decrypt(privateKeyHex, payload), charset);
    }

    private SM4Options resolveEncryptOptions(SM4Options options) {
        if (options == null) {
            return SM4Options.builder()
                .mode(SM4CipherMode.GCM)
                .padding(SM4Padding.NONE)
                .iv(generateIv(SM4CipherMode.GCM))
                .tagLength(DEFAULT_TAG_LENGTH)
                .securityContext(securityContext)
                .build();
        }

        byte[] iv = options.iv();
        if (requiresIv(options.mode()) && !Checks.hasBytes(iv)) {
            iv = generateIv(options.mode());
        }
        return SM4Options.builder()
            .mode(options.mode())
            .padding(options.padding())
            .iv(iv)
            .aad(options.aad())
            .tagLength(options.tagLength())
            .tag(options.tag())
            .securityContext(Checks.defaultIfNull(options.securityContext(), securityContext))
            .build();
    }

    private SM4Options optionsFromPayload(SM2Sm4HybridPayload payload) {
        SM4Options.Builder builder = SM4Options.builder()
            .mode(payload.mode())
            .padding(payload.padding())
            .securityContext(securityContext);
        if (payload.hasIv()) {
            builder.iv(payload.iv());
        }
        if (payload.hasAad()) {
            builder.aad(payload.aad());
        }
        if (payload.hasTag()) {
            builder.tag(payload.tag()).tagLength(payload.tag().length);
        }
        return builder.build();
    }

    private boolean requiresIv(SM4CipherMode mode) {
        return mode != SM4CipherMode.ECB;
    }

    private byte[] generateIv(SM4CipherMode mode) {
        int length = (mode == SM4CipherMode.GCM || mode == SM4CipherMode.CCM) ? AEAD_IV_LENGTH : BLOCK_IV_LENGTH;
        byte[] iv = new byte[length];
        securityContext.secureRandom().nextBytes(iv);
        return iv;
    }
}
