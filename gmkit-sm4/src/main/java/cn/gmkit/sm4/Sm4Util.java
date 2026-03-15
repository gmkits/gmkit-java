package cn.gmkit.sm4;

import cn.gmkit.core.*;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * @author mumu
 * @description SM4加密算法工具类，提供密钥生成、加密和解密功能，支持多种模式和填充方式
 * @since 1.0.0
 */
public final class Sm4Util {

    private static final String ALGORITHM = "SM4";
    private static final int BLOCK_SIZE = 16;
    private static final int DEFAULT_KEY_SIZE = 128;

    private Sm4Util() {
    }

    public static byte[] generateKey() {
        return generateKey(GmSecurityContexts.defaults());
    }

    public static byte[] generateKey(GmSecurityContext securityContext) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, context(securityContext).provider());
            keyGenerator.init(DEFAULT_KEY_SIZE, context(securityContext).secureRandom());
            SecretKey key = keyGenerator.generateKey();
            return key.getEncoded();
        } catch (GeneralSecurityException ex) {
            throw new GmkitException("Failed to generate SM4 key", ex);
        }
    }

    public static String generateKeyHex() {
        return HexCodec.encode(generateKey());
    }

    public static String generateKeyHex(GmSecurityContext securityContext) {
        return HexCodec.encode(generateKey(securityContext));
    }

    public static Sm4CipherResult encryptHex(String keyHex, String data, Sm4Options options) {
        return encrypt(HexCodec.decodeStrict(keyHex, "SM4 key"), Texts.utf8(data), options);
    }

    public static Sm4CipherResult encryptHex(String keyHex, byte[] data, Sm4Options options) {
        return encrypt(HexCodec.decodeStrict(keyHex, "SM4 key"), data, options);
    }

    public static Sm4CipherResult encrypt(byte[] key, byte[] data, Sm4Options options) {
        Sm4Options resolved = options != null ? options : Sm4Options.builder().build();
        byte[] safeKey = Bytes.requireLength(Bytes.clone(key), BLOCK_SIZE, "SM4 key");
        byte[] prepared = applyEncryptPadding(data, resolved.mode(), resolved.padding());
        int tagLength = resolveTagLength(resolved.mode(), resolved.tagLength());
        try {
            Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, safeKey, resolved, tagLength);
            byte[] encrypted = cipher.doFinal(prepared);
            return splitCiphertextAndTag(resolved.mode(), encrypted, tagLength);
        } catch (GeneralSecurityException ex) {
            throw new GmkitException("SM4 encryption failed", ex);
        }
    }

    public static byte[] decryptHex(String keyHex, String ciphertextHex, Sm4DecryptOptions options) {
        return decrypt(
            HexCodec.decodeStrict(keyHex, "SM4 key"),
            HexCodec.decodeStrict(ciphertextHex, "ciphertext"),
            options);
    }

    public static String decryptToUtf8(byte[] key, byte[] ciphertext, Sm4DecryptOptions options) {
        return Texts.utf8(decrypt(key, ciphertext, options));
    }

    public static String decryptToUtf8(byte[] key, Sm4CipherResult result, Sm4DecryptOptions options) {
        return Texts.utf8(decrypt(key, result, options));
    }

    public static byte[] decrypt(byte[] key, Sm4CipherResult result, Sm4DecryptOptions options) {
        byte[] tag = result.tag();
        Sm4DecryptOptions resolved = mergeTag(options, tag);
        return decrypt(key, result.ciphertext(), resolved);
    }

    public static byte[] decrypt(byte[] key, byte[] ciphertext, Sm4DecryptOptions options) {
        Sm4DecryptOptions resolved = options != null ? options : Sm4DecryptOptions.builder().build();
        byte[] safeKey = Bytes.requireLength(Bytes.clone(key), BLOCK_SIZE, "SM4 key");
        int tagLength = resolveTagLength(resolved.mode(), resolved.tagLength());
        byte[] combined = appendTagIfNeeded(ciphertext, resolved.tag(), resolved.mode(), tagLength);
        try {
            Cipher cipher = newCipher(Cipher.DECRYPT_MODE, safeKey, resolved, tagLength);
            byte[] decrypted = cipher.doFinal(combined);
            return stripDecryptPadding(decrypted, resolved.mode(), resolved.padding());
        } catch (GeneralSecurityException ex) {
            throw new GmkitException("SM4 decryption failed", ex);
        }
    }

    private static Sm4DecryptOptions mergeTag(Sm4DecryptOptions options, byte[] tag) {
        if (tag == null || tag.length == 0) {
            return options != null ? options : Sm4DecryptOptions.builder().build();
        }
        Sm4DecryptOptions.Builder builder = Sm4DecryptOptions.builder()
            .mode(options != null ? options.mode() : null)
            .padding(options != null ? options.padding() : null)
            .iv(options != null ? options.iv() : null)
            .aad(options != null ? options.aad() : null)
            .tagLength(options != null ? options.tagLength() : null)
            .securityContext(options != null ? options.securityContext() : null)
            .tag(tag);
        return builder.build();
    }

    private static GmSecurityContext context(GmSecurityContext securityContext) {
        return securityContext != null ? securityContext : GmSecurityContexts.defaults();
    }

    private static Cipher newCipher(int opMode, byte[] key, Sm4Options options, int tagLength)
        throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(transformation(options.mode(), options.padding()), context(options.securityContext()).provider());
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        if (options.mode() == Sm4CipherMode.ECB) {
            cipher.init(opMode, keySpec);
            return cipher;
        }
        if (options.mode() == Sm4CipherMode.CBC
            || options.mode() == Sm4CipherMode.CTR
            || options.mode() == Sm4CipherMode.CFB
            || options.mode() == Sm4CipherMode.OFB) {
            byte[] iv = Bytes.requireLength(Bytes.clone(options.iv()), BLOCK_SIZE, "IV");
            cipher.init(opMode, keySpec, new IvParameterSpec(iv));
            return cipher;
        }
        if (options.mode() == Sm4CipherMode.GCM) {
            byte[] iv = Bytes.requireLength(Bytes.clone(options.iv()), 12, "IV");
            cipher.init(opMode, keySpec, new AEADParameterSpec(iv, tagLength * 8, options.aad()));
            return cipher;
        }
        if (options.mode() == Sm4CipherMode.CCM) {
            byte[] nonce = Bytes.clone(options.iv());
            if (nonce == null || nonce.length < 7 || nonce.length > 13) {
                throw new GmkitException("Nonce must be 7-13 bytes for CCM mode");
            }
            cipher.init(opMode, keySpec, new AEADParameterSpec(nonce, tagLength * 8, options.aad()));
            return cipher;
        }
        throw new GmkitException("Unsupported SM4 mode: " + options.mode());
    }

    private static String transformation(Sm4CipherMode mode, Sm4Padding padding) {
        if (mode == Sm4CipherMode.GCM || mode == Sm4CipherMode.CCM || mode.isStreamLike()) {
            return "SM4/" + mode.name() + "/NoPadding";
        }
        if (padding == Sm4Padding.PKCS7) {
            return "SM4/" + mode.name() + "/PKCS5Padding";
        }
        return "SM4/" + mode.name() + "/NoPadding";
    }

    private static byte[] applyEncryptPadding(byte[] data, Sm4CipherMode mode, Sm4Padding padding) {
        byte[] source = Bytes.clone(data);
        if (mode.isStreamLike()) {
            return source;
        }
        if (padding == Sm4Padding.NONE) {
            requireBlockMultiple(source.length, "Plaintext");
            return source;
        }
        if (padding == Sm4Padding.ZERO) {
            if (source.length == 0 || source.length % BLOCK_SIZE == 0) {
                return source;
            }
            byte[] padded = new byte[((source.length / BLOCK_SIZE) + 1) * BLOCK_SIZE];
            System.arraycopy(source, 0, padded, 0, source.length);
            return padded;
        }
        return source;
    }

    private static byte[] stripDecryptPadding(byte[] data, Sm4CipherMode mode, Sm4Padding padding) {
        if (mode.isStreamLike() || padding != Sm4Padding.ZERO) {
            return data;
        }
        int end = data.length;
        while (end > 0 && data[end - 1] == 0) {
            end--;
        }
        if (end == data.length) {
            return data;
        }
        byte[] trimmed = new byte[end];
        System.arraycopy(data, 0, trimmed, 0, end);
        return trimmed;
    }

    private static void requireBlockMultiple(int length, String label) {
        if (length % BLOCK_SIZE != 0) {
            throw new GmkitException(label + " length must be a multiple of 16 bytes");
        }
    }

    private static Sm4CipherResult splitCiphertextAndTag(Sm4CipherMode mode, byte[] encrypted, int tagLength) {
        if (mode != Sm4CipherMode.GCM && mode != Sm4CipherMode.CCM) {
            return new Sm4CipherResult(encrypted, null);
        }
        if (encrypted.length < tagLength) {
            throw new GmkitException("Encrypted output is shorter than requested tag length");
        }
        int cipherLength = encrypted.length - tagLength;
        byte[] ciphertext = new byte[cipherLength];
        byte[] tag = new byte[tagLength];
        System.arraycopy(encrypted, 0, ciphertext, 0, cipherLength);
        System.arraycopy(encrypted, cipherLength, tag, 0, tagLength);
        return new Sm4CipherResult(ciphertext, tag);
    }

    private static byte[] appendTagIfNeeded(byte[] ciphertext, byte[] tag, Sm4CipherMode mode, int tagLength) {
        if (mode != Sm4CipherMode.GCM && mode != Sm4CipherMode.CCM) {
            return Bytes.clone(ciphertext);
        }
        if (tag == null || tag.length == 0) {
            throw new GmkitException(mode.name() + " mode requires authentication tag");
        }
        if (tag.length != tagLength) {
            throw new GmkitException("Authentication tag length must be " + tagLength + " bytes for " + mode.name() + " mode");
        }
        return Bytes.concat(ciphertext, tag);
    }

    private static int resolveTagLength(Sm4CipherMode mode, Integer configuredTagLength) {
        if (mode == Sm4CipherMode.GCM) {
            int resolved = configuredTagLength != null ? configuredTagLength : 16;
            if (resolved < 12 || resolved > 16) {
                throw new GmkitException("GCM tag length must be between 12 and 16 bytes");
            }
            return resolved;
        }
        if (mode == Sm4CipherMode.CCM) {
            int resolved = configuredTagLength != null ? configuredTagLength : 16;
            if (resolved < 4 || resolved > 16 || (resolved & 1) != 0) {
                throw new GmkitException("CCM tag length must be an even value between 4 and 16 bytes");
            }
            return resolved;
        }
        return 0;
    }
}

