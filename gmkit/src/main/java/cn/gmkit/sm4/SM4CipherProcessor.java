package cn.gmkit.sm4;

import cn.gmkit.core.*;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

final class SM4CipherProcessor {

    private SM4CipherProcessor() {
    }

    static byte[] generateKey(GmSecurityContext securityContext) {
        try {
            GmSecurityContext resolved = SM4Support.context(securityContext);
            KeyGenerator keyGenerator = KeyGenerator.getInstance(SM4Support.ALGORITHM, resolved.provider());
            keyGenerator.init(SM4Support.DEFAULT_KEY_SIZE, resolved.secureRandom());
            SecretKey key = keyGenerator.generateKey();
            return key.getEncoded();
        } catch (GeneralSecurityException ex) {
            throw new GmkitException("Failed to generate SM4 key: please verify that the configured Provider supports SM4", ex);
        }
    }

    static SM4CipherResult encrypt(byte[] key, byte[] data, SM4Options options) {
        SM4Options resolved = SM4Support.options(options);
        byte[] safeKey = Bytes.requireLength(Bytes.clone(key), SM4Support.BLOCK_SIZE, "SM4 key");
        byte[] prepared = SM4Paddings.apply(data, resolved.mode(), resolved.padding());
        int tagLength = SM4Support.resolveTagLength(resolved.mode(), resolved.tagLength());
        try {
            Cipher cipher = newCipher(Cipher.ENCRYPT_MODE, safeKey, resolved, tagLength);
            byte[] encrypted = cipher.doFinal(prepared);
            return SM4AeadSupport.splitCiphertextAndTag(resolved.mode(), encrypted, tagLength);
        } catch (GeneralSecurityException ex) {
            throw new GmkitException("SM4 encryption failed: please verify the mode, IV/nonce length and Provider configuration", ex);
        }
    }

    static byte[] decrypt(byte[] key, byte[] ciphertext, SM4Options options) {
        SM4Options resolved = SM4Support.options(options);
        byte[] safeKey = Bytes.requireLength(Bytes.clone(key), SM4Support.BLOCK_SIZE, "SM4 key");
        int tagLength = SM4Support.resolveTagLength(resolved.mode(), resolved.tagLength());
        byte[] combined = SM4AeadSupport.appendTagIfNeeded(ciphertext, resolved.tag(), resolved.mode(), tagLength);
        try {
            Cipher cipher = newCipher(Cipher.DECRYPT_MODE, safeKey, resolved, tagLength);
            byte[] decrypted = cipher.doFinal(combined);
            return SM4Paddings.strip(decrypted, resolved.mode(), resolved.padding());
        } catch (GeneralSecurityException ex) {
            throw new GmkitException("SM4 decryption failed: please verify the key, IV/nonce, padding and authentication tag", ex);
        }
    }

    private static Cipher newCipher(int opMode, byte[] key, SM4Options options, int tagLength)
        throws GeneralSecurityException {
        GmSecurityContext securityContext = SM4Support.context(options.securityContext());
        Cipher cipher = Cipher.getInstance(transformation(options.mode(), options.padding()), securityContext.provider());
        SecretKeySpec keySpec = new SecretKeySpec(key, SM4Support.ALGORITHM);
        if (options.mode() == SM4CipherMode.ECB) {
            cipher.init(opMode, keySpec);
            return cipher;
        }
        if (options.mode() == SM4CipherMode.CBC
            || options.mode() == SM4CipherMode.CTR
            || options.mode() == SM4CipherMode.CFB
            || options.mode() == SM4CipherMode.OFB) {
            byte[] iv = Bytes.requireLength(Bytes.clone(options.iv()), SM4Support.BLOCK_SIZE, "IV");
            cipher.init(opMode, keySpec, new IvParameterSpec(iv));
            return cipher;
        }
        if (options.mode() == SM4CipherMode.GCM) {
            byte[] iv = Bytes.requireLength(Bytes.clone(options.iv()), 12, "IV");
            cipher.init(opMode, keySpec, new AEADParameterSpec(iv, tagLength * 8, options.aad()));
            return cipher;
        }
        if (options.mode() == SM4CipherMode.CCM) {
            byte[] nonce = Bytes.clone(options.iv());
            if (nonce == null || nonce.length < 7 || nonce.length > 13) {
                throw new GmkitException("Invalid SM4 CCM nonce length: expected 7 to 13 bytes");
            }
            cipher.init(opMode, keySpec, new AEADParameterSpec(nonce, tagLength * 8, options.aad()));
            return cipher;
        }
        throw new GmkitException("Unsupported SM4 mode: " + options.mode());
    }

    private static String transformation(SM4CipherMode mode, SM4Padding padding) {
        if (mode == SM4CipherMode.GCM || mode == SM4CipherMode.CCM || mode.isStreamLike()) {
            return "SM4/" + mode.name() + "/NoPadding";
        }
        if (padding == SM4Padding.PKCS7) {
            return "SM4/" + mode.name() + "/PKCS5Padding";
        }
        return "SM4/" + mode.name() + "/NoPadding";
    }
}

