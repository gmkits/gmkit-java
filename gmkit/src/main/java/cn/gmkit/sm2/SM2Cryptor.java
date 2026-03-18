package cn.gmkit.sm2;

import cn.gmkit.core.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

final class SM2Cryptor {

    private SM2Cryptor() {
    }

    static byte[] encrypt(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        ECPublicKeyParameters publicKey = SM2KeyOps.toPublicKeyParameters(publicKeyHex);
        SM2Engine engine = new SM2Engine(SM2Domain.cipherMode(mode).toBcMode());
        CipherParameters parameters = new ParametersWithRandom(publicKey, SM2Domain.context(securityContext).secureRandom());
        try {
            engine.init(true, parameters);
            return engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException ex) {
            throw new GmkitException("SM2 encryption failed", ex);
        }
    }

    static String encryptHex(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return HexCodec.encode(encrypt(publicKeyHex, data, mode, securityContext));
    }

    static String encryptBase64(String publicKeyHex, byte[] data, SM2CipherMode mode, GmSecurityContext securityContext) {
        return Base64Codec.encode(encrypt(publicKeyHex, data, mode, securityContext));
    }

    static byte[] decrypt(String privateKeyHex, byte[] ciphertext, SM2CipherMode mode) {
        ECPrivateKeyParameters privateKey = SM2KeyOps.toPrivateKeyParameters(privateKeyHex);
        byte[] normalizedCiphertext = SM2Ciphertexts.decodeAuto(ciphertext, mode);
        SM2Engine engine = new SM2Engine(SM2Domain.cipherMode(mode).toBcMode());
        try {
            engine.init(false, privateKey);
            return engine.processBlock(normalizedCiphertext, 0, normalizedCiphertext.length);
        } catch (InvalidCipherTextException ex) {
            throw new GmkitException("SM2 decryption failed: please confirm the private key, ciphertext layout and ASN.1/RAW encoding", ex);
        }
    }

    static byte[] decrypt(String privateKeyHex, String ciphertext, SM2CipherMode mode) {
        return decrypt(privateKeyHex, ByteEncodings.decodeAuto(ciphertext, "ciphertext"), mode);
    }
}

