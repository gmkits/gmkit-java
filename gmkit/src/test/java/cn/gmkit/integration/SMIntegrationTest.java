package cn.gmkit.integration;

import cn.gmkit.core.*;
import cn.gmkit.sm2.SM2;
import cn.gmkit.sm2.SM2KeyPair;
import cn.gmkit.sm3.SM3;
import cn.gmkit.sm4.SM4;
import cn.gmkit.sm4.SM4CipherResult;
import cn.gmkit.sm4.SM4Options;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SMIntegrationTest {

    @Test
    void sm2ShouldProtectSm4SessionKeyAndSm3ShouldDigestCiphertext() {
        SM2 sm2 = new SM2();
        SM3 sm3 = new SM3();
        SM4 sm4 = new SM4();
        SM2KeyPair sm2KeyPair = sm2.generateKeyPair(false);
        byte[] sm4Key = sm4.generateKey();
        byte[] iv = HexCodec.decodeStrict("000102030405060708090a0b0c0d0e0f", "IV");
        byte[] plaintext = Texts.utf8("跨算法集成回归");

        byte[] wrappedKey = sm2.encrypt(sm2KeyPair.publicKey(), sm4Key, SM2CipherMode.C1C3C2);
        byte[] unwrappedKey = sm2.decrypt(sm2KeyPair.privateKey(), wrappedKey, SM2CipherMode.C1C3C2);
        SM4CipherResult ciphertext = sm4.encrypt(
            sm4Key,
            plaintext,
            SM4Options.builder()
                .mode(SM4CipherMode.CBC)
                .padding(SM4Padding.PKCS7)
                .iv(iv)
                .build());

        String digest = sm3.digestHex(ciphertext.ciphertext());

        assertArrayEquals(sm4Key, unwrappedKey);
        assertArrayEquals(
            plaintext,
            sm4.decrypt(
                unwrappedKey,
                ciphertext,
                SM4Options.builder()
                    .mode(SM4CipherMode.CBC)
                    .padding(SM4Padding.PKCS7)
                    .iv(iv)
                    .build()));
        assertEquals(digest, sm3.digestHex(ciphertext.ciphertext()));
        assertNotEquals(digest, sm3.digestHex(plaintext));
    }
}
