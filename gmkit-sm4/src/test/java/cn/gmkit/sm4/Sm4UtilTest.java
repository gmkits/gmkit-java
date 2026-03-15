package cn.gmkit.sm4;

import cn.gmkit.core.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Sm4UtilTest {

    private static final byte[] KEY = HexCodec.decodeStrict("0123456789abcdeffedcba9876543210", "SM4 key");
    private static final byte[] IV = HexCodec.decodeStrict("000102030405060708090a0b0c0d0e0f", "IV");

    @Test
    void cbcPkcs7ShouldRoundTrip() {
        Sm4CipherResult encrypted = Sm4Util.encrypt(
            KEY,
            Texts.utf8("hello gmkit-java"),
            Sm4Options.builder()
                .mode(Sm4CipherMode.CBC)
                .padding(Sm4Padding.PKCS7)
                .iv(IV)
                .build());

        byte[] decrypted = Sm4Util.decrypt(
            KEY,
            encrypted,
            Sm4DecryptOptions.builder()
                .mode(Sm4CipherMode.CBC)
                .padding(Sm4Padding.PKCS7)
                .iv(IV)
                .build());

        assertEquals("hello gmkit-java", Texts.utf8(decrypted));
    }

    @Test
    void gcmShouldRoundTripWithAad() {
        byte[] aad = Texts.utf8("metadata");
        byte[] gcmIv = HexCodec.decodeStrict("00112233445566778899aabb", "IV");

        Sm4CipherResult encrypted = Sm4Util.encrypt(
            KEY,
            Texts.utf8("aead payload"),
            Sm4Options.builder()
                .mode(Sm4CipherMode.GCM)
                .iv(gcmIv)
                .aad(aad)
                .tagLength(16)
                .build());

        assertNotNull(encrypted.tag());
        assertEquals(16, encrypted.tag().length);

        byte[] decrypted = Sm4Util.decrypt(
            KEY,
            encrypted,
            Sm4DecryptOptions.builder()
                .mode(Sm4CipherMode.GCM)
                .iv(gcmIv)
                .aad(aad)
                .tagLength(16)
                .build());

        assertArrayEquals(Texts.utf8("aead payload"), decrypted);
    }

    @Test
    void gcmShouldRejectTruncatedTag() {
        byte[] aad = Texts.utf8("metadata");
        byte[] gcmIv = HexCodec.decodeStrict("00112233445566778899aabb", "IV");

        Sm4CipherResult encrypted = Sm4Util.encrypt(
            KEY,
            Texts.utf8("aead payload"),
            Sm4Options.builder()
                .mode(Sm4CipherMode.GCM)
                .iv(gcmIv)
                .aad(aad)
                .build());

        byte[] truncatedTag = new byte[12];
        System.arraycopy(encrypted.tag(), 0, truncatedTag, 0, truncatedTag.length);

        assertThrows(
            GmkitException.class,
            () -> Sm4Util.decrypt(
                KEY,
                encrypted.ciphertext(),
                Sm4DecryptOptions.builder()
                    .mode(Sm4CipherMode.GCM)
                    .iv(gcmIv)
                    .aad(aad)
                    .tagLength(16)
                    .tag(truncatedTag)
                    .build()));
    }

    @Test
    void objectStyleApiShouldRoundTrip() {
        Sm4 sm4 = new Sm4(KEY);
        Sm4CipherResult encrypted = sm4.encrypt(
            "object-api",
            Sm4Options.builder()
                .mode(Sm4CipherMode.CBC)
                .padding(Sm4Padding.PKCS7)
                .iv(IV)
                .build());

        assertEquals(
            "object-api",
            sm4.decryptToUtf8(
                encrypted,
                Sm4DecryptOptions.builder()
                    .mode(Sm4CipherMode.CBC)
                    .padding(Sm4Padding.PKCS7)
                    .iv(IV)
                    .build()));
    }
}

