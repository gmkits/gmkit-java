package cn.gmkit.sm4;

import cn.gmkit.core.HexCodec;
import cn.gmkit.core.SM4CipherMode;
import cn.gmkit.core.SM4Padding;
import cn.gmkit.core.Texts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class SM4StandardVectorsTest {

    private static final byte[] KEY = HexCodec.decodeStrict("0123456789abcdeffedcba9876543210", "SM4 key");
    private static final byte[] IV = HexCodec.decodeStrict("000102030405060708090a0b0c0d0e0f", "IV");
    private static final byte[] NONCE_12 = HexCodec.decodeStrict("00112233445566778899aabb", "nonce");
    private final SM4 sm4 = new SM4();

    @Test
    void ecbNoPaddingShouldMatchOfficialVector() {
        byte[] plaintext = HexCodec.decodeStrict("0123456789abcdeffedcba9876543210", "plaintext");

        SM4CipherResult encrypted = sm4.encrypt(
            KEY,
            plaintext,
            SM4Options.builder()
                .mode(SM4CipherMode.ECB)
                .padding(SM4Padding.NONE)
                .build());

        assertEquals("681edf34d206965e86b3e94f536e4246", encrypted.ciphertextHex());
        assertArrayEquals(
            plaintext,
            sm4.decrypt(
                KEY,
                encrypted.ciphertext(),
                SM4Options.builder()
                    .mode(SM4CipherMode.ECB)
                    .padding(SM4Padding.NONE)
                    .build()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("roundTripCases")
    void roundTripShouldCoverMultipleModes(String name, byte[] plaintext, SM4Options options) {
        SM4CipherResult encrypted = sm4.encrypt(KEY, plaintext, options);
        byte[] decrypted = sm4.decrypt(KEY, encrypted, options);

        assertArrayEquals(plaintext, decrypted, name);
        if (options.mode() == SM4CipherMode.GCM || options.mode() == SM4CipherMode.CCM) {
            assertEquals(options.tagLength().intValue(), encrypted.tag().length, name);
        }
    }

    @Test
    void ecbShouldBeDeterministicForSamePlaintextAndKey() {
        SM4Options options = SM4Options.builder()
            .mode(SM4CipherMode.ECB)
            .padding(SM4Padding.PKCS7)
            .build();

        SM4CipherResult left = sm4.encrypt(KEY, Texts.utf8("deterministic"), options);
        SM4CipherResult right = sm4.encrypt(KEY, Texts.utf8("deterministic"), options);

        assertEquals(left.ciphertextHex(), right.ciphertextHex());
    }

    @Test
    void cbcShouldProduceDifferentCiphertextForDifferentIv() {
        byte[] plaintext = Texts.utf8("same plaintext");

        SM4CipherResult left = sm4.encrypt(
            KEY,
            plaintext,
            SM4Options.builder()
                .mode(SM4CipherMode.CBC)
                .padding(SM4Padding.PKCS7)
                .iv(IV)
                .build());
        SM4CipherResult right = sm4.encrypt(
            KEY,
            plaintext,
            SM4Options.builder()
                .mode(SM4CipherMode.CBC)
                .padding(SM4Padding.PKCS7)
                .iv(HexCodec.decodeStrict("0f0e0d0c0b0a09080706050403020100", "IV"))
                .build());

        assertNotEquals(left.ciphertextHex(), right.ciphertextHex());
    }

    private static Stream<Arguments> roundTripCases() {
        return Stream.of(
            Arguments.of(
                "ECB/PKCS7 UTF-8",
                Texts.utf8("hello gmkit"),
                SM4Options.builder()
                    .mode(SM4CipherMode.ECB)
                    .padding(SM4Padding.PKCS7)
                    .build()),
            Arguments.of(
                "CBC/PKCS7 UTF-8",
                Texts.utf8("cbc-pkcs7"),
                SM4Options.builder()
                    .mode(SM4CipherMode.CBC)
                    .padding(SM4Padding.PKCS7)
                    .iv(IV)
                    .build()),
            Arguments.of(
                "CBC/NONE block-aligned",
                HexCodec.decodeStrict("00112233445566778899aabbccddeeff", "plaintext"),
                SM4Options.builder()
                    .mode(SM4CipherMode.CBC)
                    .padding(SM4Padding.NONE)
                    .iv(IV)
                    .build()),
            Arguments.of(
                "CBC/ZERO short input",
                Texts.utf8("zero-padding"),
                SM4Options.builder()
                    .mode(SM4CipherMode.CBC)
                    .padding(SM4Padding.ZERO)
                    .iv(IV)
                    .build()),
            Arguments.of(
                "CTR binary payload",
                HexCodec.decodeStrict("00112233445566778899aabbccddee", "plaintext"),
                SM4Options.builder()
                    .mode(SM4CipherMode.CTR)
                    .padding(SM4Padding.NONE)
                    .iv(IV)
                    .build()),
            Arguments.of(
                "CFB Chinese text",
                Texts.utf8("国密工具"),
                SM4Options.builder()
                    .mode(SM4CipherMode.CFB)
                    .padding(SM4Padding.NONE)
                    .iv(IV)
                    .build()),
            Arguments.of(
                "OFB empty payload",
                new byte[0],
                SM4Options.builder()
                    .mode(SM4CipherMode.OFB)
                    .padding(SM4Padding.NONE)
                    .iv(IV)
                    .build()),
            Arguments.of(
                "GCM with AAD",
                Texts.utf8("authenticated payload"),
                SM4Options.builder()
                    .mode(SM4CipherMode.GCM)
                    .padding(SM4Padding.NONE)
                    .iv(NONCE_12)
                    .aad(Texts.utf8("aad"))
                    .tagLength(16)
                    .build()),
            Arguments.of(
                "CCM with AAD",
                Texts.utf8("ccm payload"),
                SM4Options.builder()
                    .mode(SM4CipherMode.CCM)
                    .padding(SM4Padding.NONE)
                    .iv(NONCE_12)
                    .aad(Texts.utf8("aad"))
                    .tagLength(12)
                    .build()));
    }
}
