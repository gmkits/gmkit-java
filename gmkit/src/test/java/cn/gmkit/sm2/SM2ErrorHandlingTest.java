package cn.gmkit.sm2;

import cn.gmkit.core.GmkitException;
import cn.gmkit.core.SM2CipherMode;
import cn.gmkit.core.SM2SignatureInputFormat;
import cn.gmkit.core.Texts;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SM2ErrorHandlingTest {

    private final SM2 sm2 = new SM2();

    @Test
    void shouldRejectOddLengthPrivateKeyHex() {
        GmkitException exception = assertThrows(
            GmkitException.class,
            () -> sm2.getPublicKeyFromPrivateKey("abc", false));

        assertEquals("Invalid private key: hexadecimal strings must have an even length", exception.getMessage());
    }

    @Test
    void shouldRejectInvalidPublicKeyPrefix() {
        String invalidPrefixKey = "05609EA50E3212338AB9074492175300724BA2ACEC5DADAA26A0188CE426BE5769"
            + "7D5C8ECDA528D93EA689D5F4975508694299129C1AE6B2D10B11E9BE0CEF8C1B";
        GmkitException exception = assertThrows(
            GmkitException.class,
            () -> sm2.compressPublicKey(invalidPrefixKey));

        assertEquals("Invalid public key prefix: must be 02, 03, or 04", exception.getMessage());
    }

    @Test
    void decryptShouldRejectOddLengthCiphertextStringInsteadOfTreatingItAsBase64() {
        SM2KeyPair keyPair = sm2.generateKeyPair(false);

        GmkitException exception = assertThrows(
            GmkitException.class,
            () -> sm2.decrypt(keyPair.privateKey(), "0xabc", SM2CipherMode.C1C3C2));

        assertEquals("Invalid ciphertext: hexadecimal strings must have an even length", exception.getMessage());
    }

    @Test
    void decryptShouldRejectMalformedAsn1Ciphertext() {
        SM2KeyPair keyPair = sm2.generateKeyPair(false);
        byte[] malformed = new byte[]{0x30, 0x03, 0x02, 0x01, 0x01};

        GmkitException exception = assertThrows(
            GmkitException.class,
            () -> sm2.decrypt(keyPair.privateKey(), malformed, SM2CipherMode.C1C3C2));

        assertTrue(exception.getMessage().contains("ASN.1"));
    }

    @Test
    void verifyShouldReturnFalseForMalformedSignature() {
        SM2KeyPair keyPair = sm2.generateKeyPair(false);

        assertFalse(sm2.verify(
            keyPair.publicKey(),
            Texts.utf8("hello"),
            new byte[10],
            SM2VerifyOptions.builder()
                .signatureFormat(SM2SignatureInputFormat.RAW)
                .build()));
    }

    @Test
    void verifyShouldReturnFalseWithWrongPublicKey() {
        SM2KeyPair signer = sm2.generateKeyPair(false);
        SM2KeyPair verifier = sm2.generateKeyPair(false);
        byte[] message = Texts.utf8("wrong-public-key");
        byte[] signature = sm2.sign(signer.privateKey(), message);

        assertFalse(sm2.verify(verifier.publicKey(), message, signature));
    }

    @Test
    void signShouldRejectNullMessage() {
        SM2KeyPair keyPair = sm2.generateKeyPair(false);

        GmkitException exception = assertThrows(
            GmkitException.class,
            () -> sm2.sign(keyPair.privateKey(), null));

        assertEquals("SM2 message must not be null", exception.getMessage());
    }

    @Test
    void decryptShouldRejectShortCiphertext() {
        SM2KeyPair keyPair = sm2.generateKeyPair(false);

        GmkitException exception = assertThrows(
            GmkitException.class,
            () -> sm2.decrypt(keyPair.privateKey(), new byte[10], SM2CipherMode.C1C3C2));

        assertTrue(exception.getMessage().contains("expected raw C1||C3||C2"));
    }
}
