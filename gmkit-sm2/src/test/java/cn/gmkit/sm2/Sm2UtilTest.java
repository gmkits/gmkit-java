package cn.gmkit.sm2;

import cn.gmkit.core.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Sm2UtilTest {

    @Test
    void compressAndDecompressShouldRoundTrip() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        String compressed = Sm2Util.compressPublicKey(keyPair.publicKey());
        String decompressed = Sm2Util.decompressPublicKey(compressed);

        assertTrue(compressed.startsWith("02") || compressed.startsWith("03"));
        assertEquals(keyPair.publicKey(), decompressed);
    }

    @Test
    void signAndVerifyShouldSupportRawAndDer() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        byte[] message = Texts.utf8("gmkit-java-sm2");

        byte[] rawSignature = Sm2Util.sign(
            keyPair.privateKey(),
            message,
            Sm2SignOptions.builder()
                .signatureFormat(Sm2SignatureFormat.RAW)
                .build());
        byte[] derSignature = Sm2Util.sign(
            keyPair.privateKey(),
            message,
            Sm2SignOptions.builder()
                .signatureFormat(Sm2SignatureFormat.DER)
                .userId("")
                .build());

        assertTrue(Sm2Util.verify(
            keyPair.publicKey(),
            message,
            rawSignature,
            Sm2VerifyOptions.builder()
                .signatureFormat(Sm2SignatureInputFormat.RAW)
                .build()));
        assertTrue(Sm2Util.verify(
            keyPair.publicKey(),
            message,
            derSignature,
            Sm2VerifyOptions.builder()
                .signatureFormat(Sm2SignatureInputFormat.DER)
                .userId("")
                .build()));
    }

    @Test
    void signAndVerifyShouldSupportSkipZ() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        byte[] message = Texts.utf8("skip-z");

        byte[] signature = Sm2Util.sign(
            keyPair.privateKey(),
            message,
            Sm2SignOptions.builder()
                .skipZComputation(true)
                .build());

        assertTrue(Sm2Util.verify(
            keyPair.publicKey(),
            message,
            signature,
            Sm2VerifyOptions.builder()
                .skipZComputation(true)
                .signatureFormat(Sm2SignatureInputFormat.RAW)
                .build()));
        assertFalse(Sm2Util.verify(
            keyPair.publicKey(),
            message,
            signature,
            Sm2VerifyOptions.builder()
                .skipZComputation(false)
                .signatureFormat(Sm2SignatureInputFormat.RAW)
                .build()));
    }

    @Test
    void encryptAndDecryptShouldSupportBothLayouts() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        byte[] plaintext = Texts.utf8("layout-compatibility");

        byte[] c1c3c2 = Sm2Util.encrypt(
            keyPair.publicKey(),
            plaintext,
            Sm2EncryptOptions.builder()
                .mode(Sm2CipherMode.C1C3C2)
                .build());
        byte[] c1c2c3 = Sm2Util.encrypt(
            keyPair.publicKey(),
            plaintext,
            Sm2EncryptOptions.builder()
                .mode(Sm2CipherMode.C1C2C3)
                .build());

        assertArrayEquals(
            plaintext,
            Sm2Util.decrypt(keyPair.privateKey(), c1c3c2, Sm2DecryptOptions.builder().mode(Sm2CipherMode.C1C3C2).build()));
        assertArrayEquals(
            plaintext,
            Sm2Util.decrypt(keyPair.privateKey(), c1c2c3, Sm2DecryptOptions.builder().mode(Sm2CipherMode.C1C2C3).build()));
        assertNotEquals(HexCodec.encode(c1c3c2), HexCodec.encode(c1c2c3));
    }

    @Test
    void ciphertextDerCodecShouldRoundTrip() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        byte[] ciphertext = Sm2Util.encrypt(
            keyPair.publicKey(),
            Texts.utf8("der-roundtrip"),
            Sm2EncryptOptions.builder().build());

        byte[] der = Sm2Ciphertexts.encodeDer(ciphertext, Sm2CipherMode.C1C3C2);
        byte[] restored = Sm2Ciphertexts.decodeDer(der, Sm2CipherMode.C1C3C2);

        assertArrayEquals(ciphertext, restored);
    }

    @Test
    void signatureCodecShouldRoundTripBetweenDerAndRaw() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        byte[] signature = Sm2Util.sign(
            keyPair.privateKey(),
            Texts.utf8("codec"),
            Sm2SignOptions.builder().signatureFormat(Sm2SignatureFormat.DER).build());

        byte[] raw = Sm2Signatures.derToRaw(signature);
        byte[] restored = Sm2Signatures.rawToDer(raw);

        assertArrayEquals(signature, restored);
    }

    @Test
    void signDigestShouldSupportDirectEInput() {
        Sm2KeyPair keyPair = Sm2Util.generateKeyPair(false);
        byte[] directE = Texts.utf8("abc");
        byte[] rawSignature = Sm2Util.signDigest(keyPair.privateKey(), directE, Sm2SignatureFormat.RAW);

        assertTrue(Sm2Util.verifyDigest(keyPair.publicKey(), directE, Sm2Signatures.rawToDer(rawSignature)));
        assertFalse(Sm2Util.verifyWithoutZ(keyPair.publicKey(), directE, rawSignature, Sm2SignatureInputFormat.RAW));
    }

    @Test
    void cryptToolsVectorsShouldDifferentiateWithZAndDirectE() {
        byte[] message = HexCodec.decodeStrict("616263", "message");
        String publicKey = "04609EA50E3212338AB9074492175300724BA2ACEC5DADAA26A0188CE426BE5769"
            + "7D5C8ECDA528D93EA689D5F4975508694299129C1AE6B2D10B11E9BE0CEF8C1B";
        byte[] withZSignature = HexCodec.decodeStrict(
            "44A6DDC9492AA9C16EA85FF4BC618F35AAF71D5599264E291AD3D4122FFE645B"
                + "18148DF631C2F3125A347D4C37123005DC5333707CA9DF48FD47FB9CC267DC7E",
            "withZSignature");
        byte[] directESignature = HexCodec.decodeStrict(
            "68E99D2487389A8F28483225B7119455951B937B1E9A9DDF61A77D96501AD6C9"
                + "9C4030684DA568D9D37CA10ACA7CA77F7D389C2E46630720B56323BF7B1A2E4B",
            "directESignature");

        assertTrue(Sm2Util.verify(
            publicKey,
            message,
            withZSignature,
            Sm2VerifyOptions.builder()
                .userId(Sm2Util.LEGACY_USER_ID)
                .signatureFormat(Sm2SignatureInputFormat.RAW)
                .build()));
        assertFalse(Sm2Util.verifyWithoutZ(publicKey, message, withZSignature, Sm2SignatureInputFormat.RAW));

        assertFalse(Sm2Util.verify(
            publicKey,
            message,
            directESignature,
            Sm2VerifyOptions.builder()
                .userId(Sm2Util.LEGACY_USER_ID)
                .signatureFormat(Sm2SignatureInputFormat.RAW)
                .build()));
        assertFalse(Sm2Util.verifyWithoutZ(publicKey, message, directESignature, Sm2SignatureInputFormat.RAW));
        assertFalse(Sm2Util.verifyDigest(
            publicKey,
            Sm2Util.computeEWithoutZ(message),
            Sm2Signatures.rawToDer(directESignature)));
        assertTrue(Sm2Util.verifyDigest(publicKey, message, Sm2Signatures.rawToDer(directESignature)));
    }

    @Test
    void keyExchangeShouldDeriveSameSharedSecretAndConfirmTags() {
        Sm2KeyPair initiatorStatic = Sm2Util.generateKeyPair(false);
        Sm2KeyPair initiatorEphemeral = Sm2Util.generateKeyPair(false);
        Sm2KeyPair responderStatic = Sm2Util.generateKeyPair(false);
        Sm2KeyPair responderEphemeral = Sm2Util.generateKeyPair(false);

        byte[] initiatorKey = Sm2Util.keyExchange(
            initiatorStatic.privateKey(),
            initiatorEphemeral.privateKey(),
            responderStatic.publicKey(),
            responderEphemeral.publicKey(),
            Sm2KeyExchangeOptions.builder()
                .initiator(true)
                .keyBits(128)
                .selfId("ABCDEFG1234")
                .peerId("1234567ABCD")
                .build());
        byte[] responderKey = Sm2Util.keyExchange(
            responderStatic.privateKey(),
            responderEphemeral.privateKey(),
            initiatorStatic.publicKey(),
            initiatorEphemeral.publicKey(),
            Sm2KeyExchangeOptions.builder()
                .initiator(false)
                .keyBits(128)
                .selfId("1234567ABCD")
                .peerId("ABCDEFG1234")
                .build());

        assertArrayEquals(initiatorKey, responderKey);

        Sm2KeyExchangeResult responderResult = Sm2Util.keyExchangeWithConfirmation(
            responderStatic.privateKey(),
            responderEphemeral.privateKey(),
            initiatorStatic.publicKey(),
            initiatorEphemeral.publicKey(),
            Sm2KeyExchangeOptions.builder()
                .initiator(false)
                .keyBits(128)
                .selfId("1234567ABCD")
                .peerId("ABCDEFG1234")
                .build());
        Sm2KeyExchangeResult initiatorResult = Sm2Util.keyExchangeWithConfirmation(
            initiatorStatic.privateKey(),
            initiatorEphemeral.privateKey(),
            responderStatic.publicKey(),
            responderEphemeral.publicKey(),
            Sm2KeyExchangeOptions.builder()
                .initiator(true)
                .keyBits(128)
                .selfId("ABCDEFG1234")
                .peerId("1234567ABCD")
                .confirmationTag(responderResult.s1())
                .build());

        assertArrayEquals(responderResult.key(), initiatorResult.key());
        assertTrue(Sm2Util.confirmResponder(responderResult.s2(), initiatorResult.s2()));
    }

    @Test
    void objectStyleApiShouldEncryptSignAndSkipZ() {
        Sm2 sm2 = Sm2.generate();
        byte[] message = Texts.utf8("object-api");

        byte[] ciphertext = sm2.encrypt(message, Sm2EncryptOptions.builder().build());
        byte[] signature = sm2.signWithoutZ(message, Sm2SignatureFormat.RAW);

        assertArrayEquals(message, sm2.decrypt(ciphertext, Sm2DecryptOptions.builder().build()));
        assertTrue(sm2.verifyWithoutZ(message, signature, Sm2SignatureInputFormat.RAW));
    }
}

