package cn.gmkit.sm3;

import cn.gmkit.core.Base64Codec;
import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SM3StandardVectorsTest {

    private final SM3 sm3 = new SM3();

    @Test
    void digestShouldMatchOfficialVectors() {
        assertEquals(
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
            sm3.digestHex(""));
        assertEquals(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            sm3.digestHex("abc"));
        assertEquals(
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
            sm3.digestHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"));
    }

    @Test
    void digestOverloadsShouldRemainConsistent() {
        String text = "国密摘要";
        byte[] bytes = Texts.utf8(text);

        assertArrayEquals(sm3.digest(bytes), sm3.digest(text));
        assertEquals(HexCodec.encode(sm3.digest(bytes)), sm3.digestHex(text));
        assertEquals(Base64Codec.encode(sm3.digest(bytes)), sm3.digestBase64(text));
    }

    @Test
    void hmacOverloadsShouldRemainConsistentAcrossFormats() {
        byte[] key = Texts.utf8("secret-key");
        String message = "hmac-payload";
        byte[] messageBytes = Texts.utf8(message);

        byte[] binary = sm3.hmac(key, messageBytes);
        assertArrayEquals(binary, sm3.hmac(key, message));
        assertEquals(HexCodec.encode(binary), sm3.hmacHex(key, messageBytes));
        assertEquals(HexCodec.encode(binary), sm3.hmacHex(key, message));
        assertEquals(Base64Codec.encode(binary), sm3.hmacBase64(key, messageBytes));
        assertEquals(Base64Codec.encode(binary), sm3.hmacBase64(key, message));
    }

    @Test
    void digestShouldShowAvalancheEffectForSmallInputChange() {
        byte[] left = sm3.digest("abc");
        byte[] right = sm3.digest("abd");

        assertNotEquals(HexCodec.encode(left), HexCodec.encode(right));
        assertTrue(hammingDistance(left, right) > 100);
    }

    @Test
    void multilingualDigestAndHmacShouldSupportExplicitCharset() {
        String text = "Hello 你好 مرحبا Привет 👋";
        byte[] key = Texts.utf8("密钥-key");

        assertEquals(
            HexCodec.encode(sm3.digest(text, StandardCharsets.UTF_16LE)),
            sm3.digestHex(text, StandardCharsets.UTF_16LE));
        assertEquals(
            Base64Codec.encode(sm3.hmac(key, text, StandardCharsets.UTF_16LE)),
            sm3.hmacBase64(key, text, StandardCharsets.UTF_16LE));
    }

    private static int hammingDistance(byte[] left, byte[] right) {
        int distance = 0;
        for (int i = 0; i < left.length; i++) {
            distance += Integer.bitCount((left[i] ^ right[i]) & 0xff);
        }
        return distance;
    }
}
