package cn.gmkit.sm3;

import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Sm3UtilTest {

    @Test
    void digestShouldMatchKnownVector() {
        assertEquals(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            Sm3Util.digestHex("abc"));
    }

    @Test
    void hmacOverloadsShouldStayConsistent() {
        byte[] key = Texts.utf8("secret");
        byte[] binary = Sm3Util.hmac(key, Texts.utf8("hello"));
        byte[] text = Sm3Util.hmac(key, "hello");

        assertArrayEquals(binary, text);
        assertEquals(32, binary.length);
        assertNotEquals(HexCodec.encode(Sm3Util.digest("hello")), HexCodec.encode(binary));
    }

    @Test
    void objectStyleApiShouldWorkForDigestAndHmac() {
        Sm3 digest = new Sm3();
        Sm3 hmac = new Sm3(Texts.utf8("secret"));

        assertEquals(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            digest.digestHex("abc"));
        assertArrayEquals(Sm3Util.hmac(Texts.utf8("secret"), "hello"), hmac.hmac("hello"));
    }
}

