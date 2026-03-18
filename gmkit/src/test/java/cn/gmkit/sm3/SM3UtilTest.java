package cn.gmkit.sm3;

import cn.gmkit.core.HexCodec;
import cn.gmkit.core.Texts;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SM3UtilTest {

    @Test
    void digestShouldMatchKnownVector() {
        assertEquals(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            SM3.digestHex("abc"));
    }

    @Test
    void hmacOverloadsShouldStayConsistent() {
        byte[] key = Texts.utf8("secret");
        byte[] binary = SM3.hmac(key, Texts.utf8("hello"));
        byte[] text = SM3.hmac(key, "hello");

        assertArrayEquals(binary, text);
        assertEquals(32, binary.length);
        assertNotEquals(HexCodec.encode(SM3.digest("hello")), HexCodec.encode(binary));
    }

    @Test
    void utilAliasShouldRemainUsable() {
        assertEquals(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            SM3Util.digestHex("abc"));
        assertArrayEquals(SM3.hmac(Texts.utf8("secret"), "hello"), SM3Util.hmac(Texts.utf8("secret"), "hello"));
    }
}

