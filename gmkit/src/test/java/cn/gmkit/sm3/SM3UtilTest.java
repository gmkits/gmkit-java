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
            SM3Util.digestHex("abc"));
    }

    @Test
    void hmacOverloadsShouldStayConsistent() {
        byte[] key = Texts.utf8("secret");
        byte[] binary = SM3Util.hmac(key, Texts.utf8("hello"));
        byte[] text = SM3Util.hmac(key, "hello");

        assertArrayEquals(binary, text);
        assertEquals(32, binary.length);
        assertNotEquals(HexCodec.encode(SM3Util.digest("hello")), HexCodec.encode(binary));
    }

    @Test
    void utilAliasShouldRemainUsable() {
        SM3 sm3 = new SM3();
        assertEquals(
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
            SM3Util.digestHex("abc"));
        assertArrayEquals(sm3.hmac(Texts.utf8("secret"), "hello"), SM3Util.hmac(Texts.utf8("secret"), "hello"));
    }

    @Test
    void gmkitxStyleAliasesShouldMatchExistingApis() {
        byte[] key = Texts.utf8("secret");

        assertArrayEquals(SM3Util.digest("abc"), SM3Util.sm3Digest("abc"));
        assertArrayEquals(SM3Util.hmac(key, "hello"), SM3Util.sm3Hmac(key, "hello"));
    }
}
