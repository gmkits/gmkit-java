package cn.gmkit.sm3;

import cn.gmkit.core.HexCodec;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SM3StandardVectorsTest {

    private static final String EMPTY_VECTOR =
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";
    private static final String ABC_VECTOR =
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    private static final String LONG_VECTOR =
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

    private final SM3 sm3 = new SM3();

    @Test
    void digestShouldMatchOfficialVectors() {
        assertEquals(EMPTY_VECTOR, sm3.digestHex(""));
        assertEquals(ABC_VECTOR, sm3.digestHex("abc"));
        assertEquals(LONG_VECTOR, sm3.digestHex("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"));
    }

    @Test
    void digestShouldShowAvalancheEffectForSmallInputChange() {
        byte[] left = sm3.digest("abc");
        byte[] right = sm3.digest("abd");

        assertNotEquals(HexCodec.encode(left), HexCodec.encode(right));
        assertTrue(hammingDistance(left, right) > 100);
    }

    private static int hammingDistance(byte[] left, byte[] right) {
        int distance = 0;
        for (int i = 0; i < left.length; i++) {
            distance += Integer.bitCount((left[i] ^ right[i]) & 0xff);
        }
        return distance;
    }
}
