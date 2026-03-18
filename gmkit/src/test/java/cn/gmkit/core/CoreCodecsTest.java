package cn.gmkit.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CoreCodecsTest {

    @Test
    void strictHexShouldRejectOddLength() {
        assertThrows(GmkitException.class, () -> HexCodec.decodeStrict("abc", "test"));
    }

    @Test
    void autoDecodeShouldPreferHexBeforeBase64() {
        byte[] decoded = ByteEncodings.decodeAuto("616263", "test");
        assertArrayEquals(Texts.utf8("abc"), decoded);
    }
}

