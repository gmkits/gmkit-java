package cn.gmkit.sm3;

import cn.gmkit.core.Checks;
import cn.gmkit.core.GmkitException;
import cn.gmkit.core.Messages;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public final class SM3Support {

    private SM3Support() {
    }

    public static byte[] digest(byte[] data) {
        Checks.requireNonNull(data, "SM3 input");
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] output = new byte[SM3.DIGEST_LENGTH];
        digest.doFinal(output, 0);
        return output;
    }

    public static byte[] hmac(byte[] key, byte[] data) {
        if (key == null || data == null) {
            throw new GmkitException(Messages.bilingual(
                "SM3 HMAC 密钥和输入都不能为空",
                "SM3 HMAC key and input must not be null"));
        }
        HMac hmac = new HMac(new SM3Digest());
        hmac.init(new KeyParameter(key));
        hmac.update(data, 0, data.length);
        byte[] output = new byte[SM3.DIGEST_LENGTH];
        hmac.doFinal(output, 0);
        return output;
    }
}
