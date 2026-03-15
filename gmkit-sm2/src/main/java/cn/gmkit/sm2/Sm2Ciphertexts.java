package cn.gmkit.sm2;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.GmkitException;
import cn.gmkit.core.Sm2CipherMode;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author mumu
 * @description SM2密文格式转换工具类
 * @since 1.0.0
 */
public final class Sm2Ciphertexts {

    private Sm2Ciphertexts() {
    }

    /**
     * 解析SM2密文数据
     *
     * @param ciphertext 密文字节数组
     * @param mode       密文排列模式
     * @return SM2密文对象
     * @throws GmkitException 如果密文格式无效
     */
    public static Sm2Ciphertext parse(byte[] ciphertext, Sm2CipherMode mode) {
        if (ciphertext == null || ciphertext.length < 97) {
            throw new GmkitException("Invalid SM2 ciphertext: too short");
        }
        if (ciphertext[0] != 0x04) {
            throw new GmkitException("Invalid SM2 ciphertext: only uncompressed C1 is supported");
        }
        int c1Length = 1 + Sm2Util.CURVE_LENGTH * 2;
        int c3Length = Sm2Util.SM3_DIGEST_LENGTH;
        if (ciphertext.length < c1Length + c3Length) {
            throw new GmkitException("Invalid SM2 ciphertext: too short");
        }
        byte[] c1 = Bytes.copyOfRange(ciphertext, 0, c1Length);
        byte[] c2;
        byte[] c3;
        if (mode == Sm2CipherMode.C1C3C2) {
            c3 = Bytes.copyOfRange(ciphertext, c1Length, c1Length + c3Length);
            c2 = Bytes.copyOfRange(ciphertext, c1Length + c3Length, ciphertext.length);
        } else {
            c2 = Bytes.copyOfRange(ciphertext, c1Length, ciphertext.length - c3Length);
            c3 = Bytes.copyOfRange(ciphertext, ciphertext.length - c3Length, ciphertext.length);
        }
        return new Sm2Ciphertext(c1, c2, c3, mode);
    }

    /**
     * 将密文编码为DER格式
     *
     * @param ciphertext 原始密文字节数组
     * @param mode       密文排列模式
     * @return DER编码的密文
     * @throws GmkitException 如果编码失败
     */
    public static byte[] encodeDer(byte[] ciphertext, Sm2CipherMode mode) {
        Sm2Ciphertext parsed = parse(ciphertext, mode);
        byte[] c1 = parsed.c1();
        byte[] c1x = Bytes.copyOfRange(c1, 1, 1 + Sm2Util.CURVE_LENGTH);
        byte[] c1y = Bytes.copyOfRange(c1, 1 + Sm2Util.CURVE_LENGTH, c1.length);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new BigInteger(1, c1x)));
        vector.add(new ASN1Integer(new BigInteger(1, c1y)));
        if (mode == Sm2CipherMode.C1C3C2) {
            vector.add(new DEROctetString(parsed.c3()));
            vector.add(new DEROctetString(parsed.c2()));
        } else {
            vector.add(new DEROctetString(parsed.c2()));
            vector.add(new DEROctetString(parsed.c3()));
        }
        try {
            return new DERSequence(vector).getEncoded();
        } catch (IOException ex) {
            throw new GmkitException("Failed to DER-encode SM2 ciphertext", ex);
        }
    }

    /**
     * 将DER格式的密文解码为原始格式
     *
     * @param derCiphertext DER编码的密文
     * @param mode          密文排列模式
     * @return 原始格式的密文字节数组
     * @throws GmkitException 如果解码失败
     */
    public static byte[] decodeDer(byte[] derCiphertext, Sm2CipherMode mode) {
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(derCiphertext);
            if (sequence.size() != 4) {
                throw new GmkitException("Invalid SM2 ciphertext DER sequence");
            }
            byte[] c1x = BigIntegers.asUnsignedByteArray(
                Sm2Util.CURVE_LENGTH,
                ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue());
            byte[] c1y = BigIntegers.asUnsignedByteArray(
                Sm2Util.CURVE_LENGTH,
                ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue());
            byte[] first = ASN1OctetString.getInstance(sequence.getObjectAt(2)).getOctets();
            byte[] second = ASN1OctetString.getInstance(sequence.getObjectAt(3)).getOctets();

            byte[] c1 = Bytes.concat(new byte[]{0x04}, c1x, c1y);
            if (mode == Sm2CipherMode.C1C3C2) {
                return Bytes.concat(c1, first, second);
            }
            return Bytes.concat(c1, second, first);
        } catch (IllegalArgumentException ex) {
            throw new GmkitException("Invalid SM2 ciphertext DER", ex);
        }
    }
}

