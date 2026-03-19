package cn.gmkit.sm2;

import cn.gmkit.core.Bytes;
import cn.gmkit.core.GmkitException;
import cn.gmkit.core.SM2CipherMode;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.math.BigInteger;

/**
 * @author mumu
 * @description SM2密文格式转换工具类
 * @since 1.0.0
 */
public final class SM2Ciphertexts {

    private SM2Ciphertexts() {
    }

    /**
     * 解析SM2密文数据
     *
     * @param ciphertext 密文字节数组
     * @param mode       密文排列模式
     * @return SM2密文对象
     * @throws GmkitException 如果密文格式无效
     */
    public static SM2Ciphertext parse(byte[] ciphertext, SM2CipherMode mode) {
        SM2CipherMode resolvedMode = SM2Domain.cipherMode(mode);
        if (ciphertext == null || ciphertext.length < SM2Domain.MIN_CIPHERTEXT_LENGTH) {
            throw new GmkitException(
                "Invalid SM2 ciphertext: expected raw C1||C3||C2 or C1||C2||C3 bytes, but length was "
                    + (ciphertext == null ? 0 : ciphertext.length));
        }
        if (ciphertext[0] != 0x04) {
            throw new GmkitException("Invalid SM2 ciphertext: raw format must start with uncompressed point prefix 0x04");
        }
        int c1Length = SM2Domain.C1_LENGTH;
        int c3Length = SM2.SM3_DIGEST_LENGTH;
        if (ciphertext.length < c1Length + c3Length) {
            throw new GmkitException("Invalid SM2 ciphertext: missing C1/C3/C2 segments");
        }
        byte[] c1 = Bytes.copyOfRange(ciphertext, 0, c1Length);
        byte[] c2;
        byte[] c3;
        if (resolvedMode == SM2CipherMode.C1C3C2) {
            c3 = Bytes.copyOfRange(ciphertext, c1Length, c1Length + c3Length);
            c2 = Bytes.copyOfRange(ciphertext, c1Length + c3Length, ciphertext.length);
        } else {
            c2 = Bytes.copyOfRange(ciphertext, c1Length, ciphertext.length - c3Length);
            c3 = Bytes.copyOfRange(ciphertext, ciphertext.length - c3Length, ciphertext.length);
        }
        return new SM2Ciphertext(c1, c2, c3, resolvedMode);
    }

    /**
     * 将密文编码为DER格式
     *
     * @param ciphertext 原始密文字节数组
     * @param mode       密文排列模式
     * @return DER编码的密文
     * @throws GmkitException 如果编码失败
     */
    public static byte[] encodeDer(byte[] ciphertext, SM2CipherMode mode) {
        SM2Ciphertext parsed = parse(ciphertext, mode);
        byte[] c1 = parsed.c1();
        byte[] c1x = Bytes.copyOfRange(c1, 1, 1 + SM2Domain.CURVE_LENGTH);
        byte[] c1y = Bytes.copyOfRange(c1, 1 + SM2Domain.CURVE_LENGTH, c1.length);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(new BigInteger(1, c1x)));
        vector.add(new ASN1Integer(new BigInteger(1, c1y)));
        if (mode == SM2CipherMode.C1C3C2) {
            vector.add(new DEROctetString(parsed.c3()));
            vector.add(new DEROctetString(parsed.c2()));
        } else {
            vector.add(new DEROctetString(parsed.c2()));
            vector.add(new DEROctetString(parsed.c3()));
        }
        try {
            return new DERSequence(vector).getEncoded();
        } catch (IOException ex) {
            throw new GmkitException("Failed to encode SM2 ciphertext as ASN.1 DER sequence", ex);
        }
    }

    /**
     * 将原始密文编码为 ASN.1 DER 格式。
     *
     * @param ciphertext 原始密文字节数组
     * @param mode       密文排列模式
     * @return ASN.1 DER 编码密文
     */
    public static byte[] encodeAsn1(byte[] ciphertext, SM2CipherMode mode) {
        return encodeDer(ciphertext, mode);
    }

    /**
     * 将DER格式的密文解码为原始格式
     *
     * @param derCiphertext DER编码的密文
     * @param mode          密文排列模式
     * @return 原始格式的密文字节数组
     * @throws GmkitException 如果解码失败
     */
    public static byte[] decodeDer(byte[] derCiphertext, SM2CipherMode mode) {
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(derCiphertext);
            if (sequence.size() != 4) {
                throw new GmkitException("Invalid SM2 ciphertext ASN.1 DER encoding: expected SEQUENCE of 4 elements");
            }
            byte[] c1x = BigIntegers.asUnsignedByteArray(
                SM2Domain.CURVE_LENGTH,
                ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue());
            byte[] c1y = BigIntegers.asUnsignedByteArray(
                SM2Domain.CURVE_LENGTH,
                ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue());
            byte[] first = ASN1OctetString.getInstance(sequence.getObjectAt(2)).getOctets();
            byte[] second = ASN1OctetString.getInstance(sequence.getObjectAt(3)).getOctets();

            byte[] c1 = Bytes.concat(new byte[]{0x04}, c1x, c1y);
            if (SM2Domain.cipherMode(mode) == SM2CipherMode.C1C3C2) {
                return Bytes.concat(c1, first, second);
            }
            return Bytes.concat(c1, second, first);
        } catch (IllegalArgumentException ex) {
            throw new GmkitException("Invalid SM2 ciphertext ASN.1 DER encoding", ex);
        }
    }

    /**
     * 将 ASN.1 DER 密文解码为原始 SM2 密文。
     *
     * @param asn1Ciphertext ASN.1 DER 编码密文
     * @param mode           密文排列模式
     * @return 原始 SM2 密文
     */
    public static byte[] decodeAsn1(byte[] asn1Ciphertext, SM2CipherMode mode) {
        return decodeDer(asn1Ciphertext, mode);
    }

    /**
     * 自动识别原始密文和 ASN.1 DER 密文。
     *
     * @param ciphertext 密文字节数组
     * @param mode       密文排列模式
     * @return 原始 SM2 密文
     */
    public static byte[] decodeAuto(byte[] ciphertext, SM2CipherMode mode) {
        if (looksLikeAsn1(ciphertext)) {
            return decodeDer(ciphertext, mode);
        }
        validateRaw(ciphertext);
        return ciphertext;
    }

    static byte[] normalizeForDecrypt(byte[] ciphertext, SM2CipherMode mode) {
        byte[] safeCiphertext = Bytes.requireNonNull(ciphertext, "SM2 ciphertext");
        if (looksLikeAsn1(safeCiphertext)) {
            return decodeDer(safeCiphertext, mode);
        }
        validateRaw(safeCiphertext);
        return safeCiphertext;
    }

    static boolean looksLikeAsn1(byte[] ciphertext) {
        return ciphertext != null
            && ciphertext.length > 2
            && ciphertext[0] == 0x30;
    }

    private static void validateRaw(byte[] ciphertext) {
        if (ciphertext == null) {
            throw new GmkitException("SM2 ciphertext must not be null");
        }
        if (ciphertext.length < SM2Domain.MIN_CIPHERTEXT_LENGTH) {
            throw new GmkitException(
                "Invalid SM2 ciphertext: expected raw C1||C3||C2 or C1||C2||C3 bytes, but length was " + ciphertext.length);
        }
        if (ciphertext[0] != 0x04) {
            throw new GmkitException("Invalid SM2 ciphertext: raw format must start with uncompressed point prefix 0x04");
        }
    }
}

