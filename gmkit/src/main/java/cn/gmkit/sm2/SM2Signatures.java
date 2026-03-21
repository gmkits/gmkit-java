package cn.gmkit.sm2;

import cn.gmkit.core.Checks;
import cn.gmkit.core.GmkitException;
import cn.gmkit.core.SM2SignatureFormat;
import cn.gmkit.core.SM2SignatureInputFormat;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;

import java.io.IOException;

/**
 * @author mumu
 * @description SM2签名格式转换工具类
 * @since 1.0.0
 */
public final class SM2Signatures {

    private SM2Signatures() {
    }

    /**
     * 将签名规范化为请求的格式
     *
     * @param signature 原始签名
     * @param format    目标格式
     * @return 规范化后的签名
     */
    public static byte[] normalizeToRequested(byte[] signature, SM2SignatureFormat format) {
        if (format == SM2SignatureFormat.DER) {
            return signature;
        }
        return derToRaw(signature);
    }

    /**
     * 将签名规范化为DER格式
     *
     * @param signature   原始签名
     * @param inputFormat 输入格式
     * @return DER格式的签名
     * @throws GmkitException 如果转换失败
     */
    public static byte[] normalizeToDer(byte[] signature, SM2SignatureInputFormat inputFormat) {
        if (inputFormat == SM2SignatureInputFormat.DER) {
            return signature;
        }
        if (inputFormat == SM2SignatureInputFormat.RAW) {
            return rawToDer(signature);
        }
        Checks.requireNonNull(signature, "Invalid SM2 signature: input");
        if (signature.length == SM2Domain.RAW_SIGNATURE_LENGTH) {
            return rawToDer(signature);
        }
        if (looksLikeDerSignature(signature)) {
            return signature;
        }
        throw new GmkitException("Invalid SM2 signature: expected 64-byte RAW (r||s) or ASN.1 DER sequence");
    }

    /**
     * 将DER格式的签名转换为原始格式
     *
     * @param derSignature DER格式的签名
     * @return 原始格式的签名（64字节R+S）
     * @throws GmkitException 如果转换失败
     */
    public static byte[] derToRaw(byte[] derSignature) {
        try {
            java.math.BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(SM2Domain.DOMAIN_PARAMS.getN(), derSignature);
            return PlainDSAEncoding.INSTANCE.encode(SM2Domain.DOMAIN_PARAMS.getN(), rs[0], rs[1]);
        } catch (IOException ex) {
            throw new GmkitException("Invalid SM2 signature ASN.1 DER encoding: expected SEQUENCE { r, s }", ex);
        }
    }

    /**
     * 将原始格式的签名转换为DER格式
     *
     * @param rawSignature 原始格式的签名（64字节R+S）
     * @return DER格式的签名
     * @throws GmkitException 如果转换失败
     */
    public static byte[] rawToDer(byte[] rawSignature) {
        Checks.requireNonNull(rawSignature, "Invalid SM2 RAW signature");
        if (rawSignature.length != SM2Domain.RAW_SIGNATURE_LENGTH) {
            throw new GmkitException("Invalid SM2 RAW signature: expected " + SM2Domain.RAW_SIGNATURE_LENGTH + " bytes (r||s)");
        }
        try {
            java.math.BigInteger[] rs = PlainDSAEncoding.INSTANCE.decode(SM2Domain.DOMAIN_PARAMS.getN(), rawSignature);
            return StandardDSAEncoding.INSTANCE.encode(SM2Domain.DOMAIN_PARAMS.getN(), rs[0], rs[1]);
        } catch (IOException ex) {
            throw new GmkitException("Invalid SM2 RAW signature: unable to encode ASN.1 DER sequence", ex);
        }
    }

    static boolean looksLikeDerSignature(byte[] signature) {
        return signature.length > 8
            && signature.length != SM2Domain.RAW_SIGNATURE_LENGTH
            && signature[0] == 0x30;
    }
}

