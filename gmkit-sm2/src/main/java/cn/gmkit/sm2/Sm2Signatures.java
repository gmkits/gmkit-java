package cn.gmkit.sm2;

import cn.gmkit.core.GmkitException;
import cn.gmkit.core.Sm2SignatureFormat;
import cn.gmkit.core.Sm2SignatureInputFormat;
import org.bouncycastle.crypto.signers.PlainDSAEncoding;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;

import java.io.IOException;

/**
 * @author mumu
 * @description SM2签名格式转换工具类
 * @since 1.0.0
 */
public final class Sm2Signatures {

    private Sm2Signatures() {
    }

    /**
     * 将签名规范化为请求的格式
     *
     * @param signature 原始签名
     * @param format    目标格式
     * @return 规范化后的签名
     */
    public static byte[] normalizeToRequested(byte[] signature, Sm2SignatureFormat format) {
        if (format == Sm2SignatureFormat.DER) {
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
    public static byte[] normalizeToDer(byte[] signature, Sm2SignatureInputFormat inputFormat) {
        if (inputFormat == Sm2SignatureInputFormat.DER) {
            return signature;
        }
        if (inputFormat == Sm2SignatureInputFormat.RAW) {
            return rawToDer(signature);
        }
        if (signature.length == Sm2Util.CURVE_LENGTH * 2) {
            return rawToDer(signature);
        }
        try {
            derToRaw(signature);
            return signature;
        } catch (GmkitException ex) {
            if (signature.length == Sm2Util.CURVE_LENGTH * 2) {
                return rawToDer(signature);
            }
            throw ex;
        }
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
            java.math.BigInteger[] rs = StandardDSAEncoding.INSTANCE.decode(Sm2Util.DOMAIN_PARAMS.getN(), derSignature);
            return PlainDSAEncoding.INSTANCE.encode(Sm2Util.DOMAIN_PARAMS.getN(), rs[0], rs[1]);
        } catch (IOException ex) {
            throw new GmkitException("Invalid DER-encoded SM2 signature", ex);
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
        try {
            java.math.BigInteger[] rs = PlainDSAEncoding.INSTANCE.decode(Sm2Util.DOMAIN_PARAMS.getN(), rawSignature);
            return StandardDSAEncoding.INSTANCE.encode(Sm2Util.DOMAIN_PARAMS.getN(), rs[0], rs[1]);
        } catch (IOException ex) {
            throw new GmkitException("Invalid raw SM2 signature", ex);
        }
    }
}

