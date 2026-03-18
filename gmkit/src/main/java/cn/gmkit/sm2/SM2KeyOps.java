package cn.gmkit.sm2;

import cn.gmkit.core.GmSecurityContext;
import cn.gmkit.core.GmkitException;
import cn.gmkit.core.HexCodec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;

final class SM2KeyOps {

    private SM2KeyOps() {
    }

    static SM2KeyPair generateKeyPair(boolean compressedPublicKey, GmSecurityContext securityContext) {
        GmSecurityContext context = SM2Domain.context(securityContext);
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(SM2Domain.DOMAIN_PARAMS, context.secureRandom()));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) pair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) pair.getPublic();
        return new SM2KeyPair(
            encodePublicKey(publicKey.getQ(), compressedPublicKey),
            HexCodec.encode(BigIntegers.asUnsignedByteArray(SM2Domain.CURVE_LENGTH, privateKey.getD())));
    }

    static String getPublicKeyFromPrivateKey(String privateKeyHex, boolean compressed) {
        ECPrivateKeyParameters privateKey = toPrivateKeyParameters(privateKeyHex);
        ECPoint publicPoint = new FixedPointCombMultiplier()
            .multiply(SM2Domain.DOMAIN_PARAMS.getG(), privateKey.getD())
            .normalize();
        return encodePublicKey(publicPoint, compressed);
    }

    static String compressPublicKey(String publicKeyHex) {
        return encodePublicKey(toPublicKeyPoint(publicKeyHex), true);
    }

    static String decompressPublicKey(String publicKeyHex) {
        return encodePublicKey(toPublicKeyPoint(publicKeyHex), false);
    }

    static ECPrivateKeyParameters toPrivateKeyParameters(String privateKeyHex) {
        byte[] privateKeyBytes = decodePrivateKey(privateKeyHex);
        BigInteger d = new BigInteger(1, privateKeyBytes);
        if (d.signum() <= 0 || d.compareTo(SM2Domain.DOMAIN_PARAMS.getN()) >= 0) {
            throw new GmkitException("Invalid private key scalar");
        }
        return new ECPrivateKeyParameters(d, SM2Domain.DOMAIN_PARAMS);
    }

    static ECPublicKeyParameters toPublicKeyParameters(String publicKeyHex) {
        ECPoint point = toPublicKeyPoint(publicKeyHex);
        return new ECPublicKeyParameters(point, SM2Domain.DOMAIN_PARAMS);
    }

    static ECPoint toPublicKeyPoint(String publicKeyHex) {
        String normalized = normalizePublicKeyHex(publicKeyHex);
        byte[] encoded = HexCodec.decodeStrict(normalized, "public key");
        ECPoint point = SM2Domain.X9_PARAMETERS.getCurve().decodePoint(encoded).normalize();
        if (point.isInfinity()) {
            throw new GmkitException("Invalid public key point");
        }
        return point;
    }

    private static byte[] decodePrivateKey(String privateKeyHex) {
        String normalized = HexCodec.normalize(privateKeyHex);
        if (normalized.isEmpty() || !HexCodec.isHex(normalized)) {
            throw new GmkitException("Invalid private key: must be a hexadecimal string");
        }
        if ((normalized.length() & 1) != 0) {
            throw new GmkitException("Invalid private key: hexadecimal strings must have an even length");
        }
        if (normalized.length() > SM2Domain.CURVE_LENGTH * 2) {
            if (normalized.length() == (SM2Domain.CURVE_LENGTH + 1) * 2 && normalized.startsWith("00")) {
                normalized = normalized.substring(2);
            } else {
                throw new GmkitException("Invalid private key: must fit in 32 bytes");
            }
        }
        if (normalized.length() < SM2Domain.CURVE_LENGTH * 2) {
            StringBuilder builder = new StringBuilder(SM2Domain.CURVE_LENGTH * 2);
            for (int i = normalized.length(); i < SM2Domain.CURVE_LENGTH * 2; i++) {
                builder.append('0');
            }
            builder.append(normalized);
            normalized = builder.toString();
        }
        return HexCodec.decodeStrict(normalized, "private key");
    }

    private static String normalizePublicKeyHex(String publicKeyHex) {
        String normalized = HexCodec.normalize(publicKeyHex);
        if (normalized.isEmpty() || !HexCodec.isHex(normalized)) {
            throw new GmkitException("Invalid public key: must be hexadecimal");
        }
        if ((normalized.length() & 1) != 0) {
            throw new GmkitException("Invalid public key: hexadecimal strings must have an even length");
        }
        if (normalized.length() != 66 && normalized.length() != 130) {
            throw new GmkitException("Invalid public key: only compressed 33-byte or uncompressed 65-byte formats are supported");
        }
        String prefix = normalized.substring(0, 2).toLowerCase();
        if (!"02".equals(prefix) && !"03".equals(prefix) && !"04".equals(prefix)) {
            throw new GmkitException("Invalid public key prefix: must be 02, 03, or 04");
        }
        return normalized.toLowerCase();
    }

    private static String encodePublicKey(ECPoint point, boolean compressed) {
        return HexCodec.encode(point.getEncoded(compressed));
    }
}

