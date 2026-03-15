package cn.gmkit.sm2;

import cn.gmkit.core.*;
import cn.gmkit.sm3.Sm3Util;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.MessageDigest;

public final class Sm2Util {

    public static final String DEFAULT_USER_ID = "1234567812345678";
    public static final String LEGACY_USER_ID = DEFAULT_USER_ID;
    public static final String GM_2023_USER_ID = "";
    public static final String CURVE_NAME = "sm2p256v1";
    public static final int SM3_DIGEST_LENGTH = 32;

    static final org.bouncycastle.asn1.x9.X9ECParameters X9_PARAMETERS = GMNamedCurves.getByName(CURVE_NAME);
    static final ECDomainParameters DOMAIN_PARAMS = new ECDomainParameters(
        X9_PARAMETERS.getCurve(),
        X9_PARAMETERS.getG(),
        X9_PARAMETERS.getN(),
        X9_PARAMETERS.getH());
    static final int CURVE_LENGTH = (DOMAIN_PARAMS.getCurve().getFieldSize() + 7) / 8;

    private Sm2Util() {
    }

    public static Sm2KeyPair generateKeyPair() {
        return generateKeyPair(false, GmSecurityContexts.defaults());
    }

    public static Sm2KeyPair generateKeyPair(boolean compressedPublicKey) {
        return generateKeyPair(compressedPublicKey, GmSecurityContexts.defaults());
    }

    public static Sm2KeyPair generateKeyPair(GmSecurityContext securityContext) {
        return generateKeyPair(false, securityContext);
    }

    public static Sm2KeyPair generateKeyPair(boolean compressedPublicKey, GmSecurityContext securityContext) {
        GmSecurityContext context = context(securityContext);
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(DOMAIN_PARAMS, context.secureRandom()));
        AsymmetricCipherKeyPair pair = generator.generateKeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) pair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) pair.getPublic();
        return new Sm2KeyPair(
            encodePublicKey(publicKey.getQ(), compressedPublicKey),
            HexCodec.encode(BigIntegers.asUnsignedByteArray(CURVE_LENGTH, privateKey.getD())));
    }

    public static String getPublicKeyFromPrivateKey(String privateKeyHex, boolean compressed) {
        ECPrivateKeyParameters privateKey = toPrivateKeyParameters(privateKeyHex);
        ECPoint publicPoint = new FixedPointCombMultiplier()
            .multiply(DOMAIN_PARAMS.getG(), privateKey.getD())
            .normalize();
        return encodePublicKey(publicPoint, compressed);
    }

    public static String compressPublicKey(String publicKeyHex) {
        return encodePublicKey(toPublicKeyPoint(publicKeyHex), true);
    }

    public static String decompressPublicKey(String publicKeyHex) {
        return encodePublicKey(toPublicKeyPoint(publicKeyHex), false);
    }

    public static byte[] encrypt(String publicKeyHex, byte[] data, Sm2EncryptOptions options) {
        Sm2EncryptOptions resolved = options != null ? options : Sm2EncryptOptions.builder().build();
        ECPublicKeyParameters publicKey = toPublicKeyParameters(publicKeyHex);
        SM2Engine engine = new SM2Engine(resolved.mode().toBcMode());
        CipherParameters parameters = new ParametersWithRandom(publicKey, resolved.securityContext().secureRandom());
        try {
            engine.init(true, parameters);
            return engine.processBlock(data, 0, data.length);
        } catch (InvalidCipherTextException ex) {
            throw new GmkitException("SM2 encryption failed", ex);
        }
    }

    public static String encryptHex(String publicKeyHex, byte[] data, Sm2EncryptOptions options) {
        return HexCodec.encode(encrypt(publicKeyHex, data, options));
    }

    public static String encryptBase64(String publicKeyHex, byte[] data, Sm2EncryptOptions options) {
        return Base64Codec.encode(encrypt(publicKeyHex, data, options));
    }

    public static byte[] decrypt(String privateKeyHex, byte[] ciphertext, Sm2DecryptOptions options) {
        Sm2DecryptOptions resolved = options != null ? options : Sm2DecryptOptions.builder().build();
        ECPrivateKeyParameters privateKey = toPrivateKeyParameters(privateKeyHex);
        SM2Engine engine = new SM2Engine(resolved.mode().toBcMode());
        try {
            engine.init(false, privateKey);
            return engine.processBlock(ciphertext, 0, ciphertext.length);
        } catch (InvalidCipherTextException ex) {
            throw new GmkitException("SM2 decryption failed", ex);
        }
    }

    public static byte[] decrypt(String privateKeyHex, String ciphertext, Sm2DecryptOptions options) {
        return decrypt(privateKeyHex, ByteEncodings.decodeAuto(ciphertext, "ciphertext"), options);
    }

    public static byte[] sign(String privateKeyHex, byte[] message, Sm2SignOptions options) {
        Sm2SignOptions resolved = options != null ? options : Sm2SignOptions.builder().build();
        String publicKeyHex = getPublicKeyFromPrivateKey(privateKeyHex, false);
        byte[] eHash = computeE(publicKeyHex, message, resolved.userId(), resolved.skipZComputation());
        return signDigest(privateKeyHex, eHash, resolved.signatureFormat(), resolved.securityContext());
    }

    public static String signHex(String privateKeyHex, byte[] message, Sm2SignOptions options) {
        return HexCodec.encode(sign(privateKeyHex, message, options));
    }

    public static String signBase64(String privateKeyHex, byte[] message, Sm2SignOptions options) {
        return Base64Codec.encode(sign(privateKeyHex, message, options));
    }

    public static byte[] signWithoutZ(String privateKeyHex, byte[] message, Sm2SignatureFormat signatureFormat) {
        return sign(
            privateKeyHex,
            message,
            Sm2SignOptions.builder()
                .signatureFormat(signatureFormat)
                .skipZComputation(true)
                .build());
    }

    public static byte[] signDigest(String privateKeyHex, byte[] eHash, Sm2SignatureFormat signatureFormat) {
        return signDigest(privateKeyHex, eHash, signatureFormat, GmSecurityContexts.defaults());
    }

    public static byte[] signDigest(
        String privateKeyHex,
        byte[] eHash,
        Sm2SignatureFormat signatureFormat,
        GmSecurityContext securityContext) {
        ECPrivateKeyParameters privateKey = toPrivateKeyParameters(privateKeyHex);
        Sm2DigestSigner signer = new Sm2DigestSigner();
        signer.init(true, new ParametersWithRandom(privateKey, context(securityContext).secureRandom()));
        try {
            byte[] der = signer.generateSignature(eHash);
            return signatureFormat == Sm2SignatureFormat.DER ? der : Sm2Signatures.derToRaw(der);
        } catch (org.bouncycastle.crypto.CryptoException ex) {
            throw new GmkitException("SM2 signing failed", ex);
        }
    }

    public static boolean verify(String publicKeyHex, byte[] message, byte[] signature, Sm2VerifyOptions options) {
        Sm2VerifyOptions resolved = options != null ? options : Sm2VerifyOptions.builder().build();
        try {
            byte[] derSignature = Sm2Signatures.normalizeToDer(signature, resolved.signatureFormat());
            byte[] eHash = computeE(publicKeyHex, message, resolved.userId(), resolved.skipZComputation());
            return verifyDigest(publicKeyHex, eHash, derSignature);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    public static boolean verify(String publicKeyHex, byte[] message, String signature, Sm2VerifyOptions options) {
        byte[] signatureBytes = ByteEncodings.decodeAuto(signature, "signature");
        return verify(publicKeyHex, message, signatureBytes, options);
    }

    public static boolean verifyWithoutZ(
        String publicKeyHex,
        byte[] message,
        byte[] signature,
        Sm2SignatureInputFormat signatureFormat) {
        return verify(
            publicKeyHex,
            message,
            signature,
            Sm2VerifyOptions.builder()
                .signatureFormat(signatureFormat)
                .skipZComputation(true)
                .build());
    }

    public static boolean verifyDigest(String publicKeyHex, byte[] eHash, byte[] derSignature) {
        ECPublicKeyParameters publicKey = toPublicKeyParameters(publicKeyHex);
        Sm2DigestSigner signer = new Sm2DigestSigner();
        signer.init(false, publicKey);
        return signer.verifySignature(eHash, derSignature);
    }

    public static byte[] computeZ(String userId, String publicKeyHex) {
        byte[] userIdBytes = userIdBytes(userId);
        byte[] entl = userIdBitLength(userIdBytes);
        ECPoint publicPoint = toPublicKeyPoint(publicKeyHex).normalize();
        byte[] a = BigIntegers.asUnsignedByteArray(CURVE_LENGTH, X9_PARAMETERS.getCurve().getA().toBigInteger());
        byte[] b = BigIntegers.asUnsignedByteArray(CURVE_LENGTH, X9_PARAMETERS.getCurve().getB().toBigInteger());
        byte[] gx = BigIntegers.asUnsignedByteArray(CURVE_LENGTH, X9_PARAMETERS.getG().getAffineXCoord().toBigInteger());
        byte[] gy = BigIntegers.asUnsignedByteArray(CURVE_LENGTH, X9_PARAMETERS.getG().getAffineYCoord().toBigInteger());
        byte[] px = BigIntegers.asUnsignedByteArray(CURVE_LENGTH, publicPoint.getAffineXCoord().toBigInteger());
        byte[] py = BigIntegers.asUnsignedByteArray(CURVE_LENGTH, publicPoint.getAffineYCoord().toBigInteger());
        return Sm3Util.digest(Bytes.concat(entl, userIdBytes, a, b, gx, gy, px, py));
    }

    public static byte[] computeE(String publicKeyHex, byte[] message, String userId, boolean skipZComputation) {
        if (skipZComputation) {
            return computeEWithoutZ(message);
        }
        return Sm3Util.digest(Bytes.concat(computeZ(userId, publicKeyHex), message));
    }

    public static byte[] computeEWithoutZ(byte[] message) {
        return Sm3Util.digest(message);
    }

    public static byte[] keyExchange(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        Sm2KeyExchangeOptions options) {
        Sm2KeyExchangeOptions resolved = resolveKeyExchangeOptions(options);
        SM2KeyExchange exchange = new SM2KeyExchange();
        exchange.init(new ParametersWithID(
            new SM2KeyExchangePrivateParameters(
                resolved.initiator(),
                toPrivateKeyParameters(selfStaticPrivateKeyHex),
                toPrivateKeyParameters(selfEphemeralPrivateKeyHex)),
            userIdBytes(resolved.selfId())));
        return exchange.calculateKey(
            resolved.keyBits(),
            new ParametersWithID(
                new SM2KeyExchangePublicParameters(
                    toPublicKeyParameters(peerStaticPublicKeyHex),
                    toPublicKeyParameters(peerEphemeralPublicKeyHex)),
                userIdBytes(resolved.peerId())));
    }

    public static Sm2KeyExchangeResult keyExchangeWithConfirmation(
        String selfStaticPrivateKeyHex,
        String selfEphemeralPrivateKeyHex,
        String peerStaticPublicKeyHex,
        String peerEphemeralPublicKeyHex,
        Sm2KeyExchangeOptions options) {
        Sm2KeyExchangeOptions resolved = resolveKeyExchangeOptions(options);
        if (resolved.initiator() && (resolved.confirmationTag() == null || resolved.confirmationTag().length == 0)) {
            throw new GmkitException("Initiator must provide peer confirmation tag for SM2 key exchange");
        }
        SM2KeyExchange exchange = new SM2KeyExchange();
        exchange.init(new ParametersWithID(
            new SM2KeyExchangePrivateParameters(
                resolved.initiator(),
                toPrivateKeyParameters(selfStaticPrivateKeyHex),
                toPrivateKeyParameters(selfEphemeralPrivateKeyHex)),
            userIdBytes(resolved.selfId())));
        byte[][] result = exchange.calculateKeyWithConfirmation(
            resolved.keyBits(),
            Bytes.clone(resolved.confirmationTag()),
            new ParametersWithID(
                new SM2KeyExchangePublicParameters(
                    toPublicKeyParameters(peerStaticPublicKeyHex),
                    toPublicKeyParameters(peerEphemeralPublicKeyHex)),
                userIdBytes(resolved.peerId())));
        if (resolved.initiator()) {
            return new Sm2KeyExchangeResult(result[0], null, result[1]);
        }
        return new Sm2KeyExchangeResult(result[0], result[1], result[2]);
    }

    public static boolean confirmResponder(byte[] expectedS2, byte[] confirmationTag) {
        if (expectedS2 == null || confirmationTag == null) {
            return false;
        }
        return MessageDigest.isEqual(Bytes.clone(expectedS2), Bytes.clone(confirmationTag));
    }

    static ECPrivateKeyParameters toPrivateKeyParameters(String privateKeyHex) {
        byte[] privateKeyBytes = decodePrivateKey(privateKeyHex);
        BigInteger d = new BigInteger(1, privateKeyBytes);
        if (d.signum() <= 0 || d.compareTo(DOMAIN_PARAMS.getN()) >= 0) {
            throw new GmkitException("Invalid private key scalar");
        }
        return new ECPrivateKeyParameters(d, DOMAIN_PARAMS);
    }

    static ECPublicKeyParameters toPublicKeyParameters(String publicKeyHex) {
        ECPoint point = toPublicKeyPoint(publicKeyHex);
        return new ECPublicKeyParameters(point, DOMAIN_PARAMS);
    }

    static ECPoint toPublicKeyPoint(String publicKeyHex) {
        String normalized = normalizePublicKeyHex(publicKeyHex);
        byte[] encoded = HexCodec.decodeStrict(normalized, "public key");
        ECPoint point = X9_PARAMETERS.getCurve().decodePoint(encoded).normalize();
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
        if (normalized.length() > CURVE_LENGTH * 2) {
            if (normalized.length() == (CURVE_LENGTH + 1) * 2 && normalized.startsWith("00")) {
                normalized = normalized.substring(2);
            } else {
                throw new GmkitException("Invalid private key: must fit in 32 bytes");
            }
        }
        if (normalized.length() < CURVE_LENGTH * 2) {
            StringBuilder builder = new StringBuilder(CURVE_LENGTH * 2);
            for (int i = normalized.length(); i < CURVE_LENGTH * 2; i++) {
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

    private static Sm2KeyExchangeOptions resolveKeyExchangeOptions(Sm2KeyExchangeOptions options) {
        Sm2KeyExchangeOptions resolved = options != null ? options : Sm2KeyExchangeOptions.builder().build();
        if (resolved.keyBits() <= 0) {
            throw new GmkitException("SM2 key exchange keyBits must be positive");
        }
        return resolved;
    }

    private static byte[] userIdBytes(String userId) {
        String resolvedUserId = userId != null ? userId : DEFAULT_USER_ID;
        byte[] bytes = Texts.utf8(resolvedUserId);
        if (bytes.length >= 8192) {
            throw new GmkitException("SM2 user ID must be less than 2^16 bits long");
        }
        return bytes;
    }

    private static byte[] userIdBitLength(byte[] userIdBytes) {
        return new byte[]{
            (byte) ((userIdBytes.length * 8) >>> 8),
            (byte) (userIdBytes.length * 8)
        };
    }

    private static GmSecurityContext context(GmSecurityContext securityContext) {
        return securityContext != null ? securityContext : GmSecurityContexts.defaults();
    }
}

