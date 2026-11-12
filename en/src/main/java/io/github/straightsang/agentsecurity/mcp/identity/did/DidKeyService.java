package io.github.straightsang.agentsecurity.mcp.identity.did;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import org.springframework.stereotype.Service;

/** Creates did:key identifiers from Ed25519 public keys and resolves them back to public keys. */
@Service
public class DidKeyService {
    private static final String DID_PREFIX = "did:key:z";
    private static final byte[] ED25519_MULTICODEC = {(byte) 0xed, 0x01};
    private static final String BASE58 =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public String createDid(PublicKey publicKey) {
        if (!(publicKey instanceof EdECPublicKey edPublicKey)) {
            throw new IllegalArgumentException("Ed25519 공개키만 did:key로 변환할 수 있습니다.");
        }
        byte[] rawKey = encodePoint(edPublicKey);
        byte[] multicodecKey = new byte[ED25519_MULTICODEC.length + rawKey.length];
        System.arraycopy(ED25519_MULTICODEC, 0, multicodecKey, 0, ED25519_MULTICODEC.length);
        System.arraycopy(rawKey, 0, multicodecKey, ED25519_MULTICODEC.length, rawKey.length);
        return DID_PREFIX + encodeBase58(multicodecKey);
    }

    public PublicKey resolvePublicKey(String did) {
        if (did == null || !did.startsWith(DID_PREFIX)) {
            throw new IllegalArgumentException("올바른 did:key 형식이 아닙니다.");
        }
        byte[] decoded = decodeBase58(did.substring(DID_PREFIX.length()));
        if (decoded.length != 34
                || decoded[0] != ED25519_MULTICODEC[0]
                || decoded[1] != ED25519_MULTICODEC[1]) {
            throw new IllegalArgumentException("Ed25519 did:key가 아닙니다.");
        }

        byte[] rawKey = Arrays.copyOfRange(decoded, 2, decoded.length);
        boolean xOdd = (rawKey[31] & 0x80) != 0;
        rawKey[31] &= 0x7f;
        BigInteger y = littleEndianToPositiveBigInteger(rawKey);

        try {
            EdECPoint point = new EdECPoint(xOdd, y);
            EdECPublicKeySpec spec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, point);
            return KeyFactory.getInstance("Ed25519").generatePublic(spec);
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("DID 공개키를 복원하지 못했습니다.", exception);
        }
    }

    private byte[] encodePoint(EdECPublicKey publicKey) {
        EdECPoint point = publicKey.getPoint();
        byte[] result = new byte[32];
        BigInteger y = point.getY();
        for (int i = 0; i < result.length; i++) {
            result[i] = y.shiftRight(i * 8).byteValue();
        }
        if (point.isXOdd()) {
            result[31] |= (byte) 0x80;
        }
        return result;
    }

    private BigInteger littleEndianToPositiveBigInteger(byte[] littleEndian) {
        byte[] bigEndian = new byte[littleEndian.length];
        for (int i = 0; i < littleEndian.length; i++) {
            bigEndian[i] = littleEndian[littleEndian.length - 1 - i];
        }
        return new BigInteger(1, bigEndian);
    }

    private String encodeBase58(byte[] input) {
        BigInteger value = new BigInteger(1, input);
        StringBuilder encoded = new StringBuilder();
        BigInteger base = BigInteger.valueOf(58);
        while (value.signum() > 0) {
            BigInteger[] quotientAndRemainder = value.divideAndRemainder(base);
            encoded.append(BASE58.charAt(quotientAndRemainder[1].intValue()));
            value = quotientAndRemainder[0];
        }
        for (byte current : input) {
            if (current != 0) break;
            encoded.append('1');
        }
        return encoded.reverse().toString();
    }

    private byte[] decodeBase58(String input) {
        if (input.isBlank()) {
            throw new IllegalArgumentException("Base58 값이 비어 있습니다.");
        }
        BigInteger value = BigInteger.ZERO;
        BigInteger base = BigInteger.valueOf(58);
        for (char current : input.toCharArray()) {
            int digit = BASE58.indexOf(current);
            if (digit < 0) {
                throw new IllegalArgumentException("Base58에 허용되지 않는 문자가 있습니다.");
            }
            value = value.multiply(base).add(BigInteger.valueOf(digit));
        }
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        int leadingZeros = 0;
        while (leadingZeros < input.length() && input.charAt(leadingZeros) == '1') {
            leadingZeros++;
        }
        byte[] result = new byte[leadingZeros + bytes.length];
        System.arraycopy(bytes, 0, result, leadingZeros, bytes.length);
        return result;
    }
}
