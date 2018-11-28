package org.bjoern.jbranca;

import io.seruco.encoding.base62.Base62;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class BrancaTokenFactory {
    private static final byte VERSION = (byte) 0xBA;
    public static final int TAG_LENGTH = 16;
    public static final int HEADER_LENGTH = 29;
    private final byte[] key;

    public BrancaTokenFactory(byte[] key) {
        this.key = key;
    }

    public byte[] encode(byte[] plaintext) {
        return encode(plaintext, makeRandomNonce());
    }

    private static int unixTimeNow() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    private static byte[] bigEndian(int unixTime) {
        return new byte[]{
                (byte) (unixTime >> 24),
                (byte) (unixTime >> 16),
                (byte) (unixTime >> 8),
                (byte) unixTime
        };
    }

    public static byte[] makeRandomNonce() {
        byte[] bytes = new byte[24];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return bytes;
    }

    public byte[] encode(byte[] plaintext, byte[] nonce) {

        ByteBuffer header = ByteBuffer.allocate(1 + 4 + 24);

        /*
            Version (1B)
         */
        header.put(0, VERSION);
        header.position(1);

        /*
            Timestamp (4B)
         */
        byte[] timestamp = makeTimestamp();
        header.put(timestamp, 0, timestamp.length);
        header.position(5);

        /*
            Nonce (24B)
         */
        header.put(nonce, 0, nonce.length);
        header.position(29);

        /*
            Ciphertext (*B)
         */
        byte[] cipherAndTag = encrypt(header.array(), plaintext, nonce);

        byte[] headerAndCipher = addAll(header.array(), cipherAndTag);

        return base62Encode(headerAndCipher);
    }

    private static byte[] addAll(final byte[] one, byte[] two) {
        byte[] ret = Arrays.copyOf(one, one.length + two.length);
        System.arraycopy(two, 0, ret, one.length, two.length);
        return ret;
    }

    private static byte[] makeTimestamp() {
        return bigEndian(unixTimeNow());
    }

    private static byte[] base62Encode(byte[] input) {
        return Base62.createInstance().encode(input);
    }

    private byte[] encrypt(byte[] header, byte[] plaintext, byte[] nonce) {
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);
        StreamCipher engine = new XChaCha20Engine();

        engine.init(true, params);
        byte[] encrypted = new byte[plaintext.length + TAG_LENGTH];

        engine.processBytes(plaintext, 0, plaintext.length, encrypted, 0);

        /*
            Generate Poly13509 and append to cipher
         */
        final Poly1305 poly1305 = new Poly1305();
        poly1305.init(cp);
        poly1305.update(header, 0, header.length);
        poly1305.doFinal(encrypted, plaintext.length);
        return encrypted;
    }

    private byte[] decrypt(byte[] header, byte[] plaintext, byte[] nonce, byte[] mac) {
        CipherParameters cp = new KeyParameter(key);
        ParametersWithIV params = new ParametersWithIV(cp, nonce);


        byte[] headerMac = new byte[16];
        final Poly1305 poly1305 = new Poly1305();
        poly1305.init(cp);
        poly1305.update(header, 0, header.length);
        poly1305.doFinal(headerMac, 0);

        if (!Arrays.equals(headerMac, mac)) {
            throw new RuntimeException("Auth failed");
        }

        StreamCipher engine = new XChaCha20Engine();
        engine.init(false, params);
        byte[] decrypted = new byte[plaintext.length];
        engine.processBytes(plaintext, 0, plaintext.length, decrypted, 0);
        return decrypted;
    }

    private void checkPoly1305(byte[] plaintext, byte[] nonce, byte[] untrustedMac) {

    }

    public byte[] decode(byte[] token) {
        byte[] decoded = Base62.createInstance().decode(token);
        if (decoded[0] != VERSION) {
            throw new RuntimeException("Not a valid version");
        }

        byte[] cypherText = Arrays.copyOfRange(decoded, HEADER_LENGTH, decoded.length);
        byte[] nonce = Arrays.copyOfRange(decoded, 5, decoded.length - cypherText.length);
        byte[] tag = Arrays.copyOfRange(decoded, decoded.length - TAG_LENGTH, decoded.length);
        byte[] header = Arrays.copyOfRange(decoded, 0, HEADER_LENGTH);
        byte[] decrypted = decrypt(header, cypherText, nonce, tag);
        return Arrays.copyOfRange(decrypted, 0, decrypted.length - 16);
    }
}
