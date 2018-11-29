package org.bjoern.jbranca;

import io.seruco.encoding.base62.Base62;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

class Bytes {
    private Bytes() {
    }

    static byte[] makeRandomNonce() {
        byte[] bytes = new byte[24];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        return bytes;
    }

    static byte[] addAll(final byte[] one, byte[] two) {
        byte[] ret = Arrays.copyOf(one, one.length + two.length);
        System.arraycopy(two, 0, ret, one.length, two.length);
        return ret;
    }

    static byte[] base62Encode(byte[] input) {
        return Base62.createInstance().encode(input);
    }
}
