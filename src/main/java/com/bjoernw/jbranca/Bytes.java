/**
 *
 *  Copyright © 2018 Bjoern Weidlich <bjoernweidlich@gmail.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.bjoernw.jbranca;

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
