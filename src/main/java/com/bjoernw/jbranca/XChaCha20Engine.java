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

import org.bouncycastle.crypto.engines.ChaChaEngine;

/**
 * We want to use a 24 byte nonce because that's what the Branca standard calls for.
 */
class XChaCha20Engine extends ChaChaEngine {

    private final static int NONCE_SIZE_BYTES = 24;

    XChaCha20Engine() {
        super(20);
    }

    public String getAlgorithmName() {
        return "XChaCha20";
    }

    protected int getNonceSize() {
        return NONCE_SIZE_BYTES;
    }

}