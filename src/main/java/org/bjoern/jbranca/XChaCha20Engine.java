package org.bjoern.jbranca;

import org.bouncycastle.crypto.engines.ChaChaEngine;

public class XChaCha20Engine extends ChaChaEngine {

    public final static int NONCE_SIZE_BYTES = 24;

    public XChaCha20Engine() {
        super(20);
    }

    public String getAlgorithmName() {
        return "XChaCha20";
    }

    protected int getNonceSize() {
        return NONCE_SIZE_BYTES;
    }

}