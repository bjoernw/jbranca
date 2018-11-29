package org.bjoern.jbranca;

import org.junit.Assert;
import org.junit.Test;

import java.util.Random;

public class BrancaTokenFactoryTest {

    @Test
    public void encode() {
        for (int i = 0; i < 5; i++) {
            byte[] key = new byte[32];
            new Random().nextBytes(key);
            BrancaTokenFactory factory = new BrancaTokenFactory(key);
            String plaintext = "{\"imajwt\": \"imajwt\"}";
            byte[] encoded = factory.seal(plaintext.getBytes());
            byte[] decoded = factory.open(encoded);
            Assert.assertEquals(plaintext, new String(decoded));
        }
    }
}