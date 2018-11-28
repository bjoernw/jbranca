package org.bjoern.jbranca;

import org.junit.Assert;
import org.junit.Test;

import java.util.Random;

public class BrancaTokenFactoryTest {

    @Test
    public void encode() {
        for (int i = 0; i < 10; i++) {
            byte[] key = new byte[32];
            new Random().nextBytes(key);
            BrancaTokenFactory factory = new BrancaTokenFactory(key);
            String plaintext = "encrypt me";
            byte[] encoded = factory.encode(plaintext.getBytes());
            byte[] decoded = factory.decode(encoded);
            Assert.assertEquals(plaintext, new String(decoded));
        }
    }
}