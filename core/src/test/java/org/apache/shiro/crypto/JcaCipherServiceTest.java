package org.apache.shiro.crypto;

import static org.junit.Assert.*;

import org.junit.Test;

public class JcaCipherServiceTest {

    @Test
    public void testDecrypt() {
	JcaCipherService cipherService = new JcaCipherService("AES") {};
	String ciphertext = "iv_helloword";
	String key = "somekey";
	try {
	    // This should cause ArrayIndexOutOfBoundsException, at least currently that's what we want
	    cipherService.decrypt(ciphertext.getBytes(), key.getBytes());
	} catch (CryptoException e) {
	    return;
	}
        fail("CryptoException was expected to be thrown");
    }

}
