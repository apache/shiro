/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.crypto.support;

import org.jsecurity.codec.Base64;
import org.jsecurity.codec.Hex;
import org.jsecurity.codec.support.CodecSupport;
import org.jsecurity.crypto.SymmetricCipher;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public class SimpleBlowfishCipher implements SymmetricCipher {

    private static final String ALGORITHM = "Blowfish";

    private static final String TRANSFORMATION_STRING = ALGORITHM + "/ECB/PKCS5Padding";

    //created by running the test program below
    private static final byte[] KEY_BYTES = Base64.decodeBase64("jJ9Kg1BAevbvhSg3vBfwfQ==");

    private static final javax.crypto.SecretKey CIPHER_KEY = new SecretKeySpec(KEY_BYTES, ALGORITHM);

    public byte[] encrypt(byte[] raw) {
        return crypt(raw, javax.crypto.Cipher.ENCRYPT_MODE);
    }

    public byte[] decrypt(byte[] encrypted) {
        return crypt(encrypted, javax.crypto.Cipher.DECRYPT_MODE);
    }

    protected javax.crypto.Cipher newCipherInstance() {
        try {
            return javax.crypto.Cipher.getInstance(TRANSFORMATION_STRING);
        } catch (Exception e) {
            String msg = "Unable to acquire a Java JCE Cipher instance using " +
                javax.crypto.Cipher.class.getName() + ".getInstance( \"" + TRANSFORMATION_STRING + "\" ). " +
                "Blowfish under this configuration is required for the " +
                getClass().getName() + " instance to function.";
            throw new IllegalStateException(msg, e);
        }
    }

    protected void init(javax.crypto.Cipher cipher, int mode, java.security.Key key) {
        try {
            cipher.init(mode, key);
        } catch (InvalidKeyException e) {
            String msg = "Unable to init cipher.";
            throw new IllegalStateException(msg);
        }
    }

    protected byte[] crypt(javax.crypto.Cipher cipher, byte[] bytes) {
        try {
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            String msg = "Unable to crypt bytes with cipher [" + cipher + "].";
            throw new IllegalStateException(msg);
        }
    }

    protected byte[] crypt(byte[] bytes, int mode) {
        javax.crypto.Cipher cipher = newCipherInstance();
        init(cipher, mode, CIPHER_KEY);
        return crypt(cipher, bytes);
    }

    public static void main(String[] unused) throws Exception {

        /* Commented out - only used to generate a a new permanent KEY_BYTES constant
        // Generate a secret key
        KeyGenerator kg = KeyGenerator.getInstance( ALGORITHM );
        kg.init(128); //using a 128 bit key size
        SecretKey key = kg.generateKey();

        String algorithm = key.getAlgorithm();
        byte[] keyData = key.getEncoded();
        //the following output in between the brackets is copied-and-pasted into this class's KEY_BYTES line of code.
        //This constant is the embedded key used to symmetrically encode/decode data.
        System.out.println("Base64 encoded keyData: [" + Base64.encodeBytes(keyData) + "]");
        */

        SymmetricCipher cipher = new SimpleBlowfishCipher();

        String[] cleartext = new String[]{
            "Hello, this is a test.",
            "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
            "日本の旅行のとき僕はいつも楽しみます"
        };

        for (String clear : cleartext) {
            byte[] cleartextBytes = CodecSupport.toBytes(clear);
            System.out.println("Clear text: [" + clear + "]");
            System.out.println("Clear text hex: [" + Hex.encodeToString(cleartextBytes) + "]");

            byte[] encrypted = cipher.encrypt(cleartextBytes);
            String encryptedHex = Hex.encodeToString(encrypted);
            System.out.println("Encrypted hex: [" + encryptedHex + "]");

            byte[] decrypted = cipher.decrypt(Hex.decode(encryptedHex));
            String decryptedString = CodecSupport.toString(decrypted);

            System.out.println("Arrays equal? " + Arrays.equals(cleartextBytes, decrypted));

            System.out.println("Decrypted text: [" + decryptedString + "]");
            System.out.println("Decrypted text hex: [" + Hex.encodeToString(decrypted) + "]");
        }
    }
}
