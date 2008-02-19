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
package org.jsecurity.crypto;

import org.jsecurity.codec.Base64;
import org.jsecurity.codec.CodecSupport;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.util.Arrays;

/**
 * JSecurity's default symmetric block Cipher using the Blowfish algorithm.  As it is a symmetric Cipher, it uses the
 * same <tt>Key</tt> to both encrypt and decrypt data.  If one is not provided via the {@link #setKey setKey} method,
 * a default one will be used, BUT NOTE:
 *
 * <p>Because JSecurity is an open-source project, if anyone knew that you were using JSecurity's default blowfish
 * cipher, they could download/view the source, and with enough effort, reconstruct the <tt>Key</tt> and decode
 * encrypted data at will.
 *
 * <p>JSecurity only really uses Ciphers to encrypt user ids and session ids, so if that information is not critical to
 * you, you might not worry about this Key issue.
 *
 * <p>However, it is hightly recommended that you provide your own <tt>Key</tt> via the {@link #setKey setKey} method
 * to a Key known only to your application, guaranteeing that no third party can decrypt your data.  If you want to
 * know how to do this, you can browse this class's source code for the <code>public static void main(String[] args)</code>
 * method to see how we created our default.  Then you can duplicate the same in your environment and set the
 * result on an instance of this class via the <tt>setKey</tt> method.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SimpleBlowfishCipher implements Cipher {

    private static final String ALGORITHM = "Blowfish";

    private static final String TRANSFORMATION_STRING = ALGORITHM + "/ECB/PKCS5Padding";

    //created by running the test program below
    private static final byte[] KEY_BYTES = Base64.decodeBase64("jJ9Kg1BAevbvhSg3vBfwfQ==");
    private static final JdkKey DEFAULT_CIPHER_KEY = new JdkKey( new SecretKeySpec( KEY_BYTES, ALGORITHM ) );

    private JdkKey key = DEFAULT_CIPHER_KEY;

    public SimpleBlowfishCipher() {
    }

    public JdkKey getKey() {
        return key;
    }

    public void setKey(JdkKey key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] raw, Key key) {
        return crypt(raw, javax.crypto.Cipher.ENCRYPT_MODE, key);
    }

    public byte[] decrypt(byte[] encrypted, Key key) {
        return crypt(encrypted, javax.crypto.Cipher.DECRYPT_MODE, key);
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

    protected byte[] crypt(byte[] bytes, int mode, Key key) {
        javax.crypto.Cipher cipher = newCipherInstance();
        java.security.Key jdkKey = getKey();
        if ( key != null ) {
            if ( key instanceof java.security.Key ) {
                jdkKey = (java.security.Key)key;
            } else {
                String msg = "The " + getClass().getName() + " implementation only accepts " + Key.class.getName() +
                        " instances that also implement the " + java.security.Key.class.getName() +
                        " interface.  The argument used is of type [" + key.getClass().getName() + "].";
                throw new IllegalArgumentException( msg );
            }
        }
        init(cipher, mode, jdkKey);
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

        Cipher cipher = new SimpleBlowfishCipher();

        String[] cleartext = new String[]{
            "Hello, this is a test.",
            "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        };

        for (String clear : cleartext) {
            byte[] cleartextBytes = CodecSupport.toBytes(clear);
            System.out.println("Clear text: [" + clear + "]");
            System.out.println("Clear text base64: [" + Base64.encodeBase64ToString(cleartextBytes) + "]");

            byte[] encrypted = cipher.encrypt(cleartextBytes, null);
            String encryptedBase64 = Base64.encodeBase64ToString( encrypted );
            System.out.println("Encrypted base64: [" + encryptedBase64 + "]");

            byte[] decrypted = cipher.decrypt(Base64.decodeBase64(encryptedBase64), null);
            String decryptedString = CodecSupport.toString(decrypted);

            System.out.println("Arrays equal? " + Arrays.equals(cleartextBytes, decrypted));

            System.out.println("Decrypted text: [" + decryptedString + "]");
            System.out.println("Decrypted text base64: [" + Base64.encodeBase64ToString(decrypted) + "]");
        }
    }
}
