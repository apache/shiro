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

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
 * @since 0.9
 */
public class BlowfishCipher implements Cipher {

    private static final String ALGORITHM = "Blowfish";

    private static final String TRANSFORMATION_STRING = ALGORITHM + "/ECB/PKCS5Padding";

    //The following KEY_BYTES String was created by running
    //System.out.println( Base64.encode( generateNewKey().getEncoded() ) ); and copying-n-pasting the output here.
    //You should run the same and set the resulting output as a property of this class instead of using
    //JSecurity's default Key for proper security.
    private static final byte[] KEY_BYTES = Base64.decode("jJ9Kg1BAevbvhSg3vBfwfQ==");
    private static final Key DEFAULT_CIPHER_KEY = new SecretKeySpec(KEY_BYTES, ALGORITHM);

    private Key key = DEFAULT_CIPHER_KEY;

    public BlowfishCipher() {
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
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
        init(cipher, mode, jdkKey);
        return crypt(cipher, bytes);
    }

    public static Key generateNewKey() {
        return generateNewKey(128);
    }

    public static Key generateNewKey( int keyBitSize ) {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance( ALGORITHM );
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to acquire " + ALGORITHM + " algorithm.  This is required to function.";
            throw new IllegalStateException(msg,e);
        }
        kg.init(keyBitSize);
        return kg.generateKey();
    }

    public static void main(String[] unused) throws Exception {

        Cipher cipher = new BlowfishCipher();

        String[] cleartext = new String[]{
                "Hello, this is a test.",
                "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        };

        for (String clear : cleartext) {
            byte[] cleartextBytes = CodecSupport.toBytes(clear);
            System.out.println("Clear text: [" + clear + "]");
            System.out.println("Clear text base64: [" + Base64.encodeToString(cleartextBytes) + "]");

            byte[] encrypted = cipher.encrypt(cleartextBytes, null);
            String encryptedBase64 = Base64.encodeToString(encrypted);
            System.out.println("Encrypted base64: [" + encryptedBase64 + "]");

            byte[] decrypted = cipher.decrypt(Base64.decode(encryptedBase64), null);
            String decryptedString = CodecSupport.toString(decrypted);

            System.out.println("Arrays equal? " + Arrays.equals(cleartextBytes, decrypted));

            System.out.println("Decrypted text: [" + decryptedString + "]");
            System.out.println("Decrypted text base64: [" + Base64.encodeToString(decrypted) + "]");
        }
    }
}
