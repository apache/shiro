/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.ki.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.ki.codec.Base64;
import org.ki.codec.CodecSupport;

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
 * <p>Because JSecurity is an open-source project, if anyone knew that you were using JSecurity's default
 * <code>Key</code>, they could download/view the source, and with enough effort, reconstruct the <code>Key</code>
 * and decode encrypted data at will.
 *
 * <p>JSecurity only really uses Ciphers to encrypt user ids and session ids, so if that information is not critical
 * to you and you think the default key still makes things 'sufficiently difficult', then you can ignore this issue.
 *
 * <p>However, if you do feel this constitutes sensitive information, it is recommended that you provide your own
 * <tt>Key</tt> via the {@link #setKey setKey} method to a Key known only to your application,
 * guaranteeing that no third party can decrypt your data.  If you want to know how to do this, you can browse this
 * class's source code for the {@link #generateNewKey()} method to see how we created our default.  Then you can
 * duplicate the same in your environment and set the result on an instance of this class via the
 * <code>setKey</code> method.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public class BlowfishCipher implements Cipher {

    /**
     * The JDK Crypto Cipher algorithm to use for this class, equal to &quot;Blowfish&quot;.
     */
    private static final String ALGORITHM = "Blowfish";

    /**
     * The JDK Crypto Transformation string to use for this class, equal to {@link #ALGORITHM ALGORITHM} + &quot;/ECB/PKCS5Padding&quot;;
     */
    private static final String TRANSFORMATION_STRING = ALGORITHM + "/ECB/PKCS5Padding";

    //The following KEY_BYTES String was created by running
    //System.out.println( Base64.encode( generateNewKey().getEncoded() ) ); and copying-n-pasting the output here.
    //You should run the same and set the resulting output as a property of this class instead of using
    //JSecurity's default Key for proper security.
    private static final byte[] KEY_BYTES = Base64.decode("jJ9Kg1BAevbvhSg3vBfwfQ==");
    private static final Key DEFAULT_CIPHER_KEY = new SecretKeySpec(KEY_BYTES, ALGORITHM);

    /**
     * Internal private log instance.
     */
    private static final Log log = LogFactory.getLog(BlowfishCipher.class);

    /**
     * The key to use by default, can be overridden by calling {@link #setKey(java.security.Key)}.
     */
    private Key key = DEFAULT_CIPHER_KEY;

    /**
     * Default no argument constructor that uses an internal default {@link #getKey() key} to use during
     * encryption and decryption.  For propery security, you should definitely supply your own key by using the
     * {@link #setKey(java.security.Key) setKey(Key)} method.
     */
    public BlowfishCipher() {
    }

    /**
     * Returns the default {@link Key Key} to use for symmetric encryption and decryption if one is not specified during
     * encryption/decryption.  For truly secure applications,
     * you should always specify your own key via the {@link #setKey(java.security.Key) setKey} method.
     *
     * @return the {@link Key Key} to use for symmetric encryption and decryption.
     * @see #encrypt(byte[], byte[])
     * @see #decrypt(byte[], byte[])
     */
    public Key getKey() {
        return key;
    }

    /**
     * Sets the internal default {@link Key Key} to use for symmetric encryption and decryption if one is not
     * specified during encryption/decryption.   For truly secure applications, you should always specify your own
     * key via this method.
     *
     * @param key the key to use for symmetric encryption and decryption.
     * @see #encrypt(byte[], byte[])
     * @see #decrypt(byte[], byte[])
     */
    public void setKey(Key key) {
        this.key = key;
    }

    /**
     * Encrypts the specified raw byte array.  If the <code>key</code> argument is null, the internal default
     * {@link #getKey() key} will be used to encrypt the byte array.
     */
    public byte[] encrypt(byte[] raw, byte[] key) {
        byte[] encrypted = crypt(raw, javax.crypto.Cipher.ENCRYPT_MODE, key);
        if (log.isTraceEnabled()) {
            log.trace("Incoming byte array of size " + (raw != null ? raw.length : 0) + ".  Encrypted " +
                    "byte array is size " + (encrypted != null ? encrypted.length : 0));
        }
        return encrypted;
    }

    /**
     * Decrypts the specified already-encrypted byte array.  If the <code>key</code> argument is null, the internal default
     * {@link #getKey() key} will be used to encrypt the byte array.
     */
    public byte[] decrypt(byte[] encrypted, byte[] key) {
        if (log.isTraceEnabled()) {
            log.trace("Attempting to decrypt incoming byte array of length " +
                    (encrypted != null ? encrypted.length : 0));
        }
        return crypt(encrypted, javax.crypto.Cipher.DECRYPT_MODE, key);
    }

    /**
     * Returns a new {@link javax.crypto.Cipher Cipher} instance to use for encryption/decryption operations, based on
     * the {@link #TRANSFORMATION_STRING TRANSFORMATION_STRING} constant.
     *
     * @return a new Cipher instance.
     * @throws IllegalStateException if a new Cipher instance cannot be constructed based on the
     *                               {@link #TRANSFORMATION_STRING TRANSFORMATION_STRING} constant.
     */
    protected javax.crypto.Cipher newCipherInstance() throws IllegalStateException {
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

    /**
     * Initializes the JDK Cipher with the specified mode and key.  This is primarily a utility method to catch any
     * potential {@link InvalidKeyException InvalidKeyException} that might arise.
     *
     * @param cipher the JDK Cipher to {@link javax.crypto.Cipher#init(int, java.security.Key) init}.
     * @param mode   the Cipher mode
     * @param key    the Cipher's Key
     */
    protected void init(javax.crypto.Cipher cipher, int mode, java.security.Key key) {
        try {
            cipher.init(mode, key);
        } catch (InvalidKeyException e) {
            String msg = "Unable to init cipher.";
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * Calls the {@link javax.crypto.Cipher#doFinal(byte[]) doFinal(bytes)} method, propagating any exception that
     * might arise in an {@link IllegalStateException IllegalStateException}
     *
     * @param cipher the JDK Cipher to finalize (perform the actual cryption)
     * @param bytes  the bytes to crypt
     * @return the resulting crypted byte array.
     */
    protected byte[] crypt(javax.crypto.Cipher cipher, byte[] bytes) {
        try {
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            String msg = "Unable to crypt bytes with cipher [" + cipher + "].";
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * Calls the {@link #init(javax.crypto.Cipher, int, java.security.Key)} and then
     * {@link #crypt(javax.crypto.Cipher, byte[])}.  Ensures that the key is never null by using the
     * {@link #getKey() default key} if the method argument key is <code>null</code>.
     *
     * @param bytes the bytes to crypt
     * @param mode  the JDK Cipher mode
     * @param key   the key to use to do the cryption.  If <code>null</code> the {@link #getKey() default key} will be used.
     * @return the resulting crypted byte array
     */
    protected byte[] crypt(byte[] bytes, int mode, byte[] key) {
        javax.crypto.Cipher cipher = newCipherInstance();

        java.security.Key jdkKey;
        if (key == null) {
            jdkKey = getKey();
        } else {
            jdkKey = new SecretKeySpec(key, ALGORITHM);
        }

        init(cipher, mode, jdkKey);
        return crypt(cipher, bytes);
    }

    /**
     * Generates a new {@link Key Key} suitable for this Cipher by calling
     * {@link #generateNewKey(int) generateNewKey(128)} (uses a 128 bit size by default).
     *
     * @return a new {@link Key Key}, 128 bits in length.
     */
    public static Key generateNewKey() {
        return generateNewKey(128);
    }

    /**
     * Generates a new {@link Key Key} of the specified size suitable for this Cipher
     * (based on the {@link #ALGORITHM ALGORITHM} using the JDK {@link KeyGenerator KeyGenerator}.
     *
     * @param keyBitSize the bit size of the key to create
     * @return the created key suitable for use with this Cipher.
     */
    public static Key generateNewKey(int keyBitSize) {
        KeyGenerator kg;
        try {
            kg = KeyGenerator.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            String msg = "Unable to acquire " + ALGORITHM + " algorithm.  This is required to function.";
            throw new IllegalStateException(msg, e);
        }
        kg.init(keyBitSize);
        return kg.generateKey();
    }

    /**
     * Simple test main method to ensure functionality is correct.  Should really be moved to a proper test case.
     *
     * @param unused ignored
     * @throws Exception if anything unexpected happens.
     */
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
