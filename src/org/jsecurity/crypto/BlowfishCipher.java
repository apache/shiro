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
package org.jsecurity.crypto;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
 * same <tt>Key</tt> to both encrypt and decrypt data.  If one is not provided via the {@link #setDefaultKey setKey} method,
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
 * <tt>Key</tt> via the {@link # setDefaultKey setKey} method to a Key known only to your application, guaranteeing that no
 * third party can decrypt your data.  If you want to know how to do this, you can browse this class's source code
 * for the {@link #generateNewKey()} method to see how we created our default.  Then you can duplicate the same in
 * your environment and set the result on an instance of this class via the <code>setKey</code> method.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
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

    protected transient final Log log = LogFactory.getLog(getClass());

    private Key defaultKey = DEFAULT_CIPHER_KEY;

    public BlowfishCipher() {
    }

    public Key getDefaultKey() {
        return defaultKey;
    }

    public void setDefaultKey(Key defaultKey) {
        this.defaultKey = defaultKey;
    }

    public byte[] encrypt(byte[] raw, byte[] key) {
        byte[] encrypted = crypt(raw, javax.crypto.Cipher.ENCRYPT_MODE, key);
        if (log.isTraceEnabled()) {
            log.trace("Incoming byte array of size " + (raw != null ? raw.length : 0) + ".  Encrypted " +
                    "byte array is size " + (encrypted != null ? encrypted.length : 0));
        }
        return encrypted;
    }

    public byte[] decrypt(byte[] encrypted, byte[] key) {
        if (log.isTraceEnabled()) {
            log.trace("Attempting to decrypt incoming byte array of length " +
                    (encrypted != null ? encrypted.length : 0));
        }
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
            throw new IllegalStateException(msg, e);
        }
    }

    protected byte[] crypt(javax.crypto.Cipher cipher, byte[] bytes) {
        try {
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            String msg = "Unable to crypt bytes with cipher [" + cipher + "].";
            throw new IllegalStateException(msg, e);
        }
    }

    protected byte[] crypt(byte[] bytes, int mode, byte[] key) {
        javax.crypto.Cipher cipher = newCipherInstance();

        java.security.Key jdkKey;
        if (key == null) {
            jdkKey = getDefaultKey();
        } else {
            jdkKey = new SecretKeySpec(key, ALGORITHM);
        }

        init(cipher, mode, jdkKey);
        return crypt(cipher, bytes);
    }

    public static Key generateNewKey() {
        return generateNewKey(128);
    }

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
