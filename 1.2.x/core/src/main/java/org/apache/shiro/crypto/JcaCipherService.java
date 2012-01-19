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
package org.apache.shiro.crypto;

import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.CipherInputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Abstract {@code CipherService} implementation utilizing Java's JCA APIs.
 * <h2>Auto-generated Initialization Vectors</h2>
 * Shiro does something by default for all of its {@code CipherService} implementations that the JCA
 * {@link javax.crypto.Cipher Cipher} does not do:  by default,
 * <a href="http://en.wikipedia.org/wiki/Initialization_vector">initialization vector</a>s are automatically randomly
 * generated and prepended to encrypted data before returning from the {@code encrypt} methods.  That is, the returned
 * byte array or {@code OutputStream} is actually a concatenation of an initialization vector byte array plus the actual
 * encrypted data byte array.  The {@code decrypt} methods in turn know to read this prepended initialization vector
 * before decrypting the real data that follows.
 * <p/>
 * This is highly desirable because initialization vectors guarantee that, for a key and any plaintext, the encrypted
 * output will always be different <em>even if you call {@code encrypt} multiple times with the exact same arguments</em>.
 * This is essential in cryptography to ensure that data patterns cannot be identified across multiple input sources
 * that are the same or similar.
 * <p/>
 * You can turn off this behavior by setting the
 * {@link #setGenerateInitializationVectors(boolean) generateInitializationVectors} property to {@code false}, but it
 * is highly recommended that you do not do this unless you have a very good reason to do so, since you would be losing
 * a critical security feature.
 * <h3>Initialization Vector Size</h3>
 * This implementation defaults the {@link #setInitializationVectorSize(int) initializationVectorSize} attribute to
 * {@code 128} bits, a fairly common size.  Initialization vector sizes are very algorithm specific however, so subclass
 * implementations will often override this value in their constructor if necessary.
 * <p/>
 * Also note that {@code initializationVectorSize} values are specified in the number of
 * bits (not bytes!) to match common references in most cryptography documentation.  In practice though, initialization
 * vectors are always specified as a byte array, so ensure that if you set this property, that the value is a multiple
 * of {@code 8} to ensure that the IV can be correctly represented as a byte array (the
 * {@link #setInitializationVectorSize(int) setInitializationVectorSize} mutator method enforces this).
 *
 * @since 1.0
 */
public abstract class JcaCipherService implements CipherService {

    /**
     * Internal private log instance.
     */
    private static final Logger log = LoggerFactory.getLogger(JcaCipherService.class);

    /**
     * Default key size (in bits) for generated keys.
     */
    private static final int DEFAULT_KEY_SIZE = 128;

    /**
     * Default size of the internal buffer (in bytes) used to transfer data between streams during stream operations
     */
    private static final int DEFAULT_STREAMING_BUFFER_SIZE = 512;

    private static final int BITS_PER_BYTE = 8;

    /**
     * Default SecureRandom algorithm name to use when acquiring the SecureRandom instance.
     */
    private static final String RANDOM_NUM_GENERATOR_ALGORITHM_NAME = "SHA1PRNG";

    /**
     * The name of the cipher algorithm to use for all encryption, decryption, and key operations
     */
    private String algorithmName;

    /**
     * The size in bits (not bytes) of generated cipher keys
     */
    private int keySize;

    /**
     * The size of the internal buffer (in bytes) used to transfer data from one stream to another during stream operations
     */
    private int streamingBufferSize;

    private boolean generateInitializationVectors;
    private int initializationVectorSize;


    private SecureRandom secureRandom;

    /**
     * Creates a new {@code JcaCipherService} instance which will use the specified cipher {@code algorithmName}
     * for all encryption, decryption, and key operations.  Also, the following defaults are set:
     * <ul>
     * <li>{@link #setKeySize keySize} = 128 bits</li>
     * <li>{@link #setInitializationVectorSize(int) initializationVectorSize} = 128 bits</li>
     * <li>{@link #setStreamingBufferSize(int) streamingBufferSize} = 512 bytes</li>
     * </ul>
     *
     * @param algorithmName the name of the cipher algorithm to use for all encryption, decryption, and key operations
     */
    protected JcaCipherService(String algorithmName) {
        if (!StringUtils.hasText(algorithmName)) {
            throw new IllegalArgumentException("algorithmName argument cannot be null or empty.");
        }
        this.algorithmName = algorithmName;
        this.keySize = DEFAULT_KEY_SIZE;
        this.initializationVectorSize = DEFAULT_KEY_SIZE; //default to same size as the key size (a common algorithm practice)
        this.streamingBufferSize = DEFAULT_STREAMING_BUFFER_SIZE;
        this.generateInitializationVectors = true;
    }

    /**
     * Returns the cipher algorithm name that will be used for all encryption, decryption, and key operations (for
     * example, 'AES', 'Blowfish', 'RSA', 'DSA', 'TripleDES', etc).
     *
     * @return the cipher algorithm name that will be used for all encryption, decryption, and key operations
     */
    public String getAlgorithmName() {
        return algorithmName;
    }

    /**
     * Returns the size in bits (not bytes) of generated cipher keys.
     *
     * @return the size in bits (not bytes) of generated cipher keys.
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Sets the size in bits (not bytes) of generated cipher keys.
     *
     * @param keySize the size in bits (not bytes) of generated cipher keys.
     */
    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public boolean isGenerateInitializationVectors() {
        return generateInitializationVectors;
    }

    public void setGenerateInitializationVectors(boolean generateInitializationVectors) {
        this.generateInitializationVectors = generateInitializationVectors;
    }

    /**
     * Returns the algorithm-specific size in bits of generated initialization vectors.
     *
     * @return the algorithm-specific size in bits of generated initialization vectors.
     */
    public int getInitializationVectorSize() {
        return initializationVectorSize;
    }

    /**
     * Sets the algorithm-specific initialization vector size in bits (not bytes!) to be used when generating
     * initialization vectors.  The  value must be a multiple of {@code 8} to ensure that the IV can be represented
     * as a byte array.
     *
     * @param initializationVectorSize the size in bits (not bytes) of generated initialization vectors.
     * @throws IllegalArgumentException if the size is not a multiple of {@code 8}.
     */
    public void setInitializationVectorSize(int initializationVectorSize) throws IllegalArgumentException {
        if (initializationVectorSize % BITS_PER_BYTE != 0) {
            String msg = "Initialization vector sizes are specified in bits, but must be a multiple of 8 so they " +
                    "can be easily represented as a byte array.";
            throw new IllegalArgumentException(msg);
        }
        this.initializationVectorSize = initializationVectorSize;
    }

    protected boolean isGenerateInitializationVectors(boolean streaming) {
        return isGenerateInitializationVectors();
    }

    /**
     * Returns the size in bytes of the internal buffer used to transfer data from one stream to another during stream
     * operations ({@link #encrypt(java.io.InputStream, java.io.OutputStream, byte[])} and
     * {@link #decrypt(java.io.InputStream, java.io.OutputStream, byte[])}).
     * <p/>
     * Default size is {@code 512} bytes.
     *
     * @return the size of the internal buffer used to transfer data from one stream to another during stream
     *         operations
     */
    public int getStreamingBufferSize() {
        return streamingBufferSize;
    }

    /**
     * Sets the size in bytes of the internal buffer used to transfer data from one stream to another during stream
     * operations ({@link #encrypt(java.io.InputStream, java.io.OutputStream, byte[])} and
     * {@link #decrypt(java.io.InputStream, java.io.OutputStream, byte[])}).
     * <p/>
     * Default size is {@code 512} bytes.
     *
     * @param streamingBufferSize the size of the internal buffer used to transfer data from one stream to another
     *                            during stream operations
     */
    public void setStreamingBufferSize(int streamingBufferSize) {
        this.streamingBufferSize = streamingBufferSize;
    }

    /**
     * Returns a source of randomness for encryption operations.  If one is not configured, and the underlying
     * algorithm needs one, the JDK {@code SHA1PRNG} instance will be used by default.
     *
     * @return a source of randomness for encryption operations.  If one is not configured, and the underlying
     *         algorithm needs one, the JDK {@code SHA1PRNG} instance will be used by default.
     */
    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    /**
     * Sets a source of randomness for encryption operations.  If one is not configured, and the underlying
     * algorithm needs one, the JDK {@code SHA1PRNG} instance will be used by default.
     *
     * @param secureRandom a source of randomness for encryption operations.  If one is not configured, and the
     *                     underlying algorithm needs one, the JDK {@code SHA1PRNG} instance will be used by default.
     */
    public void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    protected static SecureRandom getDefaultSecureRandom() {
        try {
            return java.security.SecureRandom.getInstance(RANDOM_NUM_GENERATOR_ALGORITHM_NAME);
        } catch (java.security.NoSuchAlgorithmException e) {
            log.debug("The SecureRandom SHA1PRNG algorithm is not available on the current platform.  Using the " +
                    "platform's default SecureRandom algorithm.", e);
            return new java.security.SecureRandom();
        }
    }

    protected SecureRandom ensureSecureRandom() {
        SecureRandom random = getSecureRandom();
        if (random == null) {
            random = getDefaultSecureRandom();
        }
        return random;
    }

    /**
     * Returns the transformation string to use with the {@link javax.crypto.Cipher#getInstance} invocation when
     * creating a new {@code Cipher} instance.  This default implementation always returns
     * {@link #getAlgorithmName() getAlgorithmName()}.  Block cipher implementations will want to override this method
     * to support appending cipher operation modes and padding schemes.
     *
     * @param streaming if the transformation string is going to be used for a Cipher for stream-based encryption or not.
     * @return the transformation string to use with the {@link javax.crypto.Cipher#getInstance} invocation when
     *         creating a new {@code Cipher} instance.
     */
    protected String getTransformationString(boolean streaming) {
        return getAlgorithmName();
    }

    protected byte[] generateInitializationVector(boolean streaming) {
        int size = getInitializationVectorSize();
        if (size <= 0) {
            String msg = "initializationVectorSize property must be greater than zero.  This number is " +
                    "typically set in the " + CipherService.class.getSimpleName() + " subclass constructor.  " +
                    "Also check your configuration to ensure that if you are setting a value, it is positive.";
            throw new IllegalStateException(msg);
        }
        if (size % BITS_PER_BYTE != 0) {
            String msg = "initializationVectorSize property must be a multiple of 8 to represent as a byte array.";
            throw new IllegalStateException(msg);
        }
        int sizeInBytes = size / BITS_PER_BYTE;
        byte[] ivBytes = new byte[sizeInBytes];
        SecureRandom random = ensureSecureRandom();
        random.nextBytes(ivBytes);
        return ivBytes;
    }

    public ByteSource encrypt(byte[] plaintext, byte[] key) {
        byte[] ivBytes = null;
        boolean generate = isGenerateInitializationVectors(false);
        if (generate) {
            ivBytes = generateInitializationVector(false);
            if (ivBytes == null || ivBytes.length == 0) {
                throw new IllegalStateException("Initialization vector generation is enabled - generated vector" +
                        "cannot be null or empty.");
            }
        }
        return encrypt(plaintext, key, ivBytes, generate);
    }

    private ByteSource encrypt(byte[] plaintext, byte[] key, byte[] iv, boolean prependIv) throws CryptoException {

        final int MODE = javax.crypto.Cipher.ENCRYPT_MODE;

        byte[] output;

        if (prependIv && iv != null && iv.length > 0) {

            byte[] encrypted = crypt(plaintext, key, iv, MODE);

            output = new byte[iv.length + encrypted.length];

            //now copy the iv bytes + encrypted bytes into one output array:

            // iv bytes:
            System.arraycopy(iv, 0, output, 0, iv.length);

            // + encrypted bytes:
            System.arraycopy(encrypted, 0, output, iv.length, encrypted.length);
        } else {
            output = crypt(plaintext, key, iv, MODE);
        }

        if (log.isTraceEnabled()) {
            log.trace("Incoming plaintext of size " + (plaintext != null ? plaintext.length : 0) + ".  Ciphertext " +
                    "byte array is size " + (output != null ? output.length : 0));
        }

        return ByteSource.Util.bytes(output);
    }

    public ByteSource decrypt(byte[] ciphertext, byte[] key) throws CryptoException {

        byte[] encrypted = ciphertext;

        //No IV, check if we need to read the IV from the stream:
        byte[] iv = null;

        if (isGenerateInitializationVectors(false)) {
            try {
                //We are generating IVs, so the ciphertext argument array is not actually 100% cipher text.  Instead, it
                //is:
                // - the first N bytes is the initialization vector, where N equals the value of the
                // 'initializationVectorSize' attribute.
                // - the remaining bytes in the method argument (arg.length - N) is the real cipher text.

                //So we need to chunk the method argument into its constituent parts to find the IV and then use
                //the IV to decrypt the real ciphertext:

                int ivSize = getInitializationVectorSize();
                int ivByteSize = ivSize / BITS_PER_BYTE;

                //now we know how large the iv is, so extract the iv bytes:
                iv = new byte[ivByteSize];
                System.arraycopy(ciphertext, 0, iv, 0, ivByteSize);

                //remaining data is the actual encrypted ciphertext.  Isolate it:
                int encryptedSize = ciphertext.length - ivByteSize;
                encrypted = new byte[encryptedSize];
                System.arraycopy(ciphertext, ivByteSize, encrypted, 0, encryptedSize);
            } catch (Exception e) {
                String msg = "Unable to correctly extract the Initialization Vector or ciphertext.";
                throw new CryptoException(msg, e);
            }
        }

        return decrypt(encrypted, key, iv);
    }

    private ByteSource decrypt(byte[] ciphertext, byte[] key, byte[] iv) throws CryptoException {
        if (log.isTraceEnabled()) {
            log.trace("Attempting to decrypt incoming byte array of length " +
                    (ciphertext != null ? ciphertext.length : 0));
        }
        byte[] decrypted = crypt(ciphertext, key, iv, javax.crypto.Cipher.DECRYPT_MODE);
        return decrypted == null ? null : ByteSource.Util.bytes(decrypted);
    }

    /**
     * Returns a new {@link javax.crypto.Cipher Cipher} instance to use for encryption/decryption operations.  The
     * Cipher's {@code transformationString} for the {@code Cipher}.{@link javax.crypto.Cipher#getInstance getInstance}
     * call is obtaind via the {@link #getTransformationString(boolean) getTransformationString} method.
     *
     * @param streaming {@code true} if the cipher instance will be used as a stream cipher, {@code false} if it will be
     *                  used as a block cipher.
     * @return a new JDK {@code Cipher} instance.
     * @throws CryptoException if a new Cipher instance cannot be constructed based on the
     *                         {@link #getTransformationString(boolean) getTransformationString} value.
     */
    private javax.crypto.Cipher newCipherInstance(boolean streaming) throws CryptoException {
        String transformationString = getTransformationString(streaming);
        try {
            return javax.crypto.Cipher.getInstance(transformationString);
        } catch (Exception e) {
            String msg = "Unable to acquire a Java JCA Cipher instance using " +
                    javax.crypto.Cipher.class.getName() + ".getInstance( \"" + transformationString + "\" ). " +
                    getAlgorithmName() + " under this configuration is required for the " +
                    getClass().getName() + " instance to function.";
            throw new CryptoException(msg, e);
        }
    }

    /**
     * Functions as follows:
     * <ol>
     * <li>Creates a {@link #newCipherInstance(boolean) new JDK cipher instance}</li>
     * <li>Converts the specified key bytes into an {@link #getAlgorithmName() algorithm}-compatible JDK
     * {@link Key key} instance</li>
     * <li>{@link #init(javax.crypto.Cipher, int, java.security.Key, AlgorithmParameterSpec, SecureRandom) Initializes}
     * the JDK cipher instance with the JDK key</li>
     * <li>Calls the {@link #crypt(javax.crypto.Cipher, byte[]) crypt(cipher,bytes)} method to either encrypt or
     * decrypt the data based on the specified Cipher behavior mode
     * ({@link javax.crypto.Cipher#ENCRYPT_MODE Cipher.ENCRYPT_MODE} or
     * {@link javax.crypto.Cipher#DECRYPT_MODE Cipher.DECRYPT_MODE})</li>
     * </ol>
     *
     * @param bytes the bytes to crypt
     * @param key   the key to use to perform the encryption or decryption.
     * @param iv    the initialization vector to use for the crypt operation (optional, may be {@code null}).
     * @param mode  the JDK Cipher behavior mode (Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE).
     * @return the resulting crypted byte array
     * @throws IllegalArgumentException if {@code bytes} are null or empty.
     * @throws CryptoException          if Cipher initialization or the crypt operation fails
     */
    private byte[] crypt(byte[] bytes, byte[] key, byte[] iv, int mode) throws IllegalArgumentException, CryptoException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("key argument cannot be null or empty.");
        }
        javax.crypto.Cipher cipher = initNewCipher(mode, key, iv, false);
        return crypt(cipher, bytes);
    }

    /**
     * Calls the {@link javax.crypto.Cipher#doFinal(byte[]) doFinal(bytes)} method, propagating any exception that
     * might arise in an {@link CryptoException}
     *
     * @param cipher the JDK Cipher to finalize (perform the actual cryption)
     * @param bytes  the bytes to crypt
     * @return the resulting crypted byte array.
     * @throws CryptoException if there is an illegal block size or bad padding
     */
    private byte[] crypt(javax.crypto.Cipher cipher, byte[] bytes) throws CryptoException {
        try {
            return cipher.doFinal(bytes);
        } catch (Exception e) {
            String msg = "Unable to execute 'doFinal' with cipher instance [" + cipher + "].";
            throw new CryptoException(msg, e);
        }
    }

    /**
     * Initializes the JDK Cipher with the specified mode and key.  This is primarily a utility method to catch any
     * potential {@link java.security.InvalidKeyException InvalidKeyException} that might arise.
     *
     * @param cipher the JDK Cipher to {@link javax.crypto.Cipher#init(int, java.security.Key) init}.
     * @param mode   the Cipher mode
     * @param key    the Cipher's Key
     * @param spec   the JDK AlgorithmParameterSpec for cipher initialization (optional, may be null).
     * @param random the SecureRandom to use for cipher initialization (optional, may be null).
     * @throws CryptoException if the key is invalid
     */
    private void init(javax.crypto.Cipher cipher, int mode, java.security.Key key,
                      AlgorithmParameterSpec spec, SecureRandom random) throws CryptoException {
        try {
            if (random != null) {
                if (spec != null) {
                    cipher.init(mode, key, spec, random);
                } else {
                    cipher.init(mode, key, random);
                }
            } else {
                if (spec != null) {
                    cipher.init(mode, key, spec);
                } else {
                    cipher.init(mode, key);
                }
            }
        } catch (Exception e) {
            String msg = "Unable to init cipher instance.";
            throw new CryptoException(msg, e);
        }
    }


    public void encrypt(InputStream in, OutputStream out, byte[] key) throws CryptoException {
        byte[] iv = null;
        boolean generate = isGenerateInitializationVectors(true);
        if (generate) {
            iv = generateInitializationVector(true);
            if (iv == null || iv.length == 0) {
                throw new IllegalStateException("Initialization vector generation is enabled - generated vector" +
                        "cannot be null or empty.");
            }
        }
        encrypt(in, out, key, iv, generate);
    }

    private void encrypt(InputStream in, OutputStream out, byte[] key, byte[] iv, boolean prependIv) throws CryptoException {
        if (prependIv && iv != null && iv.length > 0) {
            try {
                //first write the IV:
                out.write(iv);
            } catch (IOException e) {
                throw new CryptoException(e);
            }
        }

        crypt(in, out, key, iv, javax.crypto.Cipher.ENCRYPT_MODE);
    }

    public void decrypt(InputStream in, OutputStream out, byte[] key) throws CryptoException {
        decrypt(in, out, key, isGenerateInitializationVectors(true));
    }

    private void decrypt(InputStream in, OutputStream out, byte[] key, boolean ivPrepended) throws CryptoException {

        byte[] iv = null;
        //No Initialization Vector provided as a method argument - check if we need to read the IV from the stream:
        if (ivPrepended) {
            //we are generating IVs, so we need to read the previously-generated IV from the stream before
            //we decrypt the rest of the stream (we need the IV to decrypt):
            int ivSize = getInitializationVectorSize();
            int ivByteSize = ivSize / BITS_PER_BYTE;
            iv = new byte[ivByteSize];
            int read;

            try {
                read = in.read(iv);
            } catch (IOException e) {
                String msg = "Unable to correctly read the Initialization Vector from the input stream.";
                throw new CryptoException(msg, e);
            }

            if (read != ivByteSize) {
                throw new CryptoException("Unable to read initialization vector bytes from the InputStream.  " +
                        "This is required when initialization vectors are autogenerated during an encryption " +
                        "operation.");
            }
        }

        decrypt(in, out, key, iv);
    }

    private void decrypt(InputStream in, OutputStream out, byte[] decryptionKey, byte[] iv) throws CryptoException {
        crypt(in, out, decryptionKey, iv, javax.crypto.Cipher.DECRYPT_MODE);
    }

    private void crypt(InputStream in, OutputStream out, byte[] keyBytes, byte[] iv, int cryptMode) throws CryptoException {
        if (in == null) {
            throw new NullPointerException("InputStream argument cannot be null.");
        }
        if (out == null) {
            throw new NullPointerException("OutputStream argument cannot be null.");
        }

        javax.crypto.Cipher cipher = initNewCipher(cryptMode, keyBytes, iv, true);

        CipherInputStream cis = new CipherInputStream(in, cipher);

        int bufSize = getStreamingBufferSize();
        byte[] buffer = new byte[bufSize];

        int bytesRead;
        try {
            while ((bytesRead = cis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new CryptoException(e);
        }
    }

    private javax.crypto.Cipher initNewCipher(int jcaCipherMode, byte[] key, byte[] iv, boolean streaming)
            throws CryptoException {

        javax.crypto.Cipher cipher = newCipherInstance(streaming);
        java.security.Key jdkKey = new SecretKeySpec(key, getAlgorithmName());
        IvParameterSpec ivSpec = null;
        if (iv != null && iv.length > 0) {
            ivSpec = new IvParameterSpec(iv);
        }

        init(cipher, jcaCipherMode, jdkKey, ivSpec, getSecureRandom());

        return cipher;
    }
}
