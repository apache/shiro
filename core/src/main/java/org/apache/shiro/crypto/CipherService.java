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

import java.io.InputStream;
import java.io.OutputStream;

/**
 * A {@code CipherService} uses a cryptographic algorithm called a
 * <a href="http://en.wikipedia.org/wiki/Cipher">Cipher</a> to convert an original input source using a {@code key} to
 * an uninterpretable format.  The resulting encrypted output is only able to be converted back to original form with
 * a {@code key} as well.  {@code CipherService}s can perform both encryption and decryption.
 * <h2>Cipher Basics</h2>
 * For what is known as <em>Symmetric</em> {@code Cipher}s, the {@code Key} used to encrypt the source is the same
 * as (or trivially similar to) the {@code Key} used to decrypt it.
 * <p/>
 * For <em>Asymmetric</em> {@code Cipher}s, the encryption {@code Key} is not the same as the decryption {@code Key}.
 * The most common type of Asymmetric Ciphers are based on what is called public/private key pairs:
 * <p/>
 * A <em>private</em> key is known only to a single party, and as its name implies, is supposed be kept very private
 * and secure.  A <em>public</em> key that is associated with the private key can be disseminated freely to anyone.
 * Then data encrypted by the public key can only be decrypted by the private key and vice versa, but neither party
 * need share their private key with anyone else.  By not sharing a private key, you can guarantee no 3rd party can
 * intercept the key and therefore use it to decrypt a message.
 * <p/>
 * This asymmetric key technology was created as a
 * more secure alternative to symmetric ciphers that sometimes suffer from man-in-the-middle attacks since, for
 * data shared between two parties, the same Key must also be shared and may be compromised.
 * <p/>
 * Note that a symmetric cipher is perfectly fine to use if you just want to encode data in a format no one else
 * can understand and you never give away the key.  Shiro uses a symmetric cipher when creating certain
 * HTTP Cookies for example - because it is often undesirable to have user's identity stored in a plain-text cookie,
 * that identity can be converted via a symmetric cipher.  Since the the same exact Shiro application will receive
 * the cookie, it can decrypt it via the same {@code Key} and there is no potential for discovery since that Key
 * is never shared with anyone.
 * <h2>{@code CipherService}s vs JDK {@link javax.crypto.Cipher Cipher}s</h2>
 * Shiro {@code CipherService}s essentially do the same things as JDK {@link javax.crypto.Cipher Cipher}s, but in
 * simpler and easier-to-use ways for most application developers.  When thinking about encrypting and decrypting data
 * in an application, most app developers want what a {@code CipherService} provides, rather than having to manage the
 * lower-level intricacies of the JDK's {@code Cipher} API.  Here are a few reasons why most people prefer
 * {@code CipherService}s:
 * <ul>
 * <li><b>Stateless Methods</b> - {@code CipherService} method calls do not retain state between method invocations.
 * JDK {@code Cipher} instances do retain state across invocations, requiring its end-users to manage the instance
 * and its state themselves.</li>
 * <li><b>Thread Safety</b> - {@code CipherService} instances are thread-safe inherently because no state is
 * retained across method invocations.  JDK {@code Cipher} instances retain state and cannot be used by multiple
 * threads concurrently.</li>
 * <li><b>Single Operation</b> - {@code CipherService} method calls are single operation methods: encryption or
 * decryption in their entirety are done as a single method call.  This is ideal for the large majority of developer
 * needs where you have something unencrypted and just want it decrypted (or vice versa) in a single method call.  In
 * contrast, JDK {@code Cipher} instances can support encrypting/decrypting data in chunks over time (because it
 * retains state), but this often introduces API clutter and confusion for most application developers.</li>
 * <li><b>Type Safe</b> - There are {@code CipherService} implementations for different Cipher algorithms
 * ({@code AesCipherService}, {@code BlowfishCipherService}, etc).  There is only one JDK {@code Cipher} class to
 * represent all cipher algorithms/instances.
 * <li><b>Simple Construction</b> - Because {@code CipherService} instances are type-safe, instantiating and using
 * one is often as simple as calling the default constructor, for example, <code>new AesCipherService();</code>.  The
 * JDK {@code Cipher} class however requires using a procedural factory method with String arguments to indicate how
 * the instance should be created.  The String arguments themselves are somewhat cryptic and hard to
 * understand unless you're a security expert.  Shiro hides these details from you, but allows you to configure them
 * if you want.</li>
 * </ul>
 *
 * @see BlowfishCipherService
 * @see AesCipherService
 * @since 1.0
 */
public interface CipherService {

    /**
     * Decrypts encrypted data via the specified cipher key and returns the original (pre-encrypted) data.
     * Note that the key must be in a format understood by the CipherService implementation.
     *
     * @param encrypted     the previously encrypted data to decrypt
     * @param decryptionKey the cipher key used during decryption.
     * @return a byte source representing the original form of the specified encrypted data.
     * @throws CryptoException if there is an error during decryption
     */
    ByteSource decrypt(byte[] encrypted, byte[] decryptionKey) throws CryptoException;

    /**
     * Receives encrypted data from the given {@code InputStream}, decrypts it, and sends the resulting decrypted data
     * to the given {@code OutputStream}.
     * <p/>
     * <b>NOTE:</b> This method <em>does NOT</em> flush or close either stream prior to returning - the caller must
     * do so when they are finished with the streams.  For example:
     * <pre>
     * try {
     *     InputStream in = ...
     *     OutputStream out = ...
     *     cipherService.decrypt(in, out, decryptionKey);
     * } finally {
     *     if (in != null) {
     *         try {
     *             in.close();
     *         } catch (IOException ioe1) { ... log, trigger event, etc }
     *     }
     *     if (out != null) {
     *         try {
     *             out.close();
     *         } catch (IOException ioe2) { ... log, trigger event, etc }
     *     }
     * }
     * </pre>
     *
     * @param in            the stream supplying the data to decrypt
     * @param out           the stream to send the decrypted data
     * @param decryptionKey the cipher key to use for decryption
     * @throws CryptoException if there is any problem during decryption.
     */
    void decrypt(InputStream in, OutputStream out, byte[] decryptionKey) throws CryptoException;

    /**
     * Encrypts data via the specified cipher key.  Note that the key must be in a format understood by
     * the {@code CipherService} implementation.
     *
     * @param raw           the data to encrypt
     * @param encryptionKey the cipher key used during encryption.
     * @return a byte source with the encrypted representation of the specified raw data.
     * @throws CryptoException if there is an error during encryption
     */
    ByteSource encrypt(byte[] raw, byte[] encryptionKey) throws CryptoException;

    /**
     * Receives the data from the given {@code InputStream}, encrypts it, and sends the resulting encrypted data to the
     * given {@code OutputStream}.
     * <p/>
     * <b>NOTE:</b> This method <em>does NOT</em> flush or close either stream prior to returning - the caller must
     * do so when they are finished with the streams.  For example:
     * <pre>
     * try {
     *     InputStream in = ...
     *     OutputStream out = ...
     *     cipherService.encrypt(in, out, encryptionKey);
     * } finally {
     *     if (in != null) {
     *         try {
     *             in.close();
     *         } catch (IOException ioe1) { ... log, trigger event, etc }
     *     }
     *     if (out != null) {
     *         try {
     *             out.close();
     *         } catch (IOException ioe2) { ... log, trigger event, etc }
     *     }
     * }
     * </pre>
     *
     * @param in            the stream supplying the data to encrypt
     * @param out           the stream to send the encrypted data
     * @param encryptionKey the cipher key to use for encryption
     * @throws CryptoException if there is any problem during encryption.
     */
    void encrypt(InputStream in, OutputStream out, byte[] encryptionKey) throws CryptoException;

}
