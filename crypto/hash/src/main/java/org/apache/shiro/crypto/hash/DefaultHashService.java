/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.crypto.hash;

import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.lang.util.ByteSource;

/**
 * Default implementation of the {@link HashService} interface, supporting a customizable hash algorithm name,
 * secure-random salt generation, multiple hash iterations and an optional internal
 * {@link #setPrivateSalt(ByteSource) privateSalt}.
 * <h2>Hash Algorithm</h2>
 * You may specify a hash algorithm via the {@link #setHashAlgorithmName(String)} property.  Any algorithm name
 * understood by the JDK
 * {@link java.security.MessageDigest#getInstance(String) MessageDigest.getInstance(String algorithmName)} method
 * will work.  The default is {@code SHA-512}.
 * <h2>Random Salts</h2>
 * When a salt is not specified in a request, this implementation generates secure random salts via its
 * {@link #setRandomNumberGenerator(org.apache.shiro.crypto.RandomNumberGenerator) randomNumberGenerator} property.
 * Random salts (and potentially combined with the internal {@link #getPrivateSalt() privateSalt}) is a very strong
 * salting strategy, as salts should ideally never be based on known/guessable data.  The default instance is a
 * {@link SecureRandomNumberGenerator}.
 * <h2>Hash Iterations</h2>
 * Secure hashing strategies often employ multiple hash iterations to slow down the hashing process.  This technique
 * is usually used for password hashing, since the longer it takes to compute a password hash, the longer it would
 * take for an attacker to compromise a password.  This
 * <a href="http://www.stormpath.com/blog/strong-password-hashing-apache-shiro">blog article</a>
 * explains in greater detail why this is useful, as well as information on how many iterations is 'enough'.
 * <p/>
 * You may set the number of hash iterations via the {@link #setHashIterations(int)} property.  The default is
 * {@code 1}, but should be increased significantly if the {@code HashService} is intended to be used for password
 * hashing. See the linked blog article for more info.
 * <h2>Private Salt</h2>
 * If using this implementation as part of a password hashing strategy, it might be desirable to configure a
 * {@link #setPrivateSalt(ByteSource) private salt}:
 * <p/>
 * A hash and the salt used to compute it are often stored together.  If an attacker is ever able to access
 * the hash (e.g. during password cracking) and it has the full salt value, the attacker has all of the input necessary
 * to try to brute-force crack the hash (source + complete salt).
 * <p/>
 * However, if part of the salt is not available to the attacker (because it is not stored with the hash), it is
 * <em>much</em> harder to crack the hash value since the attacker does not have the complete inputs necessary.
 * <p/>
 * The {@link #getPrivateSalt() privateSalt} property exists to satisfy this private-and-not-shared part of the salt.
 * If you configure this attribute, you can obtain this additional very important safety feature.
 * <p/>
 * <b>*</b>By default, the {@link #getPrivateSalt() privateSalt} is null, since a sensible default cannot be used that
 * isn't easily compromised (because Shiro is an open-source project and any default could be easily seen and used).
 *
 * @since 1.2
 */
public class DefaultHashService implements ConfigurableHashService {

    /**
     * The RandomNumberGenerator to use to randomly generate the public part of the hash salt.
     */
    private RandomNumberGenerator rng;

    /**
     * The MessageDigest name of the hash algorithm to use for computing hashes.
     */
    private String algorithmName;

    /**
     * The 'private' part of the hash salt.
     */
    private ByteSource privateSalt;

    /**
     * The number of hash iterations to perform when computing hashes.
     */
    private int iterations;

    /**
     * Whether or not to generate public salts if a request does not provide one.
     */
    private boolean generatePublicSalt;

    /**
     * Constructs a new {@code DefaultHashService} instance with the following defaults:
     * <ul>
     * <li>{@link #setHashAlgorithmName(String) hashAlgorithmName} = {@code SHA-512}</li>
     * <li>{@link #setHashIterations(int) hashIterations} = {@code 1}</li>
     * <li>{@link #setRandomNumberGenerator(org.apache.shiro.crypto.RandomNumberGenerator) randomNumberGenerator} =
     * new {@link SecureRandomNumberGenerator}()</li>
     * <li>{@link #setGeneratePublicSalt(boolean) generatePublicSalt} = {@code false}</li>
     * </ul>
     * <p/>
     * If this hashService will be used for password hashing it is recommended to set the
     * {@link #setPrivateSalt(ByteSource) privateSalt} and significantly increase the number of
     * {@link #setHashIterations(int) hashIterations}.  See the class-level JavaDoc for more information.
     */
    public DefaultHashService() {
        this.algorithmName = "SHA-512";
        this.iterations = 1;
        this.generatePublicSalt = false;
        this.rng = new SecureRandomNumberGenerator();
    }

    /**
     * Computes and responds with a hash based on the specified request.
     * <p/>
     * This implementation functions as follows:
     * <ul>
     * <li>If the request's {@link org.apache.shiro.crypto.hash.HashRequest#getSalt() salt} is null:
     * <p/>
     * A salt will be generated and used to compute the hash.  The salt is generated as follows:
     * <ol>
     * <li>Use the {@link #getRandomNumberGenerator() randomNumberGenerator} to generate a new random number.</li>
     * <li>{@link #combine(ByteSource, ByteSource) combine} this random salt with any configured
     * {@link #getPrivateSalt() privateSalt}
     * </li>
     * <li>Use the combined value as the salt used during hash computation</li>
     * </ol>
     * </li>
     * <li>
     * If the request salt is not null:
     * <p/>
     * This indicates that the hash computation is for comparison purposes (of a
     * previously computed hash).  The request salt will be {@link #combine(ByteSource, ByteSource) combined} with any
     * configured {@link #getPrivateSalt() privateSalt} and used as the complete salt during hash computation.
     * </li>
     * </ul>
     * <p/>
     * The returned {@code Hash}'s {@link Hash#getSalt() salt} property
     * will contain <em>only</em> the 'public' part of the salt and <em>NOT</em> the privateSalt.  See the class-level
     * JavaDoc explanation for more info.
     *
     * @param request the request to process
     * @return the response containing the result of the hash computation, as well as any hash salt used that should be
     *         exposed to the caller.
     */
    public Hash computeHash(HashRequest request) {
        if (request == null || request.getSource() == null || request.getSource().isEmpty()) {
            return null;
        }

        String algorithmName = getAlgorithmName(request);
        ByteSource source = request.getSource();
        int iterations = getIterations(request);

        ByteSource publicSalt = getPublicSalt(request);
        ByteSource privateSalt = getPrivateSalt();
        ByteSource salt = combine(privateSalt, publicSalt);

        Hash computed = new SimpleHash(algorithmName, source, salt, iterations);

        SimpleHash result = new SimpleHash(algorithmName);
        result.setBytes(computed.getBytes());
        result.setIterations(iterations);
        //Only expose the public salt - not the real/combined salt that might have been used:
        result.setSalt(publicSalt);

        return result;
    }

    protected String getAlgorithmName(HashRequest request) {
        String name = request.getAlgorithmName();
        if (name == null) {
            name = getHashAlgorithmName();
        }
        return name;
    }

    protected int getIterations(HashRequest request) {
        int iterations = Math.max(0, request.getIterations());
        if (iterations < 1) {
            iterations = Math.max(1, getHashIterations());
        }
        return iterations;
    }

    /**
     * Returns the public salt that should be used to compute a hash based on the specified request or
     * {@code null} if no public salt should be used.
     * <p/>
     * This implementation functions as follows:
     * <ol>
     * <li>If the request salt is not null and non-empty, this will be used, return it.</li>
     * <li>If the request salt is null or empty:
     * <ol>
     * <li>If a private salt has been set <em>OR</em> {@link #isGeneratePublicSalt()} is {@code true},
     * auto generate a random public salt via the configured
     * {@link #getRandomNumberGenerator() randomNumberGenerator}.</li>
     * <li>If a private salt has not been configured and {@link #isGeneratePublicSalt()} is {@code false},
     * do nothing - return {@code null} to indicate a salt should not be used during hash computation.</li>
     * </ol>
     * </li>
     * </ol>
     *
     * @param request request the request to process
     * @return the public salt that should be used to compute a hash based on the specified request or
     *         {@code null} if no public salt should be used.
     */
    protected ByteSource getPublicSalt(HashRequest request) {

        ByteSource publicSalt = request.getSalt();

        if (publicSalt != null && !publicSalt.isEmpty()) {
            //a public salt was explicitly requested to be used - go ahead and use it:
            return publicSalt;
        }

        publicSalt = null;

        //check to see if we need to generate one:
        ByteSource privateSalt = getPrivateSalt();
        boolean privateSaltExists = privateSalt != null && !privateSalt.isEmpty();

        //If a private salt exists, we must generate a public salt to protect the integrity of the private salt.
        //Or generate it if the instance is explicitly configured to do so:
        if (privateSaltExists || isGeneratePublicSalt()) {
            publicSalt = getRandomNumberGenerator().nextBytes();
        }

        return publicSalt;
    }

    /**
     * Combines the specified 'private' salt bytes with the specified additional extra bytes to use as the
     * total salt during hash computation.  {@code privateSaltBytes} will be {@code null} }if no private salt has been
     * configured.
     *
     * @param privateSalt the (possibly {@code null}) 'private' salt to combine with the specified extra bytes
     * @param publicSalt  the extra bytes to use in addition to the given private salt.
     * @return a combination of the specified private salt bytes and extra bytes that will be used as the total
     *         salt during hash computation.
     */
    protected ByteSource combine(ByteSource privateSalt, ByteSource publicSalt) {

        byte[] privateSaltBytes = privateSalt != null ? privateSalt.getBytes() : null;
        int privateSaltLength = privateSaltBytes != null ? privateSaltBytes.length : 0;

        byte[] publicSaltBytes = publicSalt != null ? publicSalt.getBytes() : null;
        int extraBytesLength = publicSaltBytes != null ? publicSaltBytes.length : 0;

        int length = privateSaltLength + extraBytesLength;

        if (length <= 0) {
            return null;
        }

        byte[] combined = new byte[length];

        int i = 0;
        for (int j = 0; j < privateSaltLength; j++) {
            assert privateSaltBytes != null;
            combined[i++] = privateSaltBytes[j];
        }
        for (int j = 0; j < extraBytesLength; j++) {
            assert publicSaltBytes != null;
            combined[i++] = publicSaltBytes[j];
        }

        return ByteSource.Util.bytes(combined);
    }

    public void setHashAlgorithmName(String name) {
        this.algorithmName = name;
    }

    public String getHashAlgorithmName() {
        return this.algorithmName;
    }

    public void setPrivateSalt(ByteSource privateSalt) {
        this.privateSalt = privateSalt;
    }

    public ByteSource getPrivateSalt() {
        return this.privateSalt;
    }

    public void setHashIterations(int count) {
        this.iterations = count;
    }

    public int getHashIterations() {
        return this.iterations;
    }

    public void setRandomNumberGenerator(RandomNumberGenerator rng) {
        this.rng = rng;
    }

    public RandomNumberGenerator getRandomNumberGenerator() {
        return this.rng;
    }

    /**
     * Returns {@code true} if a public salt should be randomly generated and used to compute a hash if a
     * {@link HashRequest} does not specify a salt, {@code false} otherwise.
     * <p/>
     * The default value is {@code false} but should definitely be set to {@code true} if the
     * {@code HashService} instance is being used for password hashing.
     * <p/>
     * <b>NOTE:</b> this property only has an effect if a {@link #getPrivateSalt() privateSalt} is NOT configured.  If a
     * private salt has been configured and a request does not provide a salt, a random salt will always be generated
     * to protect the integrity of the private salt (without a public salt, the private salt would be exposed as-is,
     * which is undesirable).
     *
     * @return {@code true} if a public salt should be randomly generated and used to compute a hash if a
     *         {@link HashRequest} does not specify a salt, {@code false} otherwise.
     */
    public boolean isGeneratePublicSalt() {
        return generatePublicSalt;
    }

    /**
     * Sets whether or not a public salt should be randomly generated and used to compute a hash if a
     * {@link HashRequest} does not specify a salt.
     * <p/>
     * The default value is {@code false} but should definitely be set to {@code true} if the
     * {@code HashService} instance is being used for password hashing.
     * <p/>
     * <b>NOTE:</b> this property only has an effect if a {@link #getPrivateSalt() privateSalt} is NOT configured.  If a
     * private salt has been configured and a request does not provide a salt, a random salt will always be generated
     * to protect the integrity of the private salt (without a public salt, the private salt would be exposed as-is,
     * which is undesirable).
     *
     * @param generatePublicSalt whether or not a public salt should be randomly generated and used to compute a hash
     *                           if a {@link HashRequest} does not specify a salt.
     */
    public void setGeneratePublicSalt(boolean generatePublicSalt) {
        this.generatePublicSalt = generatePublicSalt;
    }
}
