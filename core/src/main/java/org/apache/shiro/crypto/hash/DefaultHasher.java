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
import org.apache.shiro.util.ByteSource;

/**
 * Default implementation of the {@link Hasher} interface, supporting secure-random salt generation, an internal
 * private {@link #setBaseSalt(byte[]) baseSalt}, multiple hash iterations and customizable hash algorithm name.
 * <h2>Base Salt</h2>
 * It is <b><em>strongly recommended</em></b> to configure a {@link #setBaseSalt(byte[]) base salt}.
 * Indeed, the {@link Hasher} concept exists largely to support the {@code base salt} concept:
 * <p/>
 * A hash and the salt used to compute it are often stored together.  If an attacker is ever able to access
 * the hash (e.g. during password cracking) and it has the full salt value, the attacker has all of the input necessary
 * to try to brute-force crack the hash (source + complete salt).
 * <p/>
 * However, if part of the salt is not available to the attacker (because it is not stored with the hash), it is
 * <em>much</em> harder to crack the hash value since the attacker does not have the complete inputs necessary.
 * <p/>
 * The {@link #getBaseSalt() baseSalt} property exists to satisfy this private-and-not-shared part of the salt.  If you
 * configure this attribute, you obtain this additional very important safety feature.
 * <p/>
 * <b>*</b>By default, the {@link #getBaseSalt() baseSalt} is null, since a sensible default cannot be used that isn't
 * easily compromised (because Shiro is an open-source project and any default could be easily seen and used).  It is
 * expected all end-users will want to provide their own.
 * <h2>Random Salts</h2>
 * When a salt is not specified in a request, this implementation generates secure random salts via its
 * {@link #setRandomNumberGenerator(org.apache.shiro.crypto.RandomNumberGenerator) randomNumberGenerator} property.
 * Random salts (combined with the internal {@link #getBaseSalt() baseSalt}) is the strongest salting strategy,
 * as salts should ideally never be based on known/guessable data.  The default is a
 * {@link SecureRandomNumberGenerator}.
 * <h2>Password Hash Iterations</h2>
 * The most secure hashing strategy employs multiple hash iterations to slow down the hashing process.  This technique
 * is usually used for password hashing, since the longer it takes to compute a password hash, the longer it would
 * take for an attacker to compromise a password.  This
 * <a href="http://www.katasoft.com/blog/2011/04/04/strong-password-hashing-apache-shiro">Katasoft blog article</a>
 * explains in greater detail why this is useful, as well as information on how many iterations is 'enough'.
 * <p/>
 * You may set the number of hash iterations via the {@link #setHashIterations(int)} property.  The default is
 * {@code 1}, but should be increased significantly for password hashing. See the linked blog article for more info.
 * <h2>Hash Algorithm</h2>
 * You may specify a hash algorithm via the {@link #setHashAlgorithmName(String)} property.  The default is
 * {@code SHA-512}.
 *
 * @since 1.2
 */
public class DefaultHasher implements ConfigurableHasher {

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
    private byte[] baseSalt;

    /**
     * The number of hash iterations to perform when computing hashes.
     */
    private int iterations;

    /**
     * Constructs a new {@code DefaultHasher} instance with the following defaults:
     * <ul>
     * <li>{@link #setHashAlgorithmName(String) hashAlgorithmName} = {@code SHA-512}</li>
     * <li>{@link #setHashIterations(int) hashIterations} = {@code 1}</li>
     * <li>{@link #setRandomNumberGenerator(org.apache.shiro.crypto.RandomNumberGenerator) randomNumberGenerator} =
     * {@link SecureRandomNumberGenerator}</li>
     * </ul>
     * <p/>
     * If this hasher will be used for password hashing it is <b><em>strongly recommended</em></b> to set the
     * {@link #setBaseSalt(byte[]) baseSalt} and significantly increase the number of
     * {@link #setHashIterations(int) hashIterations}.  See the class-level JavaDoc for more information.
     */
    public DefaultHasher() {
        this.algorithmName = "SHA-512";
        this.iterations = 1;
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
     * <li>{@link #combine(byte[], byte[]) combine} this random salt with any configured {@link #getBaseSalt() baseSalt}
     * </li>
     * <li>Use the combined value as the salt used during hash computation</li>
     * </ol>
     * </li>
     * <li>
     * If the request's salt is not null:
     * <p/>
     * This indicates that the hash computation is for comparison purposes (of a
     * previously computed hash).  The request salt will be {@link #combine(byte[], byte[]) combined} with any
     * configured {@link #getBaseSalt() baseSalt} and used as the complete salt during hash computation.
     * </li>
     * </ul>
     * <p/>
     * The returned {@code HashResponse}'s {@link org.apache.shiro.crypto.hash.HashResponse#getSalt() salt} property
     * will contain <em>only</em> the 'public' part of the salt and <em>NOT</em> the baseSalt.  See the class-level JavaDoc
     * explanation for more info.
     *
     * @param request the request to process
     * @return the response containing the result of the hash computation, as well as any hash salt used that should be
     *         exposed to the caller.
     */
    public HashResponse computeHash(HashRequest request) {
        if (request == null) {
            return null;
        }
        ByteSource source = request.getSource();

        byte[] sourceBytes = source != null ? source.getBytes() : null;
        if (sourceBytes == null || sourceBytes.length == 0) {
            return null;
        }

        ByteSource requestSalt = request.getSalt();
        byte[] publicSaltBytes = requestSalt != null ? requestSalt.getBytes() : null;
        if (publicSaltBytes != null && publicSaltBytes.length == 0) {
            publicSaltBytes = null;
        }
        if (publicSaltBytes == null) {
            getRandomNumberGenerator().nextBytes().getBytes();
        }

        String algorithmName = getHashAlgorithmName();
        byte[] baseSalt = getBaseSalt();
        byte[] saltBytes = combine(baseSalt, publicSaltBytes);
        int iterations = Math.max(1, getHashIterations());

        Hash result = new SimpleHash(algorithmName, sourceBytes, saltBytes, iterations);
        ByteSource publicSalt = ByteSource.Util.bytes(publicSaltBytes);

        return new SimpleHashResponse(result, publicSalt);
    }

    /**
     * Combines the specified 'private' base salt bytes with the specified additional extra bytes to use as the
     * total salt during hash computation.  {@code baseSaltBytes} will be {@code null} }if no base salt has been configured.
     *
     * @param baseSaltBytes the (possibly {@code null}) 'private' base salt to combine with the specified extra bytes
     * @param extraBytes the extra bytes to use in addition to the gien base salt bytes.
     * @return a combination of the specified base salt bytes and extra bytes that will be used as the total
     * salt during hash computation.
     */
    protected byte[] combine(byte[] baseSaltBytes, byte[] extraBytes) {
        int baseSaltLength = baseSaltBytes != null ? baseSaltBytes.length : 0;
        int randomBytesLength = extraBytes != null ? extraBytes.length : 0;

        int length = baseSaltLength + randomBytesLength;
        byte[] combined = new byte[length];

        int i = 0;
        for (int j = 0; j < baseSaltLength; j++) {
            assert baseSaltBytes != null;
            combined[i++] = baseSaltBytes[j];
        }
        for (int j = 0; j < randomBytesLength; j++) {
            assert extraBytes != null;
            combined[i++] = extraBytes[j];
        }

        return combined;
    }


    public void setHashAlgorithmName(String name) {
        this.algorithmName = name;
    }

    public String getHashAlgorithmName() {
        return this.algorithmName;
    }

    public void setBaseSalt(byte[] baseSalt) {
        this.baseSalt = baseSalt;
    }

    public byte[] getBaseSalt() {
        return this.baseSalt;
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
}
