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

package org.apache.shiro.crypto.hash;

import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.SimpleByteSource;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import static java.util.Collections.unmodifiableList;

public class Argon2Hash extends AbstractCryptHash {
    private static final long serialVersionUID = 2647354947284558921L;

    private static final String ALGORITHM_NAME = "argon2id";

    private static final List<String> ALGORITHMS_ARGON2 = Arrays.asList("argon2id", "argon2i", "argon2d");

    private static final int DEFAULT_ITERATIONS = 10;

    private static final int DEFAULT_MEMORY = 1_048_576;

    private static final int DEFAULT_PARALLELISM = 4;

    /**
     * 128 bits of salt is the recommended salt length.
     */
    private static final int SALT_LENGTH = 16;

    public Argon2Hash(byte[] hashedData, ByteSource salt, int cost) {
        super(ALGORITHM_NAME, hashedData, salt, cost);
    }

    public Argon2Hash(String version, byte[] hashedData, ByteSource salt, int cost) {
        super(version, hashedData, salt, cost);
    }

    public static List<String> getAlgorithmsArgon2() {
        return unmodifiableList(ALGORITHMS_ARGON2);
    }

    public static Argon2Hash generate(final char[] source) {
        return generate(source, createSalt(), DEFAULT_ITERATIONS);
    }

    public static byte[] createSalt() {
        return new SecureRandom().generateSeed(SALT_LENGTH);
    }


    public static Argon2Hash generate(final char[] source, final byte[] salt, final int iterations) {
        final Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(DEFAULT_MEMORY)
                .withParallelism(DEFAULT_PARALLELISM)
                .withSalt(salt)
                .build();

        final Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(parameters);

        final byte[] hash = new byte[32];
        gen.generateBytes(source, hash);

        return new Argon2Hash(ALGORITHM_NAME, hash, new SimpleByteSource(salt), iterations);
    }

    @Override
    protected void checkValidAlgorithm() {
        if (!ALGORITHMS_ARGON2.contains(getAlgorithmName())) {
            final String message = String.format(
                    Locale.ENGLISH,
                    "Given algorithm name [%s] not valid for argon2. " +
                            "Valid algorithms: [%s].",
                    getAlgorithmName(),
                    ALGORITHMS_ARGON2
            );
            throw new IllegalArgumentException(message);
        }
    }

    @Override
    protected void checkValidIterations() {
        int iterations = this.getIterations();
        if (iterations < 1) {
            final String message = String.format(
                    Locale.ENGLISH,
                    "Expected argon2 iterations >= 1, but was [%d].",
                    iterations
            );
            throw new IllegalArgumentException(message);
        }
    }

    @Override
    public String getAlgorithmName() {
        // TODO: implement
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.crypto.hash.Argon2Hash::getAlgorithmName].");
    }

    @Override
    public boolean matchesPassword(ByteSource plaintextBytes) {
        // TODO: implement
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.crypto.hash.Argon2Hash::matchesPassword].");
    }

    @Override
    public int getSaltLength() {
        // TODO: implement
        throw new UnsupportedOperationException("not yet implemented: [org.apache.shiro.crypto.hash.Argon2Hash::getSaltLength].");
    }

}
