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
import java.util.Objects;
import java.util.StringJoiner;

import static java.util.Collections.unmodifiableList;
import static java.util.Objects.requireNonNull;

/**
 * The Argon2 key derivation function (KDF) is a modern algorithm to shade and hash passwords.
 *
 * <p>The default implementation ({@code argon2id}) is designed to use both memory and cpu to make
 * brute force attacks unfeasible.</p>
 *
 * <p>The defaults are taken from
 * <a href="https://argon2-cffi.readthedocs.io/en/stable/parameters.html">argon2-cffi.readthedocs.io</a>.
 * The RFC suggests to use 1 GiB of memory for frontend and 4 GiB for backend authentication.</p>
 */
public class Argon2Hash extends AbstractCryptHash {
    private static final long serialVersionUID = 2647354947284558921L;

    private static final String ALGORITHM_NAME = "argon2id";

    public static final int DEFAULT_ITERATIONS = 4;

    private static final List<String> ALGORITHMS_ARGON2 = Arrays.asList("argon2id", "argon2i", "argon2d");

    private static final int DEFAULT_MEMORY = 1_048_576 / 4;

    private static final int DEFAULT_PARALLELISM = 4;

    /**
     * 128 bits of salt is the recommended salt length.
     */
    private static final int SALT_LENGTH = 16;

    private final int memoryKiB;

    private final int parallelism;

    public Argon2Hash(byte[] hashedData, ByteSource salt, int iterations, int memoryKiB, int parallelism) {
        super(ALGORITHM_NAME, hashedData, salt, iterations);
        this.memoryKiB = memoryKiB;
        this.parallelism = parallelism;
    }

    public Argon2Hash(String version, byte[] hashedData, ByteSource salt, int iterations, int memoryKiB, int parallelism) {
        super(version, hashedData, salt, iterations);
        this.memoryKiB = memoryKiB;
        this.parallelism = parallelism;
    }

    public static List<String> getAlgorithmsArgon2() {
        return unmodifiableList(ALGORITHMS_ARGON2);
    }

    public static ByteSource createSalt() {
        return new SimpleByteSource(new SecureRandom().generateSeed(SALT_LENGTH));
    }

    public static Argon2Hash generate(final char[] source) {
        return generate(new SimpleByteSource(source), createSalt(), DEFAULT_ITERATIONS);
    }

    public static Argon2Hash generate(final ByteSource source, final ByteSource salt, final int iterations) {
        return generate(ALGORITHM_NAME, source, requireNonNull(salt, "salt"), iterations);
    }

    public static Argon2Hash generate(String algorithmName, ByteSource source, ByteSource salt, int iterations) {
        return generate(algorithmName, source, salt, DEFAULT_ITERATIONS, DEFAULT_MEMORY, DEFAULT_PARALLELISM);
    }

    public static Argon2Hash generate(String algorithmName, ByteSource source, ByteSource salt, int iterations, int memoryKiB, int parallelism) {
        int type;
        switch (requireNonNull(algorithmName, "algorithmName")) {
            case "argon2i":
                type = Argon2Parameters.ARGON2_i;
                break;
            case "argon2d":
                type = Argon2Parameters.ARGON2_d;
                break;
            case "argon2":
                // fall through
            case "argon2id":
                type = Argon2Parameters.ARGON2_id;
                break;
            default:
                throw new UnsupportedOperationException("Unknown argon2 algorithm: " + algorithmName);
        }

        final Argon2Parameters parameters = new Argon2Parameters.Builder(type)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKiB)
                .withParallelism(parallelism)
                .withSalt(requireNonNull(salt, "salt").getBytes())
                .build();

        final Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(parameters);

        final byte[] hash = new byte[32];
        gen.generateBytes(source.getBytes(), hash);

        return new Argon2Hash(algorithmName, hash, new SimpleByteSource(salt), iterations, memoryKiB, parallelism);
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
    public boolean matchesPassword(ByteSource plaintextBytes) {
        Argon2Hash compare = generate(this.getAlgorithmName(), plaintextBytes, this.getSalt(), this.getIterations(), this.memoryKiB, this.parallelism);
        return this.equals(compare);
    }

    @Override
    public int getSaltLength() {
        return SALT_LENGTH;
    }

    public int getMemoryKiB() {
        return memoryKiB;
    }

    public int getParallelism() {
        return parallelism;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (other == null || getClass() != other.getClass()) {
            return false;
        }
        if (!super.equals(other)) {
            return false;
        }
        Argon2Hash that = (Argon2Hash) other;
        return memoryKiB == that.memoryKiB && parallelism == that.parallelism;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), memoryKiB, parallelism);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", Argon2Hash.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .add("memoryKiB=" + memoryKiB)
                .add("parallelism=" + parallelism)
                .toString();
    }
}
