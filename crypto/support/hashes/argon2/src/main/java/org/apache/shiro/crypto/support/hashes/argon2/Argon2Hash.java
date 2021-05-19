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

package org.apache.shiro.crypto.support.hashes.argon2;

import org.apache.shiro.crypto.hash.AbstractCryptHash;
import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.SimpleByteSource;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64.Encoder;
import java.util.HashSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.StringJoiner;
import java.util.regex.Pattern;

import static java.util.Collections.unmodifiableSet;
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
 *
 * <p>Example crypt string is: {@code $argon2i$v=19$m=16384,t=100,p=2$M3ByeyZKLjFRREJqQi87WQ$5kRCtDjL6RoIWGq9bL27DkFNunucg1hW280PmP0XDtY}.</p>
 *
 * <p>Default values are taken from <a href="https://datatracker.ietf.org/doc/draft-irtf-cfrg-argon2/?include_text=1">draft-irtf-cfrg-argon2-13</a>.
 * This implementation is using the parameters from section 4, paragraph 2 (memory constrained environment).</p>
 *
 * @since 2.0
 */
class Argon2Hash extends AbstractCryptHash {
    private static final long serialVersionUID = 2647354947284558921L;

    private static final Logger LOG = LoggerFactory.getLogger(Argon2Hash.class);

    public static final String DEFAULT_ALGORITHM_NAME = "argon2id";

    public static final int DEFAULT_ALGORITHM_VERSION = Argon2Parameters.ARGON2_VERSION_13;

    /**
     * Number of iterations, default taken from draft-irtf-cfrg-argon2-13, 4.2.
     */
    public static final int DEFAULT_ITERATIONS = 1;

    /**
     * Amount of memory, default (64 MiB) taken from draft-irtf-cfrg-argon2-13, 4.2.
     */
    public static final int DEFAULT_MEMORY_KIB = 64 * 1024;

    private static final Set<String> ALGORITHMS_ARGON2 = new HashSet<>(Arrays.asList("argon2id", "argon2i", "argon2d"));

    private static final Pattern DELIMITER_COMMA = Pattern.compile(",");

    /**
     * Number of default lanes, p=4 is the default recommendation, taken from draft-irtf-cfrg-argon2-13, 4.2.
     */
    public static final int DEFAULT_PARALLELISM = 4;

    /**
     * 256 bits tag size is the default recommendation, taken from draft-irtf-cfrg-argon2-13, 4.2.
     */
    public static final int DEFAULT_OUTPUT_LENGTH_BITS = 256;


    /**
     * 128 bits of salt is the recommended salt length, taken from draft-irtf-cfrg-argon2-13, 4.2.
     */
    private static final int SALT_LENGTH_BITS = 128;

    private final int argonVersion;

    private final int iterations;

    private final int memoryKiB;

    private final int parallelism;

    public Argon2Hash(String algorithmName, int argonVersion, byte[] hashedData, ByteSource salt, int iterations, int memoryAsKB, int parallelism) {
        super(algorithmName, hashedData, salt);
        this.argonVersion = argonVersion;
        this.iterations = iterations;
        this.memoryKiB = memoryAsKB;
        this.parallelism = parallelism;

        checkValidIterations();
    }

    public static Set<String> getAlgorithmsArgon2() {
        return unmodifiableSet(ALGORITHMS_ARGON2);
    }

    protected static ByteSource createSalt() {
        return createSalt(new SecureRandom());
    }

    public static ByteSource createSalt(SecureRandom random) {
        return new SimpleByteSource(random.generateSeed(SALT_LENGTH_BITS / 8));
    }

    public static Argon2Hash fromString(String input) {
        // expected:
        // $argon2i$v=19$m=4096,t=3,p=4$M3ByeyZKLjFRREJqQi87WQ$5kRCtDjL6RoIWGq9bL27DkFNunucg1hW280PmP0XDtY
        if (!input.startsWith("$")) {
            throw new UnsupportedOperationException("Unsupported input: " + input);
        }

        final String[] parts = AbstractCryptHash.DELIMITER.split(input.substring(1));
        final String algorithmName = parts[0].trim();

        if (!ALGORITHMS_ARGON2.contains(algorithmName)) {
            throw new UnsupportedOperationException("Unsupported algorithm: " + algorithmName + ". Expected one of: " + ALGORITHMS_ARGON2);
        }

        final int version = parseVersion(parts[1]);
        final String parameters = parts[2];
        final int memoryPowTwo = parseMemory(parameters);
        final int iterations = parseIterations(parameters);
        final int parallelism = parseParallelism(parameters);
        final ByteSource salt = new SimpleByteSource(Base64.decode(parts[3]));
        final byte[] hashedData = Base64.decode(parts[4]);

        return new Argon2Hash(algorithmName, version, hashedData, salt, iterations, memoryPowTwo, parallelism);
    }

    private static int parseParallelism(String parameters) {
        String parameter = DELIMITER_COMMA.splitAsStream(parameters)
                .filter(parm -> parm.startsWith("p="))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("Did not found memory parameter 'p='. Got: [" + parameters + "]."));
        return Integer.parseInt(parameter.substring(2));
    }

    private static int parseIterations(String parameters) {
        String parameter = DELIMITER_COMMA.splitAsStream(parameters)
                .filter(parm -> parm.startsWith("t="))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("Did not found memory parameter 't='. Got: [" + parameters + "]."));

        return Integer.parseInt(parameter.substring(2));
    }

    private static int parseMemory(String parameters) {
        String parameter = DELIMITER_COMMA.splitAsStream(parameters)
                .filter(parm -> parm.startsWith("m="))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("Did not found memory parameter 'm='. Got: [" + parameters + "]."));

        return Integer.parseInt(parameter.substring(2));
    }

    private static int parseVersion(final String part) {
        if (!part.startsWith("v=")) {
            throw new IllegalArgumentException("Did not find version parameter 'v='. Got: [" + part + "].");
        }

        return Integer.parseInt(part.substring(2));
    }

    public static Argon2Hash generate(final char[] source) {
        return generate(new SimpleByteSource(source), createSalt(), DEFAULT_ITERATIONS);
    }

    public static Argon2Hash generate(final ByteSource source, final ByteSource salt, final int iterations) {
        return generate(DEFAULT_ALGORITHM_NAME, source, requireNonNull(salt, "salt"), iterations);
    }

    public static Argon2Hash generate(String algorithmName, ByteSource source, ByteSource salt, int iterations) {
        return generate(algorithmName, DEFAULT_ALGORITHM_VERSION, source, salt, iterations, DEFAULT_MEMORY_KIB, DEFAULT_PARALLELISM, DEFAULT_OUTPUT_LENGTH_BITS);
    }

    public static Argon2Hash generate(
            String algorithmName,
            int argonVersion,
            ByteSource source,
            ByteSource salt,
            int iterations,
            int memoryAsKB,
            int parallelism,
            int outputLengthBits
    ) {
        final int type;
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
                throw new IllegalArgumentException("Unknown argon2 algorithm: " + algorithmName);
        }

        final Argon2Parameters parameters = new Argon2Parameters.Builder(type)
                .withVersion(argonVersion)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .withSalt(requireNonNull(salt, "salt").getBytes())
                .withMemoryAsKB(memoryAsKB)
                .build();

        final Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(parameters);

        final byte[] hash = new byte[outputLengthBits / 8];
        gen.generateBytes(source.getBytes(), hash);

        return new Argon2Hash(algorithmName, argonVersion, hash, new SimpleByteSource(salt), iterations, memoryAsKB, parallelism);
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
    public int getIterations() {
        return this.iterations;
    }

    @Override
    public boolean matchesPassword(ByteSource plaintextBytes) {
        try {
            Argon2Hash compare = generate(
                    this.getAlgorithmName(),
                    this.argonVersion,
                    plaintextBytes,
                    this.getSalt(),
                    this.getIterations(),
                    this.memoryKiB,
                    this.parallelism,
                    this.getBytes().length * 8);

            return this.equals(compare);
        } catch (IllegalArgumentException illegalArgumentException) {
            // cannot recreate hash. Do not log password.
            LOG.warn("Cannot recreate a hash using the same parameters.", illegalArgumentException);
            return false;
        }
    }

    @Override
    public int getSaltLength() {
        return SALT_LENGTH_BITS / 8;
    }

    @Override
    public String formatToCryptString() {
        // expected:
        // $argon2i$v=19$m=4096,t=3,p=4$M3ByeyZKLjFRREJqQi87WQ$5kRCtDjL6RoIWGq9bL27DkFNunucg1hW280PmP0XDtY
        Encoder encoder = java.util.Base64.getEncoder().withoutPadding();
        String saltBase64 = encoder.encodeToString(this.getSalt().getBytes());
        String dataBase64 = encoder.encodeToString(this.getBytes());

        return new StringJoiner("$", "$", "")
                .add(this.getAlgorithmName())
                .add("v=" + this.argonVersion)
                .add(formatParameters())
                .add(saltBase64)
                .add(dataBase64)
                .toString();
    }

    private CharSequence formatParameters() {
        return String.format(
                Locale.ENGLISH,
                "t=%d,m=%d,p=%d",
                getIterations(),
                getMemoryKiB(),
                getParallelism()
        );
    }

    public int getMemoryKiB() {
        return memoryKiB;
    }

    public int getParallelism() {
        return parallelism;
    }

    public int getArgonVersion() {
        return argonVersion;
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
        return argonVersion == that.argonVersion && iterations == that.iterations && memoryKiB == that.memoryKiB && parallelism == that.parallelism;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), argonVersion, iterations, memoryKiB, parallelism);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", Argon2Hash.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .add("version=" + argonVersion)
                .add("iterations=" + iterations)
                .add("memoryKiB=" + memoryKiB)
                .add("parallelism=" + parallelism)
                .toString();
    }
}
