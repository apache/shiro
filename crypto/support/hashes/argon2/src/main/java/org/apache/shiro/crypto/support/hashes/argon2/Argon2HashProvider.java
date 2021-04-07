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

import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.HashSpi;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.SimpleByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

/**
 * A HashProvider for the Argon2 hash algorithm.
 *
 * <p>This class is intended to be used by the {@code HashProvider} class from Shiro. However,
 * this class can also be used to created instances of the Argon2 hash manually.</p>
 *
 * <p>Furthermore, there is a nested {@link Parameters} class which provides names for the
 * keys used in the parameters map of the {@link HashRequest} class.</p>
 *
 * @since 2.0
 */
public class Argon2HashProvider implements HashSpi {

    private static final Logger LOG = LoggerFactory.getLogger(Argon2HashProvider.class);

    @Override
    public Set<String> getImplementedAlgorithms() {
        return Argon2Hash.getAlgorithmsArgon2();
    }

    @Override
    public Argon2Hash fromString(String format) {
        return Argon2Hash.fromString(format);
    }

    @Override
    public HashFactory newHashFactory(Random random) {
        return new Argon2HashFactory(random);
    }

    static class Argon2HashFactory implements HashSpi.HashFactory {

        private final SecureRandom random;

        public Argon2HashFactory(Random random) {
            if (!(random instanceof SecureRandom)) {
                throw new IllegalArgumentException("Only SecureRandom instances are supported at the moment!");
            }

            this.random = (SecureRandom) random;
        }

        @Override
        public Argon2Hash generate(HashRequest hashRequest) {
            final String algorithmName = Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_ALGORITHM_NAME))
                    .map(algo -> (String) algo)
                    .orElse(Parameters.DEFAULT_ALGORITHM_NAME);

            final int version = Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_ALGORITHM_VERSION))
                    .flatMap(algoV -> intOrEmpty(algoV, Parameters.PARAMETER_ALGORITHM_VERSION))
                    .orElse(Parameters.DEFAULT_ALGORITHM_VERSION);

            final ByteSource salt = parseSalt(hashRequest);

            final int iterations = Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_ITERATIONS))
                    .flatMap(algoV -> intOrEmpty(algoV, Parameters.PARAMETER_ITERATIONS))
                    .orElse(Parameters.DEFAULT_ITERATIONS);

            final int memoryKib = Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_MEMORY_KIB))
                    .flatMap(algoV -> intOrEmpty(algoV, Parameters.PARAMETER_MEMORY_KIB))
                    .orElse(Parameters.DEFAULT_MEMORY_KIB);

            final int parallelism = Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_PARALLELISM))
                    .flatMap(algoV -> intOrEmpty(algoV, Parameters.PARAMETER_PARALLELISM))
                    .orElse(Parameters.DEFAULT_PARALLELISM);

            final int outputLengthBits = Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_OUTPUT_LENGTH_BITS))
                    .flatMap(algoV -> intOrEmpty(algoV, Parameters.PARAMETER_OUTPUT_LENGTH_BITS))
                    .orElse(Parameters.DEFAULT_OUTPUT_LENGTH_BITS);

            return Argon2Hash.generate(
                    algorithmName,
                    version,
                    hashRequest.getSource(),
                    salt,
                    iterations,
                    memoryKib,
                    parallelism,
                    outputLengthBits
            );
        }

        private ByteSource parseSalt(HashRequest hashRequest) {
            return Optional.ofNullable(hashRequest.getParameters().get(Parameters.PARAMETER_SALT))
                    .map(saltParm -> Base64.getDecoder().decode((String) saltParm))
                    .map(SimpleByteSource::new)
                    .flatMap(this::lengthValidOrEmpty)
                    .orElseGet(() -> Argon2Hash.createSalt(random));
        }

        private Optional<ByteSource> lengthValidOrEmpty(ByteSource bytes) {
            if (bytes.getBytes().length != 16) {
                return Optional.empty();
            }

            return Optional.of(bytes);
        }

        private Optional<Integer> intOrEmpty(Object maybeInt, String parameterName) {
            try {
                return Optional.of(Integer.parseInt((String) maybeInt, 10));
            } catch (NumberFormatException numberFormatException) {
                String message = String.format(
                        Locale.ENGLISH,
                        "Expected Integer for parameter %s, but %s is not parsable.",
                        parameterName, maybeInt
                );
                LOG.warn(message, numberFormatException);
                return Optional.empty();
            }
        }
    }

    /**
     * Parameters for the {@link Argon2Hash} class.
     *
     * <p>This class contains public constants only. The constants starting with {@code PARAMETER_} are
     * the parameter names recognized by the
     * {@link org.apache.shiro.crypto.hash.HashSpi.HashFactory#generate(HashRequest)} method.</p>
     *
     * <p>The constants starting with {@code DEFAULT_} are their respective default values.</p>
     */
    public static final class Parameters {

        public static final String DEFAULT_ALGORITHM_NAME = Argon2Hash.DEFAULT_ALGORITHM_NAME;
        public static final int DEFAULT_ALGORITHM_VERSION = Argon2Hash.DEFAULT_ALGORITHM_VERSION;
        public static final int DEFAULT_ITERATIONS = Argon2Hash.DEFAULT_ITERATIONS;
        public static final int DEFAULT_MEMORY_KIB = Argon2Hash.DEFAULT_MEMORY_KIB;
        public static final int DEFAULT_PARALLELISM = Argon2Hash.DEFAULT_PARALLELISM;
        public static final int DEFAULT_OUTPUT_LENGTH_BITS = Argon2Hash.DEFAULT_OUTPUT_LENGTH_BITS;

        /**
         * Parameter for modifying the internal algorithm used by Argon2.
         *
         * <p>Valid values are {@code argon2i} (optimized to resist side-channel attacks),
         * {@code argon2d} (maximizes resistance to GPU cracking attacks)
         * and {@code argon2id} (a hybrid version).</p>
         *
         * <p>The default value is {@value DEFAULT_ALGORITHM_NAME} when this parameter is not specified.</p>
         */
        public static final String PARAMETER_ALGORITHM_NAME = "Argon2.algorithmName";
        public static final String PARAMETER_ALGORITHM_VERSION = "Argon2.version";

        /**
         * The salt to use.
         *
         * <p>The value for this parameter accepts a Base64-encoded 16byte (128bit) salt.</p>
         *
         * <p>As for any KDF, do not use a static salt value for multiple passwords.</p>
         *
         * <p>The default value is a new random 128bit-salt, if this parameter is not specified.</p>
         */
        public static final String PARAMETER_SALT = "Argon2.salt";

        public static final String PARAMETER_ITERATIONS = "Argon2.iterations";
        public static final String PARAMETER_MEMORY_KIB = "Argon2.memoryKib";
        public static final String PARAMETER_PARALLELISM = "Argon2.parallelism";

        /**
         * The output length (in bits) of the resulting data section.
         *
         * <p>Argon2 allows to modify the length of the generated output.</p>
         *
         * <p>The default value is {@value DEFAULT_OUTPUT_LENGTH_BITS} when this parameter is not specified.</p>
         */
        public static final String PARAMETER_OUTPUT_LENGTH_BITS = "Argon2.outputLength";

        private Parameters() {
            // utility class
        }
    }
}
