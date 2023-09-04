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

import org.apache.shiro.crypto.hash.format.Shiro1CryptFormat;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.SimpleByteSource;

import java.util.Arrays;
import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

import static java.util.Collections.unmodifiableSet;
import static java.util.stream.Collectors.toSet;

/**
 * Creates a hash provider for salt (+pepper) and Hash-based KDFs, i.e. where the algorithm name
 * is a SHA algorithm or similar.
 * @since 2.0
 */
public class SimpleHashProvider implements HashSpi {

    private static final Set<String> IMPLEMENTED_ALGORITHMS = Arrays.stream(new String[]{
            Sha256Hash.ALGORITHM_NAME,
            Sha384Hash.ALGORITHM_NAME,
            Sha512Hash.ALGORITHM_NAME
    })
            .collect(toSet());

    @Override
    public Set<String> getImplementedAlgorithms() {
        return unmodifiableSet(IMPLEMENTED_ALGORITHMS);
    }

    @Override
    public SimpleHash fromString(String format) {
        Hash hash = new Shiro1CryptFormat().parse(format);

        if (!(hash instanceof SimpleHash)) {
            throw new IllegalArgumentException("formatted string was not a simple hash: " + format);
        }

        return (SimpleHash) hash;
    }

    @Override
    public HashFactory newHashFactory(Random random) {
        return new SimpleHashFactory(random);
    }

    static class SimpleHashFactory implements HashSpi.HashFactory {

        private final Random random;

        SimpleHashFactory(Random random) {
            this.random = random;
        }

        @Override
        public SimpleHash generate(HashRequest hashRequest) {
            String algorithmName = hashRequest.getAlgorithmName().orElse(Parameters.DEFAULT_ALGORITHM);
            ByteSource source = hashRequest.getSource();
            final int iterations = getIterations(hashRequest);

            final ByteSource publicSalt = getPublicSalt(hashRequest);
            final /*nullable*/ ByteSource secretSalt = getSecretSalt(hashRequest);
            final ByteSource salt = combine(secretSalt, publicSalt);

            return createSimpleHash(algorithmName, source, iterations, publicSalt, salt);
        }

        /**
         * Returns the public salt that should be used to compute a hash based on the specified request.
         * <p/>
         * This implementation functions as follows:
         * <ol>
         *   <li>If the request salt is not null and non-empty, this will be used, return it.</li>
         *   <li>If the request salt is null or empty:
         *     <ol><li>create a new 16-byte salt.</li></ol>
         *   </li>
         * </ol>
         *
         * @param request request the request to process
         * @return the public salt that should be used to compute a hash based on the specified request or
         * {@code null} if no public salt should be used.
         */
        protected ByteSource getPublicSalt(HashRequest request) {
            Optional<ByteSource> publicSalt = request.getSalt();

            if (publicSalt.isPresent() && !publicSalt.orElseThrow(NoSuchElementException::new).isEmpty()) {
                //a public salt was explicitly requested to be used - go ahead and use it:
                return publicSalt.orElseThrow(NoSuchElementException::new);
            }

            // generate salt if absent from the request.
            byte[] ps = new byte[16];
            random.nextBytes(ps);

            return new SimpleByteSource(ps);
        }

        private ByteSource getSecretSalt(HashRequest request) {
            Optional<Object> secretSalt = Optional.ofNullable(request.getParameters().get(Parameters.PARAMETER_SECRET_SALT));

            return secretSalt
                    .map(salt -> (String) salt)
                    .map(salt -> Base64.getDecoder().decode(salt))
                    .map(SimpleByteSource::new)
                    .orElse(null);
        }

        private SimpleHash createSimpleHash(String algorithmName, ByteSource source,
                                            int iterations, ByteSource publicSalt, ByteSource salt) {
            Hash computed = new SimpleHash(algorithmName, source, salt, iterations);

            SimpleHash result = new SimpleHash(algorithmName);
            result.setBytes(computed.getBytes());
            result.setIterations(iterations);
            //Only expose the public salt - not the real/combined salt that might have been used:
            result.setSalt(publicSalt);

            return result;
        }

        protected int getIterations(HashRequest request) {
            Object parameterIterations = request.getParameters().getOrDefault(Parameters.PARAMETER_ITERATIONS, 0);

            if (!(parameterIterations instanceof Integer)) {
                return Parameters.DEFAULT_ITERATIONS;
            }

            final int iterations = Math.max(0, (Integer) parameterIterations);

            if (iterations < 1) {
                return Parameters.DEFAULT_ITERATIONS;
            }

            return iterations;
        }

        /**
         * Combines the specified 'private' salt bytes with the specified additional extra bytes to use as the
         * total salt during hash computation.  {@code privateSaltBytes} will be {@code null} }if no private salt has been
         * configured.
         *
         * @param privateSalt the (possibly {@code null}) 'private' salt to combine with the specified extra bytes
         * @param publicSalt  the extra bytes to use in addition to the given private salt.
         * @return a combination of the specified private salt bytes and extra bytes that will be used as the total
         * salt during hash computation.
         */
        protected ByteSource combine(ByteSource privateSalt, ByteSource publicSalt) {

            // optional 'pepper'
            byte[] privateSaltBytes = privateSalt != null ? privateSalt.getBytes() : null;
            int privateSaltLength = privateSaltBytes != null ? privateSaltBytes.length : 0;

            // salt must always be present.
            byte[] publicSaltBytes = publicSalt.getBytes();
            int extraBytesLength = publicSaltBytes.length;

            int length = privateSaltLength + extraBytesLength;

            if (length <= 0) {
                return SimpleByteSource.empty();
            }

            byte[] combined = new byte[length];

            int i = 0;
            for (int j = 0; j < privateSaltLength; j++) {
                combined[i++] = privateSaltBytes[j];
            }
            for (int j = 0; j < extraBytesLength; j++) {
                combined[i++] = publicSaltBytes[j];
            }

            return ByteSource.Util.bytes(combined);
        }
    }

    static final class Parameters {
        public static final String PARAMETER_ITERATIONS = "SimpleHash.iterations";

        /**
         * A secret part added to the salt. Sometimes also referred to as {@literal "Pepper"}.
         *
         * <p>For more information, see <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">Pepper (cryptography) on Wikipedia</a>.</p>
         */
        public static final String PARAMETER_SECRET_SALT = "SimpleHash.secretSalt";

        public static final String DEFAULT_ALGORITHM = "SHA-512";

        public static final int DEFAULT_ITERATIONS = 50_000;


        private Parameters() {
            // util class
        }
    }
}
