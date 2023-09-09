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

package org.apache.shiro.crypto.support.hashes.bcrypt;

import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.crypto.hash.HashSpi;
import org.apache.shiro.lang.util.ByteSource;
import org.apache.shiro.lang.util.SimpleByteSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Random;
import java.util.Set;

/**
 * @since 2.0
 */
public class BCryptProvider implements HashSpi {

    private static final Logger LOG = LoggerFactory.getLogger(BCryptProvider.class);

    @Override
    public Set<String> getImplementedAlgorithms() {
        return BCryptHash.getAlgorithmsBcrypt();
    }

    @Override
    public BCryptHash fromString(String format) {
        return BCryptHash.fromString(format);
    }

    @Override
    public HashFactory newHashFactory(Random random) {
        return new BCryptHashFactory(random);
    }

    static class BCryptHashFactory implements HashSpi.HashFactory {

        private final SecureRandom random;

        BCryptHashFactory(Random random) {
            if (!(random instanceof SecureRandom)) {
                throw new IllegalArgumentException("Only SecureRandom instances are supported at the moment!");
            }

            this.random = (SecureRandom) random;
        }

        @Override
        public BCryptHash generate(HashRequest hashRequest) {
            final String algorithmName = hashRequest.getAlgorithmName().orElse(Parameters.DEFAULT_ALGORITHM_NAME);

            final ByteSource salt = getSalt(hashRequest);

            final int cost = getCost(hashRequest);

            return BCryptHash.generate(
                    algorithmName,
                    hashRequest.getSource(),
                    salt,
                    cost
            );
        }

        private int getCost(HashRequest hashRequest) {
            final Map<String, Object> parameters = hashRequest.getParameters();
            final Optional<String> optCostStr = Optional.ofNullable(parameters.get(Parameters.PARAMETER_COST))
                    .map(obj -> (String) obj);

            if (!optCostStr.isPresent()) {
                return BCryptHash.DEFAULT_COST;
            }

            String costStr = optCostStr.orElseThrow(NoSuchElementException::new);
            try {
                @SuppressWarnings("checkstyle:MagicNumber")
                int cost = Integer.parseInt(costStr, 10);
                BCryptHash.checkValidCost(cost);
                return cost;
            } catch (IllegalArgumentException costEx) {
                String message = String.format(
                        Locale.ENGLISH,
                        "Expected Integer for parameter %s, but %s is not parsable or valid.",
                        Parameters.PARAMETER_COST, costStr
                );
                LOG.warn(message, costEx);

                return BCryptHash.DEFAULT_COST;
            }
        }

        private ByteSource getSalt(HashRequest hashRequest) {
            final Map<String, Object> parameters = hashRequest.getParameters();
            final Optional<String> optSaltBase64 = Optional.ofNullable(parameters.get(Parameters.PARAMETER_SALT))
                    .map(obj -> (String) obj);

            if (!optSaltBase64.isPresent()) {
                return BCryptHash.createSalt(random);
            }

            final String saltBase64 = optSaltBase64.orElseThrow(NoSuchElementException::new);
            final byte[] saltBytes = Base64.getDecoder().decode(saltBase64);

            if (saltBytes.length != BCryptHash.SALT_LENGTH) {
                return BCryptHash.createSalt(random);
            }

            return new SimpleByteSource(saltBytes);
        }
    }

    public static final class Parameters {

        /**
         * Set BCryptHash algorithm name to default.
         */
        public static final String DEFAULT_ALGORITHM_NAME = BCryptHash.DEFAULT_ALGORITHM_NAME;

        /**
         * BCrypt salt param.
         */
        public static final String PARAMETER_SALT = "BCrypt.salt";

        /**
         * BCrypt cost param.
         */
        public static final String PARAMETER_COST = "BCrypt.cost";

        private Parameters() {
            // utility class
        }
    }
}
