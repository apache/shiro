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

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.Random;

/**
 * Default implementation of the {@link HashService} interface, supporting a customizable hash algorithm name.
 * <h2>Hash Algorithm</h2>
 * You may specify a hash algorithm via the {@link #setDefaultAlgorithmName(String)} property. Any algorithm name
 * understood by the JDK
 * {@link java.security.MessageDigest#getInstance(String) MessageDigest.getInstance(String algorithmName)} method
 * will work, or any Hash algorithm implemented by any loadable {@link HashSpi}. The default is {@code argon2}.
 * </p>
 * A hash and the salt used to compute it are often stored together.  If an attacker is ever able to access
 * the hash (e.g. during password cracking) and it has the full salt value, the attacker has all of the input necessary
 * to try to brute-force crack the hash (source + complete salt).
 * <p/>
 * However, if part of the salt is not available to the attacker (because it is not stored with the hash), it is
 * <em>much</em> harder to crack the hash value since the attacker does not have the complete inputs necessary.
 * <p/>
 *
 * @since 1.2
 */
public class DefaultHashService implements ConfigurableHashService {

    private final Random random;

    /**
     * The MessageDigest name of the hash algorithm to use for computing hashes.
     */
    private String defaultAlgorithmName;

    private Map<String, Object> parameters = Map.of();

    /**
     * Constructs a new {@code DefaultHashService} instance with the following defaults:
     * <ul>
     * <li>{@link #setDefaultAlgorithmName(String) hashAlgorithmName} = {@code SHA-512}</li>
     * </ul>
     */
    public DefaultHashService() {
        this.random = new SecureRandom();
        this.defaultAlgorithmName = "argon2";
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
     * <li>Use the combined value as the salt used during hash computation</li>
     * </ol>
     * </li>
     * <li>
     *
     * @param request the request to process
     * @return the response containing the result of the hash computation, as well as any hash salt used that should be
     * exposed to the caller.
     */
    @Override
    public Hash computeHash(HashRequest request) {
        if (request == null || request.getSource() == null || request.getSource().isEmpty()) {
            return null;
        }

        String algorithmName = getAlgorithmName(request);

        Optional<HashSpi> kdfHash = HashProvider.getByAlgorithmName(algorithmName);
        if (kdfHash.isPresent()) {
            HashSpi hashSpi = kdfHash.get();

            return hashSpi.newHashFactory(random).generate(request);
        }

        throw new UnsupportedOperationException("Cannot create a hash with the given algorithm: " + algorithmName);
    }


    protected String getAlgorithmName(HashRequest request) {
        return request.getAlgorithmName().orElseGet(this::getDefaultAlgorithmName);
    }

    @Override
    public void setDefaultAlgorithmName(String name) {
        this.defaultAlgorithmName = name;
    }

    @Override
    public String getDefaultAlgorithmName() {
        return this.defaultAlgorithmName;
    }

    @Override
    public Map<String, Object> getParameters() {
        return Collections.unmodifiableMap(this.parameters);
    }

    @Override
    public void setParameters(Map<String, Object> parameters) {
        this.parameters = parameters;
    }
}
